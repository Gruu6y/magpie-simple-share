import crypto from "node:crypto";

export const FRAME = Object.freeze({
  REQ_HEAD: 0x01,
  REQ_BODY: 0x02,
  REQ_END: 0x03,
  RES_HEAD: 0x04,
  RES_BODY: 0x05,
  RES_END: 0x06,
  STREAM_ABORT: 0x07,
  PAIR_REQ: 0x10,
  PAIR_STATUS: 0x11,
  PING: 0x20,
  PONG: 0x21,
});

export const MAX_FRAME_PAYLOAD = 4 * 1024 * 1024; // 4 MiB
const MAX_BODY_CHUNK = 1024 * 1024; // 1 MiB chunking stays well below 4 MiB frame cap

function toUint8Array(data) {
  if (data === null || data === undefined) {
    return new Uint8Array(0);
  }
  if (Buffer.isBuffer(data)) {
    return data;
  }
  if (data instanceof Uint8Array) {
    return data;
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  if (Array.isArray(data)) {
    return Uint8Array.from(data);
  }
  throw new TypeError("Unsupported binary chunk type");
}

function payloadToBuffer(payloadBufOrObj) {
  if (payloadBufOrObj === null || payloadBufOrObj === undefined) {
    return Buffer.alloc(0);
  }
  if (Buffer.isBuffer(payloadBufOrObj)) {
    return payloadBufOrObj;
  }
  if (ArrayBuffer.isView(payloadBufOrObj)) {
    return Buffer.from(
      payloadBufOrObj.buffer,
      payloadBufOrObj.byteOffset,
      payloadBufOrObj.byteLength,
    );
  }
  if (payloadBufOrObj instanceof ArrayBuffer) {
    return Buffer.from(payloadBufOrObj);
  }
  if (typeof payloadBufOrObj === "string") {
    return Buffer.from(payloadBufOrObj, "utf8");
  }
  return Buffer.from(JSON.stringify(payloadBufOrObj), "utf8");
}

/**
 * Encode one binary wire frame: [1-byte type][4-byte uint32BE length][payload].
 */
export function encodeFrame(type, payloadBufOrObj) {
  if (!Number.isInteger(type) || type < 0 || type > 0xff) {
    throw new RangeError(`Invalid frame type: ${String(type)}`);
  }
  const payload = payloadToBuffer(payloadBufOrObj);
  if (payload.length > MAX_FRAME_PAYLOAD) {
    const err = new Error(`Frame payload (${payload.length} bytes) exceeds 4 MiB limit`);
    err.code = "frame_too_large";
    throw err;
  }
  const frame = Buffer.allocUnsafe(5 + payload.length);
  frame[0] = type;
  frame.writeUInt32BE(payload.length, 1);
  if (payload.length > 0) {
    payload.copy(frame, 5);
  }
  return frame;
}

/**
 * Create a streaming incremental frame decoder.
 * Returns a push function `push(chunk)` that also exposes `.push`, `.reset()`, `.bufferedBytes()`.
 */
export function createFrameDecoder(onFrame, onError) {
  let buf = Buffer.alloc(0);
  let failed = false;

  function fail(err) {
    failed = true;
    buf = Buffer.alloc(0);
    if (typeof onError === "function") {
      onError(err);
    } else {
      throw err;
    }
  }

  function push(chunk) {
    if (failed) return;
    if (chunk === null || chunk === undefined) return;
    const u8 = toUint8Array(chunk);
    if (u8.byteLength === 0) return;

    const incoming = Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength);
    buf = buf.length === 0 ? Buffer.from(incoming) : Buffer.concat([buf, incoming]);

    let offset = 0;
    while (!failed && buf.length - offset >= 5) {
      const type = buf[offset];
      const length = buf.readUInt32BE(offset + 1);
      if (length > MAX_FRAME_PAYLOAD) {
        const err = new Error(`Incoming frame length (${length} bytes) exceeds 4 MiB limit`);
        err.code = "frame_too_large";
        fail(err);
        return;
      }
      if (buf.length - offset < 5 + length) {
        break;
      }
      const payload = Buffer.from(buf.subarray(offset + 5, offset + 5 + length));
      offset += 5 + length;
      try {
        onFrame?.({ type, payload });
      } catch (err) {
        fail(err);
        return;
      }
    }

    if (!failed && offset > 0) {
      buf = offset === buf.length ? Buffer.alloc(0) : Buffer.from(buf.subarray(offset));
    }
  }

  push.push = push;
  push.reset = () => {
    buf = Buffer.alloc(0);
    failed = false;
  };
  push.bufferedBytes = () => buf.length;
  return push;
}

function adaptDuplex(duplex) {
  if (!duplex || typeof duplex !== "object") {
    throw new TypeError("createFramedChannel requires a duplex transport");
  }

  // 1. Pre-normalized duplex adapter: { write(Uint8Array), onData(fn), onClose(fn), end(), destroy(err?) }
  if (typeof duplex.onData === "function" && typeof duplex.write === "function") {
    return {
      write: (u8) => Promise.resolve(duplex.write(u8)),
      onData: (fn) => duplex.onData(fn),
      onClose: (fn) => (typeof duplex.onClose === "function" ? duplex.onClose(fn) : () => {}),
      end: () => Promise.resolve(duplex.end?.()),
      destroy: (err) => {
        duplex.destroy?.(err);
      },
    };
  }

  // 2. Iroh BiStream adapter: { send: SendStream, recv: RecvStream }
  if (
    duplex.send &&
    duplex.recv &&
    typeof duplex.send.writeAll === "function" &&
    typeof duplex.recv.read === "function"
  ) {
    const dataListeners = new Set();
    const closeListeners = new Set();
    let closed = false;
    let pumping = false;

    const emitClose = (err) => {
      if (closed) return;
      closed = true;
      for (const fn of closeListeners) {
        try {
          fn(err);
        } catch {
          /* ignore listener error */
        }
      }
    };

    const startPump = () => {
      if (pumping) return;
      pumping = true;
      (async () => {
        try {
          while (!closed) {
            const chunk = await duplex.recv.read(65536);
            if (!chunk || chunk.length === 0) {
              break;
            }
            const u8 = chunk instanceof Uint8Array ? chunk : Uint8Array.from(chunk);
            for (const fn of dataListeners) {
              fn(u8);
            }
          }
          emitClose();
        } catch (err) {
          emitClose(err);
        }
      })();
    };

    return {
      write: async (u8) => {
        if (closed) throw new Error("Iroh BiStream is closed");
        await duplex.send.writeAll(Array.from(u8));
      },
      onData: (fn) => {
        dataListeners.add(fn);
        startPump();
        return () => dataListeners.delete(fn);
      },
      onClose: (fn) => {
        if (closed) {
          queueMicrotask(() => fn());
          return () => {};
        }
        closeListeners.add(fn);
        return () => closeListeners.delete(fn);
      },
      end: async () => {
        try {
          await duplex.send.finish?.();
        } finally {
          emitClose();
        }
      },
      destroy: (err) => {
        Promise.resolve(duplex.send.reset?.(0n)).catch(() => {});
        Promise.resolve(duplex.recv.stop?.(0n)).catch(() => {});
        emitClose(err);
      },
    };
  }

  // 3. WebSocket adapter (browser/Bun WebSocket or Node ws)
  if (typeof duplex.send === "function") {
    const dataListeners = new Set();
    const closeListeners = new Set();
    let closed = false;
    let blobQueue = Promise.resolve();

    try {
      if ("binaryType" in duplex) {
        duplex.binaryType = "arraybuffer";
      }
    } catch {
      /* ignore readonly binaryType */
    }

    const emitClose = (err) => {
      if (closed) return;
      closed = true;
      for (const fn of closeListeners) {
        try {
          fn(err);
        } catch {
          /* ignore listener error */
        }
      }
    };

    const handleMessage = (rawData) => {
      if (rawData instanceof Blob) {
        blobQueue = blobQueue.then(async () => {
          const ab = await rawData.arrayBuffer();
          const u8 = new Uint8Array(ab);
          for (const fn of dataListeners) fn(u8);
        });
        return;
      }
      const u8 =
        typeof rawData === "string"
          ? Buffer.from(rawData, "utf8")
          : toUint8Array(rawData);
      for (const fn of dataListeners) {
        fn(u8);
      }
    };

    if (typeof duplex.addEventListener === "function") {
      duplex.addEventListener("message", (ev) => handleMessage(ev?.data ?? ev));
      duplex.addEventListener("close", () => emitClose());
      duplex.addEventListener("error", (ev) => emitClose(ev?.error || new Error("WebSocket error")));
    } else if (typeof duplex.on === "function") {
      duplex.on("message", (data) => handleMessage(data));
      duplex.on("close", () => emitClose());
      duplex.on("error", (err) => emitClose(err));
    }

    return {
      write: async (u8) => {
        if (closed || (duplex.readyState !== undefined && duplex.readyState !== 1)) {
          throw new Error("WebSocket channel is not open");
        }
        duplex.send(u8);
      },
      onData: (fn) => {
        dataListeners.add(fn);
        return () => dataListeners.delete(fn);
      },
      onClose: (fn) => {
        if (closed) {
          queueMicrotask(() => fn());
          return () => {};
        }
        closeListeners.add(fn);
        return () => closeListeners.delete(fn);
      },
      end: () => {
        try {
          duplex.close?.();
        } finally {
          emitClose();
        }
      },
      destroy: (err) => {
        try {
          duplex.terminate?.();
          duplex.close?.();
        } finally {
          emitClose(err);
        }
      },
    };
  }

  // 4. Node/Bun net.Socket, tls.TLSSocket, or Duplex stream
  if (typeof duplex.on === "function" && typeof duplex.write === "function") {
    const closeListeners = new Set();
    let closed = Boolean(duplex.destroyed);
    let closeErr;

    const emitClose = (err) => {
      if (closed) return;
      closed = true;
      closeErr = err;
      for (const fn of closeListeners) {
        try {
          fn(err);
        } catch {
          /* ignore listener error */
        }
      }
    };

    duplex.on("close", () => emitClose(closeErr));
    duplex.on("error", (err) => {
      closeErr = err;
      emitClose(err);
    });

    return {
      write: (u8) =>
        new Promise((resolve, reject) => {
          if (closed || duplex.destroyed || duplex.writableEnded) {
            return reject(new Error("Socket channel is closed"));
          }
          duplex.write(u8, (err) => (err ? reject(err) : resolve()));
        }),
      onData: (fn) => {
        duplex.on("data", fn);
        return () => duplex.off?.("data", fn);
      },
      onClose: (fn) => {
        if (closed) {
          queueMicrotask(() => fn(closeErr));
          return () => {};
        }
        closeListeners.add(fn);
        return () => closeListeners.delete(fn);
      },
      end: () =>
        new Promise((resolve) => {
          if (closed || duplex.destroyed || duplex.writableEnded) {
            emitClose();
            return resolve();
          }
          duplex.end(() => {
            emitClose();
            resolve();
          });
        }),
      destroy: (err) => {
        duplex.destroy?.(err);
        emitClose(err);
      },
    };
  }

  throw new TypeError("Unsupported duplex transport for createFramedChannel");
}

/**
 * Wrap a duplex transport (normalized duplex, TLSSocket, net.Socket, WebSocket,
 * or Iroh BiStream) with framed message encoding/decoding.
 */
export function createFramedChannel(duplex) {
  const transport = adaptDuplex(duplex);
  const frameListeners = new Set();
  const closeListeners = new Set();
  let isClosed = false;
  let isClosing = false;
  let closeError;
  let writeChain = Promise.resolve();

  function notifyClose(err) {
    if (isClosed) return;
    isClosed = true;
    closeError = err;
    for (const fn of Array.from(closeListeners)) {
      try {
        fn(err);
      } catch {
        /* ignore listener error */
      }
    }
    closeListeners.clear();
    frameListeners.clear();
  }

  const decode = createFrameDecoder(
    (frame) => {
      for (const fn of Array.from(frameListeners)) {
        try {
          fn(frame);
        } catch {
          /* isolate individual listener failures */
        }
      }
    },
    (err) => {
      transport.destroy(err);
      notifyClose(err);
    },
  );

  transport.onData((chunk) => {
    if (!isClosed) {
      decode(chunk);
    }
  });

  transport.onClose((err) => {
    notifyClose(err);
  });

  function sendFrame(type, payload) {
    const encoded = encodeFrame(type, payload);
    if (isClosed || isClosing) {
      return Promise.reject(new Error("Cannot send frame on closed channel"));
    }
    const task = writeChain.catch(() => {}).then(async () => {
      if (isClosed) {
        throw new Error("Cannot send frame on closed channel");
      }
      await transport.write(encoded);
    });
    writeChain = task.catch(() => {});
    return task;
  }

  function onFrame(fn) {
    if (typeof fn !== "function") {
      throw new TypeError("onFrame listener must be a function");
    }
    if (isClosed) return () => {};
    frameListeners.add(fn);
    return () => frameListeners.delete(fn);
  }

  function onceFrame(pred, timeoutMs) {
    const predicate =
      typeof pred === "number"
        ? (f) => f.type === pred
        : typeof pred === "function"
          ? pred
          : null;
    if (!predicate) {
      return Promise.reject(new TypeError("onceFrame requires a predicate function or frame type"));
    }
    if (isClosed) {
      return Promise.reject(closeError || new Error("Channel is closed"));
    }

    return new Promise((resolve, reject) => {
      let timer = null;
      let offFrame = () => {};
      let offClose = () => {};

      const cleanup = () => {
        if (timer) clearTimeout(timer);
        offFrame();
        offClose();
      };

      offFrame = onFrame((frame) => {
        let matched = false;
        try {
          matched = Boolean(predicate(frame));
        } catch (err) {
          cleanup();
          reject(err);
          return;
        }
        if (matched) {
          cleanup();
          resolve(frame);
        }
      });

      offClose = onClose((err) => {
        cleanup();
        reject(err || new Error("Channel closed before matching frame arrived"));
      });

      if (typeof timeoutMs === "number" && timeoutMs > 0) {
        timer = setTimeout(() => {
          cleanup();
          const err = new Error(`Timed out waiting for frame after ${timeoutMs}ms`);
          err.code = "frame_timeout";
          reject(err);
        }, timeoutMs);
      }
    });
  }

  function onClose(fn) {
    if (typeof fn !== "function") {
      throw new TypeError("onClose listener must be a function");
    }
    if (isClosed) {
      queueMicrotask(() => fn(closeError));
      return () => {};
    }
    closeListeners.add(fn);
    return () => closeListeners.delete(fn);
  }

  async function close(err) {
    if (isClosed) return;
    if (isClosing && !err) return;
    isClosing = true;
    try {
      if (err) {
        transport.destroy(err);
      } else {
        await writeChain.catch(() => {});
        await transport.end();
      }
    } finally {
      notifyClose(err);
    }
  }

  return {
    sendFrame,
    onFrame,
    onceFrame,
    onClose,
    close,
    destroy: (err) => close(err || new Error("Channel destroyed")),
    get closed() {
      return isClosed;
    },
  };
}

// --- Multiplexed HTTP-over-framed-channel transport ---

function parseJsonPayload(payload) {
  return JSON.parse(Buffer.from(payload).toString("utf8"));
}

function buildStreamBodyPayload(streamId, chunk) {
  const idBuf = Buffer.from(streamId, "utf8");
  if (idBuf.length > 0xffff) {
    throw new RangeError("Stream id too long");
  }
  const data = Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  const framePayload = Buffer.allocUnsafe(2 + idBuf.length + data.length);
  framePayload.writeUInt16BE(idBuf.length, 0);
  idBuf.copy(framePayload, 2);
  data.copy(framePayload, 2 + idBuf.length);
  return framePayload;
}

function decodeStreamBodyPayload(payload) {
  if (payload.length < 2) {
    throw new Error("Malformed stream body frame: missing stream id length");
  }
  const idLen = payload.readUInt16BE(0);
  if (2 + idLen > payload.length) {
    throw new Error("Malformed stream body frame: truncated stream id");
  }
  const id = payload.subarray(2, 2 + idLen).toString("utf8");
  const chunk = new Uint8Array(payload.subarray(2 + idLen));
  return { id, chunk };
}

async function sendBodyChunks(sendFrameFn, frameType, streamId, body, signal, onReader) {
  if (body === null || body === undefined) return;

  const sendBytes = async (u8) => {
    for (let offset = 0; offset < u8.byteLength; offset += MAX_BODY_CHUNK) {
      if (signal?.aborted) return;
      const slice = u8.subarray(offset, Math.min(offset + MAX_BODY_CHUNK, u8.byteLength));
      await sendFrameFn(frameType, buildStreamBodyPayload(streamId, slice));
    }
  };

  if (typeof body === "string") {
    await sendBytes(Buffer.from(body, "utf8"));
    return;
  }
  if (body instanceof Uint8Array || ArrayBuffer.isView(body) || body instanceof ArrayBuffer) {
    await sendBytes(toUint8Array(body));
    return;
  }
  if (typeof body.getReader === "function") {
    const reader = body.getReader();
    onReader?.(reader);
    const onAbort = () => {
      reader.cancel().catch(() => {});
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    try {
      while (!signal?.aborted) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value && value.byteLength > 0) {
          await sendBytes(toUint8Array(value));
        }
      }
    } finally {
      onReader?.(null);
      signal?.removeEventListener("abort", onAbort);
      try {
        reader.releaseLock();
      } catch {
        /* ignore */
      }
    }
    return;
  }
  if (typeof body[Symbol.asyncIterator] === "function") {
    for await (const part of body) {
      if (signal?.aborted) break;
      const u8 = typeof part === "string" ? Buffer.from(part, "utf8") : toUint8Array(part);
      if (u8.byteLength > 0) {
        await sendBytes(u8);
      }
    }
    return;
  }
  throw new TypeError("Unsupported HTTP body type");
}

function makeAbortError(reason) {
  if (reason instanceof Error) return reason;
  const err = new Error(typeof reason === "string" && reason ? reason : "The operation was aborted");
  err.name = "AbortError";
  return err;
}

/**
 * Send one HTTP request over a framed channel and return { status, headers, body }
 * as soon as RES_HEAD arrives, streaming RES_BODY chunks with zero buffering.
 */
export async function sendHttpRequestOverChannel(
  channel,
  { id, method = "GET", path = "/", headers = {}, bodyStream = null, signal } = {},
) {
  const streamId = id !== undefined && id !== null ? String(id) : crypto.randomUUID();
  if (signal?.aborted) {
    throw makeAbortError(signal.reason);
  }
  if (channel.closed) {
    throw new Error("Cannot send HTTP request on closed channel");
  }

  let settled = false;
  let streamController = null;
  let streamClosed = false;
  let abortSent = false;
  const localAbort = new AbortController();

  const sendAbort = (reason) => {
    if (abortSent || channel.closed) return;
    abortSent = true;
    channel
      .sendFrame(FRAME.STREAM_ABORT, {
        id: streamId,
        reason: typeof reason === "string" ? reason : "aborted",
      })
      .catch(() => {});
  };

  let offFrame = () => {};
  let offClose = () => {};

  const cleanup = () => {
    offFrame();
    offClose();
    signal?.removeEventListener("abort", onCallerAbort);
  };

  let resolveHead;
  let rejectHead;
  const headPromise = new Promise((res, rej) => {
    resolveHead = res;
    rejectHead = rej;
  });

  function abortLocally(err, notifyPeer = true) {
    if (!localAbort.signal.aborted) {
      localAbort.abort(err);
    }
    if (notifyPeer) {
      sendAbort(err?.message || "aborted");
    }
    cleanup();
    if (!settled) {
      settled = true;
      rejectHead(err);
    }
    if (streamController && !streamClosed) {
      streamClosed = true;
      try {
        streamController.error(err);
      } catch {
        /* already closed */
      }
    }
  }

  function onCallerAbort() {
    abortLocally(makeAbortError(signal?.reason), true);
  }

  signal?.addEventListener("abort", onCallerAbort, { once: true });

  offClose = channel.onClose((err) => {
    abortLocally(err || new Error("Channel closed"), false);
  });

  offFrame = channel.onFrame((frame) => {
    if (frame.type === FRAME.RES_HEAD) {
      let head;
      try {
        head = parseJsonPayload(frame.payload);
      } catch {
        return;
      }
      if (String(head?.id) !== streamId || settled) return;
      settled = true;
      const body = new ReadableStream({
        start(controller) {
          streamController = controller;
        },
        cancel(reason) {
          if (streamClosed) return;
          streamClosed = true;
          abortLocally(makeAbortError(reason), true);
        },
      });
      resolveHead({
        status: Number(head.status) || 200,
        headers: head.headers && typeof head.headers === "object" ? head.headers : {},
        body,
      });
      return;
    }

    if (frame.type === FRAME.RES_BODY) {
      let parsed;
      try {
        parsed = decodeStreamBodyPayload(frame.payload);
      } catch {
        return;
      }
      if (parsed.id !== streamId) return;
      if (streamController && !streamClosed && parsed.chunk.byteLength > 0) {
        streamController.enqueue(parsed.chunk);
      }
      return;
    }

    if (frame.type === FRAME.RES_END) {
      let endMeta;
      try {
        endMeta = parseJsonPayload(frame.payload);
      } catch {
        return;
      }
      if (String(endMeta?.id) !== streamId) return;
      cleanup();
      if (!settled) {
        settled = true;
        rejectHead(new Error(endMeta.error || "Response ended before RES_HEAD"));
        return;
      }
      if (streamController && !streamClosed) {
        streamClosed = true;
        if (endMeta.error) {
          streamController.error(new Error(endMeta.error));
        } else {
          streamController.close();
        }
      }
      return;
    }

    if (frame.type === FRAME.STREAM_ABORT) {
      let meta;
      try {
        meta = parseJsonPayload(frame.payload);
      } catch {
        return;
      }
      if (String(meta?.id) !== streamId) return;
      abortLocally(new Error(meta?.reason || "Stream aborted by peer"), false);
    }
  });

  // Send REQ_HEAD, stream any body chunks without buffering, then REQ_END
  (async () => {
    try {
      await channel.sendFrame(FRAME.REQ_HEAD, {
        id: streamId,
        method: String(method || "GET").toUpperCase(),
        path: String(path || "/"),
        headers: headers && typeof headers === "object" ? headers : {},
      });
      if (bodyStream !== null && bodyStream !== undefined && !localAbort.signal.aborted) {
        await sendBodyChunks(
          (t, p) => channel.sendFrame(t, p),
          FRAME.REQ_BODY,
          streamId,
          bodyStream,
          localAbort.signal,
        );
      }
      if (!localAbort.signal.aborted && !channel.closed) {
        await channel.sendFrame(FRAME.REQ_END, { id: streamId });
      }
    } catch (err) {
      if (!localAbort.signal.aborted) {
        abortLocally(err, true);
      }
    }
  })();

  return headPromise;
}

/**
 * Serve multiplexed HTTP requests arriving over a framed channel.
 * handler(req, { signal }) returns { status, headers, body } (or Web Response).
 */
export function serveHttpRequestOnChannel(channel, handler) {
  if (typeof handler !== "function") {
    throw new TypeError("serveHttpRequestOnChannel requires a handler function");
  }
  const activeStreams = new Map();
  let stopped = false;

  const cleanupStream = (id) => {
    activeStreams.delete(id);
  };

  const abortStream = (id, reason) => {
    const entry = activeStreams.get(id);
    if (!entry) return;
    activeStreams.delete(id);
    const err = makeAbortError(reason);
    if (!entry.ac.signal.aborted) {
      entry.ac.abort(err);
    }
    if (!entry.reqClosed) {
      entry.reqClosed = true;
      try {
        entry.reqController?.error(err);
      } catch {
        /* ignore */
      }
    }
    if (entry.resReader) {
      entry.resReader.cancel(err).catch(() => {});
    }
  };

  const handleRequest = async (entry, req) => {
    let headSent = false;
    try {
      const result = await handler(req, { signal: entry.ac.signal });
      if (entry.ac.signal.aborted || stopped || channel.closed) {
        return;
      }
      const status = Number(result?.status) || 200;
      let headers = {};
      if (result?.headers instanceof Headers) {
        headers = Object.fromEntries(result.headers.entries());
      } else if (result?.headers && typeof result.headers === "object") {
        headers = result.headers;
      }

      await channel.sendFrame(FRAME.RES_HEAD, {
        id: entry.id,
        status,
        headers,
      });
      headSent = true;

      const body = result?.body ?? null;
      if (body !== null && body !== undefined && !entry.ac.signal.aborted) {
        await sendBodyChunks(
          (t, p) => channel.sendFrame(t, p),
          FRAME.RES_BODY,
          entry.id,
          body,
          entry.ac.signal,
          (r) => {
            entry.resReader = r;
          },
        );
      }

      if (!entry.ac.signal.aborted && !stopped && !channel.closed) {
        await channel.sendFrame(FRAME.RES_END, { id: entry.id });
      }
    } catch (err) {
      if (entry.ac.signal.aborted || stopped || channel.closed) {
        return;
      }
      const message = String(err?.message || err || "Internal error");
      try {
        if (!headSent) {
          await channel.sendFrame(FRAME.RES_HEAD, {
            id: entry.id,
            status: 500,
            headers: { "content-type": "application/json" },
          });
          await sendBodyChunks(
            (t, p) => channel.sendFrame(t, p),
            FRAME.RES_BODY,
            entry.id,
            JSON.stringify({ error: message }),
            entry.ac.signal,
          );
          await channel.sendFrame(FRAME.RES_END, { id: entry.id });
        } else {
          await channel.sendFrame(FRAME.RES_END, { id: entry.id, error: message });
        }
      } catch {
        /* ignore send errors on broken channel */
      }
    } finally {
      cleanupStream(entry.id);
    }
  };

  const offFrame = channel.onFrame((frame) => {
    if (stopped) return;

    if (frame.type === FRAME.REQ_HEAD) {
      let head;
      try {
        head = parseJsonPayload(frame.payload);
      } catch {
        return;
      }
      const id = String(head?.id ?? "");
      if (!id || activeStreams.has(id)) return;

      const ac = new AbortController();
      let reqController = null;
      const body = new ReadableStream({
        start(controller) {
          reqController = controller;
        },
        cancel() {
          entry.reqClosed = true;
        },
      });
      const entry = {
        id,
        ac,
        reqController,
        reqClosed: false,
        resReader: null,
      };
      activeStreams.set(id, entry);

      const req = {
        id,
        method: String(head.method || "GET").toUpperCase(),
        path: String(head.path || "/"),
        headers: head.headers && typeof head.headers === "object" ? head.headers : {},
        body,
      };
      // Dispatch concurrently so multiple stream ids execute without head-of-line blocking
      queueMicrotask(() => {
        if (!stopped) {
          handleRequest(entry, req);
        }
      });
      return;
    }

    if (frame.type === FRAME.REQ_BODY) {
      let parsed;
      try {
        parsed = decodeStreamBodyPayload(frame.payload);
      } catch {
        return;
      }
      const entry = activeStreams.get(parsed.id);
      if (!entry || entry.reqClosed) return;
      if (parsed.chunk.byteLength > 0) {
        entry.reqController?.enqueue(parsed.chunk);
      }
      return;
    }

    if (frame.type === FRAME.REQ_END) {
      let meta;
      try {
        meta = parseJsonPayload(frame.payload);
      } catch {
        return;
      }
      const id = String(meta?.id ?? "");
      const entry = activeStreams.get(id);
      if (!entry || entry.reqClosed) return;
      entry.reqClosed = true;
      try {
        if (meta?.error) {
          entry.reqController?.error(new Error(meta.error));
        } else {
          entry.reqController?.close();
        }
      } catch {
        /* ignore */
      }
      return;
    }

    if (frame.type === FRAME.STREAM_ABORT) {
      let meta;
      try {
        meta = parseJsonPayload(frame.payload);
      } catch {
        return;
      }
      const id = String(meta?.id ?? "");
      if (id) {
        abortStream(id, meta?.reason || "Stream aborted by client");
      }
    }
  });

  const offClose = channel.onClose((err) => {
    for (const id of Array.from(activeStreams.keys())) {
      abortStream(id, err?.message || "Channel closed");
    }
  });

  const stop = () => {
    if (stopped) return;
    stopped = true;
    offFrame();
    offClose();
    for (const id of Array.from(activeStreams.keys())) {
      abortStream(id, "Server stopped");
    }
  };
  stop.close = stop;
  return stop;
}
