import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import { pathToFileURL } from "node:url";

const WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const PREAMBLE_MS = 10_000;
const PAIR_MS = 10_000;
const KEEPALIVE_MS = 25_000;
const MAX_WS_PAYLOAD = 16 * 1024 * 1024;
const HTTP_RE = /^(GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH)\s/;
const sha256 = (s) => crypto.createHash("sha256").update(s).digest();

function wsFrame(opcode, data) {
  const body = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const len = body.length;
  const hdr = len <= 125 ? Buffer.from([0x80 | opcode, len])
    : len <= 65535 ? Buffer.from([0x80 | opcode, 126, len >> 8, len & 0xff])
    : Buffer.allocUnsafe(10);
  if (len > 65535) {
    hdr[0] = 0x80 | opcode;
    hdr[1] = 127;
    hdr.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([hdr, body]);
}

function createChannel(socket, kind, initialBuf, onReady) {
  let buf = initialBuf?.length ? Buffer.from(initialBuf) : Buffer.alloc(0);
  let pre = Buffer.alloc(0);
  let preDone = false;
  let closed = false;
  let onData = null, onEnd = null, onClose = null;
  const queued = [];

  const ch = {
    socket,
    get closed() { return closed; },
    sendControl(obj) {
      if (closed || socket.destroyed) return false;
      const raw = Buffer.from(JSON.stringify(obj) + "\n", "utf8");
      return kind === "ws" ? socket.write(wsFrame(0x01, raw)) : socket.write(raw);
    },
    sendData(chunk) {
      if (closed || socket.destroyed || !chunk?.length) return true;
      return kind === "ws" ? socket.write(wsFrame(0x02, chunk)) : socket.write(chunk);
    },
    fail(error) { ch.sendControl({ ok: false, error }); ch.close(); },
    pause: () => !socket.destroyed && socket.pause(),
    resume: () => !socket.destroyed && socket.resume(),
    close() {
      if (closed) return;
      closed = true;
      if (!socket.destroyed) socket.end(kind === "ws" ? Buffer.from([0x88, 0x00]) : undefined);
    },
    destroy() {
      if (closed) return;
      closed = true;
      if (!socket.destroyed) socket.destroy();
    },
    attachPipe(d, e, c) {
      onData = d; onEnd = e; onClose = c;
      while (queued.length && !closed) onData(queued.shift());
    },
    setOnClose: (c) => { onClose = c; },
  };

  function emit(chunk) {
    if (closed) return;
    if (!preDone) {
      pre = Buffer.concat([pre, chunk]);
      const nl = pre.indexOf(0x0a);
      if (nl === -1) return pre.length > 8192 ? ch.fail("bad_request") : undefined;
      const line = pre.subarray(0, nl).toString("utf8").replace(/\r$/, "");
      const extra = pre.subarray(nl + 1);
      pre = Buffer.alloc(0);
      preDone = true;
      if (extra.length) queued.push(extra);
      ch.pause();
      return onReady(ch, line);
    }
    if (onData) onData(chunk); else queued.push(chunk);
  }

  function drainWs() {
    while (buf.length >= 2 && !closed) {
      const op = buf[0] & 0x0f, masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f, off = 2;
      if (len === 126) { if (buf.length < 4) break; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) {
        if (buf.length < 10) break;
        const big = buf.readBigUInt64BE(2);
        if (big > BigInt(MAX_WS_PAYLOAD)) return ch.destroy();
        len = Number(big); off = 10;
      }
      const mLen = masked ? 4 : 0;
      if (buf.length < off + mLen + len) break;
      const payload = Buffer.from(buf.subarray(off + mLen, off + mLen + len));
      if (masked) {
        const mask = buf.subarray(off, off + 4);
        for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
      }
      buf = buf.subarray(off + mLen + len);
      if (op === 0x08) { const end = onEnd; ch.close(); end?.(); return; }
      if (op === 0x09) { if (!socket.destroyed) socket.write(wsFrame(0x0a, payload)); continue; }
      if (op <= 0x02 && payload.length) emit(payload);
    }
  }

  socket.on("data", (chunk) => {
    if (closed) return;
    if (kind === "ws") { buf = buf.length ? Buffer.concat([buf, chunk]) : chunk; drainWs(); }
    else emit(chunk);
  });
  socket.on("end", () => onEnd?.());
  socket.on("error", () => ch.destroy());
  socket.on("close", () => { closed = true; onClose?.(); });
  if (buf.length) { if (kind === "ws") drainWs(); else { const init = buf; buf = Buffer.alloc(0); emit(init); } }
  return ch;
}

function bridge(a, b) {
  const wire = (src, dst) => {
    src.attachPipe((c) => !dst.sendData(c) && src.pause(), () => dst.close(), () => dst.destroy());
    dst.socket.on("drain", () => src.resume());
  };
  wire(a, b); wire(b, a);
  a.resume(); b.resume();
}

/** Start the stateless blind TCP + WebSocket stream forwarder on a single port. */
export async function startBlindRelay({ host = "0.0.0.0", port = 3499, token = "" } = {}) {
  const expectedHash = token ? sha256(String(token)) : null;
  const slots = new Map(), pending = new Map(), sockets = new Set();
  let activeTunnels = 0, totalConnections = 0;
  const validToken = (p) => !expectedHash || (typeof p === "string" && crypto.timingSafeEqual(sha256(p), expectedHash));

  function handlePreamble(ch, line, timer) {
    clearTimeout(timer);
    let msg;
    try { msg = JSON.parse(line); } catch { return ch.fail("bad_request"); }
    if (!msg || typeof msg !== "object" || !validToken(msg.token)) return ch.fail("unauthorized");
    const { role, slotId } = msg;
    if (typeof slotId !== "string" || !slotId.length || slotId.length > 128) return ch.fail("bad_request");

    if (role === "host-ctl") {
      const prev = slots.get(slotId);
      if (prev) { clearInterval(prev.keepalive); prev.channel.destroy(); }
      const keepalive = setInterval(() => ch.sendControl({ type: "keepalive" }), KEEPALIVE_MS);
      keepalive.unref?.();
      slots.set(slotId, { channel: ch, keepalive });
      ch.attachPipe(() => {}, () => ch.close(), () => {
        clearInterval(keepalive);
        if (slots.get(slotId)?.channel !== ch) return;
        slots.delete(slotId);
        for (const [cid, e] of pending) if (e.slotId === slotId) {
          clearTimeout(e.timer); pending.delete(cid); e.client.fail("host_offline");
        }
      });
      ch.sendControl({ ok: true });
      return ch.resume();
    }

    if (role === "client") {
      const slot = slots.get(slotId);
      if (!slot || slot.channel.closed) return ch.fail("host_offline");
      const connId = crypto.randomBytes(16).toString("hex");
      const pairTimer = setTimeout(() => { if (pending.delete(connId)) ch.fail("pair_timeout"); }, PAIR_MS);
      pairTimer.unref?.();
      pending.set(connId, { slotId, client: ch, timer: pairTimer });
      ch.setOnClose(() => { const e = pending.get(connId); if (e) { clearTimeout(e.timer); pending.delete(connId); } });
      if (!slot.channel.sendControl({ type: "pair", connId })) {
        clearTimeout(pairTimer); pending.delete(connId); ch.fail("host_offline");
      }
      return;
    }

    if (role === "host-data") {
      const entry = typeof msg.connId === "string" ? pending.get(msg.connId) : null;
      if (!entry || entry.slotId !== slotId || entry.client.closed) return ch.fail("pair_not_found");
      clearTimeout(entry.timer); pending.delete(msg.connId);
      entry.client.sendControl({ ok: true, connId: msg.connId });
      ch.sendControl({ ok: true, connId: msg.connId });
      activeTunnels += 1;
      let done = false;
      entry.client.socket.once("close", () => { if (!done) { done = true; activeTunnels = Math.max(0, activeTunnels - 1); } });
      return bridge(entry.client, ch);
    }

    ch.fail("bad_role");
  }

  function handleHttp(socket, initialBuf, timer) {
    let buf = initialBuf;
    const parse = () => {
      const idx = buf.indexOf("\r\n\r\n");
      if (idx === -1) {
        if (buf.length > 16384) { clearTimeout(timer); socket.end("HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n"); }
        return false;
      }
      clearTimeout(timer);
      const lines = buf.subarray(0, idx).toString("utf8").split("\r\n"), rest = buf.subarray(idx + 4);
      const [method, rawTarget = "/"] = lines[0].split(" "), hdrs = Object.create(null);
      for (let i = 1; i < lines.length; i++) {
        const c = lines[i].indexOf(":");
        if (c > 0) hdrs[lines[i].slice(0, c).trim().toLowerCase()] = lines[i].slice(c + 1).trim();
      }
      let pathname = "/";
      try { pathname = new URL(rawTarget, "http://localhost").pathname; } catch {}
      if (method === "GET" && pathname === "/health") {
        const body = JSON.stringify({ ok: true, mode: "blind-relay" });
        socket.end(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`);
      } else if (method === "GET" && pathname === "/ws") {
        const key = hdrs["sec-websocket-key"];
        if (hdrs.upgrade?.toLowerCase() !== "websocket" || !key) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
        else {
          const accept = crypto.createHash("sha1").update(key + WS_MAGIC).digest("base64");
          socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
          const pTimer = setTimeout(() => socket.destroy(), PREAMBLE_MS);
          pTimer.unref?.();
          createChannel(socket, "ws", rest, (ch, line) => handlePreamble(ch, line, pTimer));
        }
      } else {
        const err = '{"ok":false,"error":"not_found"}';
        socket.end(`HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: ${err.length}\r\nConnection: close\r\n\r\n${err}`);
      }
      return true;
    };
    if (parse()) return;
    const onMore = (c) => { buf = Buffer.concat([buf, c]); if (parse()) socket.off("data", onMore); };
    socket.on("data", onMore);
  }

  const server = net.createServer((socket) => {
    totalConnections += 1; sockets.add(socket); socket.setNoDelay(true);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => {});
    const timer = setTimeout(() => socket.destroy(), PREAMBLE_MS);
    timer.unref?.();
    let peek = Buffer.alloc(0);
    const onFirst = (c) => {
      peek = peek.length ? Buffer.concat([peek, c]) : c;
      if (!peek.length) return;
      if (peek[0] === 0x7b) { socket.off("data", onFirst); return createChannel(socket, "tcp", peek, (ch, l) => handlePreamble(ch, l, timer)); }
      const head = peek.toString("ascii", 0, Math.min(peek.length, 16));
      if (HTTP_RE.test(head)) { socket.off("data", onFirst); return handleHttp(socket, peek, timer); }
      if (peek.length <= 8 && /^[A-Z]+$/.test(head)) return;
      socket.off("data", onFirst); clearTimeout(timer); socket.end('{"ok":false,"error":"bad_request"}\n');
    };
    socket.on("data", onFirst);
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => { server.off("error", reject); resolve(); });
  });

  const addr = server.address();
  return {
    port: addr.port,
    host: addr.address,
    stats: () => ({ slots: slots.size, pending: pending.size, activeTunnels, totalConnections }),
    async close() {
      for (const s of slots.values()) clearInterval(s.keepalive);
      slots.clear();
      for (const e of pending.values()) clearTimeout(e.timer);
      pending.clear();
      for (const s of sockets) s.destroy();
      sockets.clear();
      await new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

function isMain() {
  if (import.meta.main) return true;
  try { return Boolean(process.argv[1]) && pathToFileURL(fs.realpathSync(process.argv[1])).href === import.meta.url; }
  catch { return false; }
}

if (isMain()) {
  const relay = await startBlindRelay({
    host: process.env.HOST || "0.0.0.0",
    port: Number(process.env.PORT ?? 3499),
    token: process.env.RELAY_TOKEN || "",
  });
  console.log(`[simple-share-relay] blind relay listening on ${relay.host}:${relay.port}`);
}
