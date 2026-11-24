import crypto from "node:crypto";
import net from "node:net";
import { Duplex } from "node:stream";
import tls from "node:tls";
import {
  extractEd25519PubRawFromCertDer,
  slotIdForHost,
  verifySelfSignedEd25519Cert,
} from "./crypto.mjs";
import { createFramedChannel } from "./wire.mjs";

export const PAIR_ALPN = "mshare-pair/1";
export const API_ALPN = "mshare-api/1";

function createDummyRejectCaPem() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" });
  const derLen = (n) => (n < 0x80 ? Buffer.from([n]) : Buffer.from([0x82, n >> 8, n & 0xff]));
  const der = (tag, body) => {
    const b = Buffer.isBuffer(body) ? body : Buffer.concat(body);
    return Buffer.concat([Buffer.from([tag]), derLen(b.length), b]);
  };
  const algId = Buffer.from("300506032b6570", "hex");
  const name = Buffer.from("30133111300f06035504030c0864756d6d792d6361", "hex");
  const validity = Buffer.from("301e170d3236303130313030303030305a170d3336303130313030303030305a", "hex");
  const serial = Buffer.from("020101", "hex");
  const tbs = der(0x30, [serial, algId, name, validity, name, spki]);
  const sig = crypto.sign(null, tbs, privateKey);
  const certDer = der(0x30, [tbs, algId, der(0x03, Buffer.concat([Buffer.from([0]), sig]))]);
  return `-----BEGIN CERTIFICATE-----\n${certDer.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
}

const DUMMY_REJECT_CA_PEM = createDummyRejectCaPem();

function peekTlsClientHello(buf) {
  if (buf.length < 5) return { ready: false };
  if (buf[0] !== 0x16) return { invalid: true };
  const recLen = buf.readUInt16BE(3);
  if (recLen > 16384 || recLen < 4) return { invalid: true };
  if (buf.length < 5 + recLen) return { ready: false };
  if (buf[5] !== 0x01) return { invalid: true };

  let pos = 5 + 4 + 2 + 32; // handshake hdr + version + random
  if (pos >= buf.length) return { ready: true, sni: null, alpns: [] };
  const sidLen = buf[pos];
  pos += 1 + sidLen;
  if (pos + 2 > buf.length) return { ready: true, sni: null, alpns: [] };
  const csLen = buf.readUInt16BE(pos);
  pos += 2 + csLen;
  if (pos + 1 > buf.length) return { ready: true, sni: null, alpns: [] };
  const compLen = buf[pos];
  pos += 1 + compLen;
  if (pos + 2 > buf.length) return { ready: true, sni: null, alpns: [] };
  const extLen = buf.readUInt16BE(pos);
  pos += 2;
  const extEnd = Math.min(5 + recLen, pos + extLen);

  let sni = null;
  const alpns = [];
  while (pos + 4 <= extEnd) {
    const type = buf.readUInt16BE(pos);
    const len = buf.readUInt16BE(pos + 2);
    pos += 4;
    if (pos + len > extEnd) break;
    if (type === 0x0000 && len >= 5) {
      const nameType = buf[pos + 2];
      const nameLen = buf.readUInt16BE(pos + 3);
      if (nameType === 0 && pos + 5 + nameLen <= pos + len) {
        sni = buf.subarray(pos + 5, pos + 5 + nameLen).toString("utf8");
      }
    } else if (type === 0x0010 && len >= 2) {
      const listLen = buf.readUInt16BE(pos);
      let p = pos + 2;
      const end = Math.min(pos + 2 + listLen, pos + len);
      while (p < end) {
        const l = buf[p++];
        if (p + l > end) break;
        alpns.push(buf.subarray(p, p + l).toString("utf8"));
        p += l;
      }
    }
    pos += len;
  }
  return { ready: true, sni, alpns };
}

function attachTlsServerUpgrade(
  rawTransport,
  {
    identity,
    isAuthorizedPeer,
    getAuthorizedCertPems,
    hasActiveInvite,
    onApiChannel,
    onPairChannel,
    trackPeerChannel,
    modeLabel,
    onTlsError,
  },
) {
  let peekBuf = Buffer.alloc(0);
  let upgraded = false;
  let closed = false;
  const hsTimer = setTimeout(() => {
    if (!upgraded && !closed) {
      closed = true;
      rawTransport.destroy();
    }
  }, 10_000);
  hsTimer.unref?.();

  const abortRaw = (err) => {
    if (closed) return;
    closed = true;
    clearTimeout(hsTimer);
    if (err) onTlsError?.(err);
    rawTransport.destroy();
  };

  const onErr = (err) => abortRaw(err);
  rawTransport.on("error", onErr);

  const onPeek = async (chunk) => {
    if (upgraded || closed) return;
    peekBuf = peekBuf.length ? Buffer.concat([peekBuf, chunk]) : Buffer.from(chunk);
    if (peekBuf.length > 16389) return abortRaw(new Error("ClientHello too large"));

    const hello = peekTlsClientHello(peekBuf);
    if (hello.invalid) return abortRaw(new Error("Invalid TLS ClientHello"));
    if (!hello.ready) return;

    upgraded = true;
    rawTransport.pause();
    rawTransport.off("data", onPeek);
    rawTransport.off("error", onErr);

    const isPair = hello.alpns.includes(PAIR_ALPN) || hello.sni === "pair.mshare";
    const isApi = !isPair && (hello.alpns.includes(API_ALPN) || hello.sni === "api.mshare");
    if (!isPair && !isApi) {
      return abortRaw(new Error("Unknown mTLS ALPN/SNI"));
    }

    try {
      if (isPair && !Boolean(await hasActiveInvite?.())) {
        return abortRaw(new Error("No active invite for pairing"));
      }
      const caList = isApi ? (await getAuthorizedCertPems?.()) || [] : undefined;
      const tlsOpts = {
        isServer: true,
        key: identity.keyPem,
        cert: identity.certPem,
        minVersion: "TLSv1.3",
        requestCert: true,
        rejectUnauthorized: isApi,
        ALPNProtocols: [isPair ? PAIR_ALPN : API_ALPN],
        ...(isApi ? { ca: caList.length > 0 ? caList : [DUMMY_REJECT_CA_PEM] } : {}),
      };

      rawTransport.unshift(peekBuf);
      const tlsSock = new tls.TLSSocket(rawTransport, tlsOpts);

      tlsSock.on("error", (err) => {
        clearTimeout(hsTimer);
        onTlsError?.(err);
        if (!tlsSock.destroyed) tlsSock.destroy();
      });

      tlsSock.once("secure", async () => {
        clearTimeout(hsTimer);
        try {
          const peerCert = tlsSock.getPeerCertificate();
          if (!peerCert?.raw) {
            tlsSock.destroy();
            return;
          }
          const pubRaw = extractEd25519PubRawFromCertDer(peerCert.raw);
          const peerPubKeyHex = pubRaw.toString("hex");
          const check = verifySelfSignedEd25519Cert(peerCert.raw, peerPubKeyHex);
          if (!check.ok) {
            tlsSock.destroy();
            return;
          }

          if (isApi) {
            if (!tlsSock.authorized || !Boolean(await isAuthorizedPeer?.(peerPubKeyHex))) {
              tlsSock.destroy();
              return;
            }
            const channel = createFramedChannel(tlsSock);
            trackPeerChannel?.(peerPubKeyHex, channel);
            const linkInfo = { mode: modeLabel, linkType: modeLabel === "direct" ? "公网直连 mTLS" : "自建盲中转", isDirect: modeLabel === "direct" };
            Promise.resolve(
              onApiChannel?.(channel, {
                peerPubKeyHex,
                peerCertPem: check.certPem,
                linkInfo,
              }),
            ).catch(() => channel.destroy());
            return;
          }

          if (!Boolean(await hasActiveInvite?.())) {
            tlsSock.destroy();
            return;
          }
          const channel = createFramedChannel(tlsSock);
          const linkInfo = { mode: modeLabel, linkType: modeLabel === "direct" ? "公网直连 mTLS" : "自建盲中转", isDirect: modeLabel === "direct" };
          Promise.resolve(
            onPairChannel?.(channel, {
              peerPubKeyHex,
              peerCertPem: check.certPem,
              linkInfo,
            }),
          ).catch(() => channel.destroy());
        } catch (err) {
          onTlsError?.(err);
          tlsSock.destroy();
        }
      });
    } catch (err) {
      abortRaw(err);
    }
  };

  rawTransport.on("data", onPeek);
}

async function upgradeClientTls(
  rawTransportOrSocket,
  {
    identity,
    expectedHostPubKeyHex,
    expectedHostCertPem,
    alpn,
    host,
    port,
    timeoutMs = 10_000,
    modeLabel = "direct",
  },
) {
  const isPair = alpn === PAIR_ALPN;
  const servername = isPair ? "pair.mshare" : "api.mshare";
  if (!isPair && !expectedHostCertPem) {
    throw new Error("Pinned hostCertPem is required for mTLS API channel");
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        tlsSock.destroy();
        reject(new Error(`mTLS handshake timed out (${servername})`));
      }
    }, timeoutMs);
    timer.unref?.();

    const tlsOpts = {
      ...(rawTransportOrSocket ? { socket: rawTransportOrSocket } : { host, port }),
      key: identity.keyPem,
      cert: identity.certPem,
      minVersion: "TLSv1.3",
      ALPNProtocols: [alpn],
      servername,
      checkServerIdentity: () => undefined,
      ...(isPair
        ? { rejectUnauthorized: false }
        : { ca: [expectedHostCertPem], rejectUnauthorized: true }),
    };

    const tlsSock = tls.connect(tlsOpts, () => {
      if (settled) return;
      clearTimeout(timer);
      try {
        const peerCert = tlsSock.getPeerCertificate();
        if (!peerCert?.raw) {
          throw new Error("Host did not present a TLS certificate");
        }
        const check = verifySelfSignedEd25519Cert(peerCert.raw, expectedHostPubKeyHex);
        if (!check.ok) {
          throw new Error("Host Ed25519 certificate pin verification failed");
        }
        settled = true;
        const channel = createFramedChannel(tlsSock);
        const linkInfo = {
          mode: modeLabel,
          linkType: modeLabel === "direct" ? "公网直连 mTLS" : "自建盲中转",
          isDirect: modeLabel === "direct",
        };
        resolve({
          channel,
          hostPubKeyHex: check.pubKeyHex,
          peerPubKeyHex: check.pubKeyHex,
          hostCertPem: check.certPem,
          linkInfo,
          close: () => channel.close(),
        });
      } catch (err) {
        settled = true;
        tlsSock.destroy();
        reject(err);
      }
    });

    tlsSock.on("error", (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(err);
      }
    });
  });
}

/**
 * Parse Mode 2 relay address ("host:port", "[::1]:port", "ws://...", or "wss://...").
 */
export function parseRelayAddress(relayAddr) {
  if (typeof relayAddr !== "string" || !relayAddr.trim()) {
    throw new Error("Relay address is required");
  }
  const trimmed = relayAddr.trim();
  if (/^wss?:\/\//i.test(trimmed)) {
    const url = new URL(trimmed);
    if (!url.pathname || url.pathname === "/") url.pathname = "/ws";
    return { kind: "ws", url: url.toString(), label: trimmed };
  }
  const cleanTcp = trimmed.replace(/^tcp:\/\//i, "");
  let host;
  let portStr;
  if (cleanTcp.startsWith("[")) {
    const m = cleanTcp.match(/^\[([^\]]+)\]:(\d+)$/);
    if (!m) throw new Error(`Invalid IPv6 relay address: ${relayAddr}`);
    [, host, portStr] = m;
  } else {
    const idx = cleanTcp.lastIndexOf(":");
    if (idx <= 0) throw new Error(`Relay address must include port: ${relayAddr}`);
    host = cleanTcp.slice(0, idx);
    portStr = cleanTcp.slice(idx + 1);
  }
  const port = Number(portStr);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid relay port in address: ${relayAddr}`);
  }
  return { kind: "tcp", host, port, label: `${host}:${port}` };
}

function createWsTransportDuplex(ws, initialRemainder) {
  let eof = false;
  const duplex = new Duplex({
    read() {},
    write(chunk, _enc, cb) {
      if (ws.readyState !== 1) return cb(new Error("WebSocket relay connection is not open"));
      try {
        ws.send(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        cb();
      } catch (err) {
        cb(err);
      }
    },
    final(cb) {
      try {
        ws.close();
      } catch {}
      cb();
    },
    destroy(err, cb) {
      try {
        ws.close();
      } catch {}
      cb(err);
    },
  });

  if (initialRemainder?.length) {
    duplex.push(Buffer.from(initialRemainder));
  }
  ws.addEventListener("message", (ev) => {
    if (eof) return;
    const chunk = typeof ev.data === "string" ? Buffer.from(ev.data, "utf8") : Buffer.from(ev.data);
    if (chunk.length > 0) duplex.push(chunk);
  });
  ws.addEventListener("close", () => {
    if (!eof) {
      eof = true;
      duplex.push(null);
    }
  });
  ws.addEventListener("error", () => {
    if (!eof) {
      eof = true;
      duplex.destroy(new Error("WebSocket relay error"));
    }
  });
  return duplex;
}

async function openRelayChannel({ parsed, preamble, mode, onControlMsg, onControlClose, timeoutMs = 10_000 }) {
  if (parsed.kind === "ws") {
    const ws = new WebSocket(parsed.url);
    ws.binaryType = "arraybuffer";
    let lineBuf = Buffer.alloc(0);

    await new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        try { ws.close(); } catch {}
        reject(new Error(`Relay WebSocket connect timeout (${parsed.label})`));
      }, timeoutMs);
      t.unref?.();
      ws.addEventListener("open", () => { clearTimeout(t); resolve(); }, { once: true });
      ws.addEventListener("error", () => { clearTimeout(t); reject(new Error(`Relay WebSocket connect failed (${parsed.label})`)); }, { once: true });
    });

    ws.send(JSON.stringify(preamble) + "\n");

    const { ack, remainder } = await new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        try { ws.close(); } catch {}
        reject(new Error("Relay handshake timeout"));
      }, timeoutMs);
      t.unref?.();

      const cleanup = () => {
        clearTimeout(t);
        ws.removeEventListener("message", onMsg);
        ws.removeEventListener("close", onCls);
      };
      const onCls = () => {
        cleanup();
        reject(new Error("Relay closed before acknowledgment"));
      };
      const onMsg = (ev) => {
        const chunk = typeof ev.data === "string" ? Buffer.from(ev.data, "utf8") : Buffer.from(ev.data);
        lineBuf = Buffer.concat([lineBuf, chunk]);
        const nl = lineBuf.indexOf(0x0a);
        if (nl === -1) return;
        const line = lineBuf.subarray(0, nl).toString("utf8").replace(/\r$/, "");
        const rest = lineBuf.subarray(nl + 1);
        cleanup();
        try {
          resolve({ ack: JSON.parse(line), remainder: rest });
        } catch (err) {
          reject(err);
        }
      };
      ws.addEventListener("message", onMsg);
      ws.addEventListener("close", onCls);
    });

    if (!ack?.ok) {
      try { ws.close(); } catch {}
      const err = new Error(ack?.error || "Relay rejected connection");
      err.code = ack?.error || "relay_rejected";
      throw err;
    }

    if (mode === "control") {
      let ctlBuf = remainder?.length ? Buffer.from(remainder) : Buffer.alloc(0);
      const emitLines = () => {
        let nl;
        while ((nl = ctlBuf.indexOf(0x0a)) !== -1) {
          const line = ctlBuf.subarray(0, nl).toString("utf8").replace(/\r$/, "");
          ctlBuf = ctlBuf.subarray(nl + 1);
          if (!line) continue;
          try { onControlMsg?.(JSON.parse(line)); } catch {}
        }
      };
      emitLines();
      ws.addEventListener("message", (ev) => {
        const chunk = typeof ev.data === "string" ? Buffer.from(ev.data, "utf8") : Buffer.from(ev.data);
        ctlBuf = ctlBuf.length ? Buffer.concat([ctlBuf, chunk]) : chunk;
        emitLines();
      });
      ws.addEventListener("close", () => onControlClose?.());
      return {
        close() {
          try { ws.close(); } catch {}
        },
      };
    }

    return { ack, transport: createWsTransportDuplex(ws, remainder) };
  }

  // Raw TCP relay channel
  const sock = net.createConnection({ host: parsed.host, port: parsed.port });
  sock.setNoDelay(true);
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      sock.destroy();
      reject(new Error(`Relay TCP connect timeout (${parsed.label})`));
    }, timeoutMs);
    t.unref?.();
    sock.once("connect", () => { clearTimeout(t); resolve(); });
    sock.once("error", (err) => { clearTimeout(t); reject(err); });
  });

  sock.write(JSON.stringify(preamble) + "\n");

  let lineBuf = Buffer.alloc(0);
  const { ack, remainder } = await new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      sock.destroy();
      reject(new Error("Relay handshake timeout"));
    }, timeoutMs);
    t.unref?.();

    const cleanup = () => {
      clearTimeout(t);
      sock.off("data", onData);
      sock.off("close", onCls);
      sock.off("error", onErr);
    };
    const onCls = () => { cleanup(); reject(new Error("Relay closed before acknowledgment")); };
    const onErr = (err) => { cleanup(); reject(err); };
    const onData = (chunk) => {
      lineBuf = Buffer.concat([lineBuf, chunk]);
      const nl = lineBuf.indexOf(0x0a);
      if (nl === -1) return;
      const line = lineBuf.subarray(0, nl).toString("utf8").replace(/\r$/, "");
      const rest = lineBuf.subarray(nl + 1);
      cleanup();
      try {
        resolve({ ack: JSON.parse(line), remainder: rest });
      } catch (err) {
        reject(err);
      }
    };
    sock.on("data", onData);
    sock.on("close", onCls);
    sock.on("error", onErr);
  });

  if (!ack?.ok) {
    sock.destroy();
    const err = new Error(ack?.error || "Relay rejected connection");
    err.code = ack?.error || "relay_rejected";
    throw err;
  }

  if (mode === "control") {
    let ctlBuf = remainder?.length ? Buffer.from(remainder) : Buffer.alloc(0);
    const emitLines = () => {
      let nl;
      while ((nl = ctlBuf.indexOf(0x0a)) !== -1) {
        const line = ctlBuf.subarray(0, nl).toString("utf8").replace(/\r$/, "");
        ctlBuf = ctlBuf.subarray(nl + 1);
        if (!line) continue;
        try { onControlMsg?.(JSON.parse(line)); } catch {}
      }
    };
    emitLines();
    sock.on("data", (chunk) => {
      ctlBuf = ctlBuf.length ? Buffer.concat([ctlBuf, chunk]) : chunk;
      emitLines();
    });
    sock.on("close", () => onControlClose?.());
    sock.on("error", () => {});
    return {
      close() {
        if (!sock.destroyed) sock.destroy();
      },
    };
  }

  if (remainder?.length) {
    sock.pause();
    sock.unshift(remainder);
  }
  return { ack, transport: sock };
}

/**
 * Start Mode 3 Direct TCP TLS 1.3 mTLS host listener.
 */
export async function startDirectHost({
  identity,
  host = "::",
  port = 3497,
  isAuthorizedPeer,
  getAuthorizedCertPems,
  hasActiveInvite,
  onApiChannel,
  onPairChannel,
  onTlsError,
} = {}) {
  const peerChannels = new Map();
  const trackPeerChannel = (pubKeyHex, ch) => {
    const key = pubKeyHex.toLowerCase();
    let set = peerChannels.get(key);
    if (!set) {
      set = new Set();
      peerChannels.set(key, set);
    }
    set.add(ch);
    ch.onClose(() => {
      set.delete(ch);
      if (set.size === 0) peerChannels.delete(key);
    });
  };

  const rawSockets = new Set();
  const server = net.createServer((socket) => {
    rawSockets.add(socket);
    socket.setNoDelay(true);
    socket.on("close", () => rawSockets.delete(socket));
    attachTlsServerUpgrade(socket, {
      identity,
      isAuthorizedPeer,
      getAuthorizedCertPems,
      hasActiveInvite,
      onApiChannel,
      onPairChannel,
      trackPeerChannel,
      modeLabel: "direct",
      onTlsError,
    });
  });

  const listenAt = (listenHost) =>
    new Promise((resolve, reject) => {
      const onErr = (err) => reject(err);
      server.once("error", onErr);
      server.listen(
        listenHost === "::" ? { port, host: "::", ipv6Only: false } : { port, host: listenHost },
        () => {
          server.off("error", onErr);
          resolve();
        },
      );
    });

  try {
    await listenAt(host);
  } catch (err) {
    if (
      host === "::" &&
      (err?.code === "EAFNOSUPPORT" ||
        err?.code === "EADDRNOTAVAIL" ||
        err?.code === "EPROTONOSUPPORT" ||
        err?.code === "EINVAL")
    ) {
      await listenAt("0.0.0.0");
    } else {
      throw err;
    }
  }

  const addr = server.address();
  return {
    port: addr.port,
    host: addr.address,
    closePeer(pubKeyHex) {
      const set = peerChannels.get(pubKeyHex?.toLowerCase());
      if (!set) return;
      for (const ch of [...set]) ch.destroy(new Error("Peer access revoked"));
      peerChannels.delete(pubKeyHex?.toLowerCase());
    },
    async close() {
      for (const set of peerChannels.values()) {
        for (const ch of [...set]) ch.destroy();
      }
      peerChannels.clear();
      for (const s of rawSockets) s.destroy();
      rawSockets.clear();
      await new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

/**
 * Dial a Mode 3 Direct mTLS host (strictly connects only to target host:port).
 */
export async function dialDirectMtls(
  identity,
  { host, port, expectedHostPubKeyHex, expectedHostCertPem, alpn = API_ALPN, timeoutMs = 10_000 },
) {
  return upgradeClientTls(null, {
    identity,
    expectedHostPubKeyHex,
    expectedHostCertPem,
    alpn,
    host,
    port,
    timeoutMs,
    modeLabel: "direct",
  });
}

/**
 * Start Mode 2 Blind Relay host listener (registers host-ctl and upgrades paired tunnels to TLS 1.3 mTLS).
 */
export async function startRelayHost({
  identity,
  relayAddr,
  relayToken = "",
  isAuthorizedPeer,
  getAuthorizedCertPems,
  hasActiveInvite,
  onApiChannel,
  onPairChannel,
  onStatusChange,
  onTlsError,
} = {}) {
  const parsed = parseRelayAddress(relayAddr);
  const slotId = slotIdForHost(identity.pubKeyHex);
  const peerChannels = new Map();
  const dataTransports = new Set();
  let stopped = false;
  let ctlHandle = null;
  let reconnectTimer = null;

  const trackPeerChannel = (pubKeyHex, ch) => {
    const key = pubKeyHex.toLowerCase();
    let set = peerChannels.get(key);
    if (!set) {
      set = new Set();
      peerChannels.set(key, set);
    }
    set.add(ch);
    ch.onClose(() => {
      set.delete(ch);
      if (set.size === 0) peerChannels.delete(key);
    });
  };

  async function handlePair(connId) {
    if (stopped) return;
    try {
      const { transport } = await openRelayChannel({
        parsed,
        preamble: { role: "host-data", slotId, connId, token: relayToken || undefined },
        mode: "data",
      });
      if (stopped) {
        transport.destroy();
        return;
      }
      dataTransports.add(transport);
      transport.on("close", () => dataTransports.delete(transport));
      attachTlsServerUpgrade(transport, {
        identity,
        isAuthorizedPeer,
        getAuthorizedCertPems,
        hasActiveInvite,
        onApiChannel,
        onPairChannel,
        trackPeerChannel,
        modeLabel: "self-relay",
        onTlsError,
      });
    } catch (err) {
      onTlsError?.(err);
    }
  }

  async function connectCtl() {
    ctlHandle = await openRelayChannel({
      parsed,
      preamble: { role: "host-ctl", slotId, token: relayToken || undefined },
      mode: "control",
      onControlMsg: (msg) => {
        if (msg?.type === "pair" && typeof msg.connId === "string") {
          handlePair(msg.connId);
        }
      },
      onControlClose: () => {
        ctlHandle = null;
        if (stopped) return;
        onStatusChange?.({ connected: false, error: "relay_disconnected" });
        reconnectTimer = setTimeout(() => {
          reconnectTimer = null;
          if (!stopped) connectCtl().catch((e) => onStatusChange?.({ connected: false, error: e.message }));
        }, 1500);
        reconnectTimer.unref?.();
      },
    });
    onStatusChange?.({ connected: true, error: null });
  }

  await connectCtl();

  return {
    slotId,
    relayAddr: parsed.label,
    closePeer(pubKeyHex) {
      const set = peerChannels.get(pubKeyHex?.toLowerCase());
      if (!set) return;
      for (const ch of [...set]) ch.destroy(new Error("Peer access revoked"));
      peerChannels.delete(pubKeyHex?.toLowerCase());
    },
    async close() {
      stopped = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      reconnectTimer = null;
      ctlHandle?.close();
      ctlHandle = null;
      for (const set of peerChannels.values()) {
        for (const ch of [...set]) ch.destroy();
      }
      peerChannels.clear();
      for (const t of dataTransports) t.destroy();
      dataTransports.clear();
    },
  };
}

/**
 * Dial a host through a Mode 2 Blind Relay (TCP or WS/WSS) and establish inner TLS 1.3 mTLS.
 */
export async function dialRelayMtls(
  identity,
  {
    relayAddr,
    relayToken = "",
    expectedHostPubKeyHex,
    expectedHostCertPem,
    alpn = API_ALPN,
    timeoutMs = 10_000,
  },
) {
  const parsed = parseRelayAddress(relayAddr);
  const slotId = slotIdForHost(expectedHostPubKeyHex);
  const { transport } = await openRelayChannel({
    parsed,
    preamble: { role: "client", slotId, token: relayToken || undefined },
    mode: "data",
    timeoutMs,
  });

  try {
    return await upgradeClientTls(transport, {
      identity,
      expectedHostPubKeyHex,
      expectedHostCertPem,
      alpn,
      timeoutMs,
      modeLabel: "self-relay",
    });
  } catch (err) {
    transport.destroy();
    throw err;
  }
}

/**
 * Verify blind-relay connectivity, token auth, and round-trip opaque byte forwarding.
 */
export async function testBlindRelayConnectivity({ relayAddr, relayToken = "", timeoutMs = 6000 }) {
  const started = Date.now();
  let parsed;
  try {
    parsed = parseRelayAddress(relayAddr);
  } catch (err) {
    return { ok: false, rttMs: null, blindVerified: false, error: err.message };
  }

  const slotId = "probe-" + crypto.randomBytes(8).toString("hex");
  let ctl = null;
  let clientTransport = null;
  let hostDataTransport = null;

  try {
    let resolvePair;
    const pairPromise = new Promise((res) => {
      resolvePair = res;
    });

    ctl = await openRelayChannel({
      parsed,
      preamble: { role: "host-ctl", slotId, token: relayToken || undefined },
      mode: "control",
      timeoutMs,
      onControlMsg: (msg) => {
        if (msg?.type === "pair" && typeof msg.connId === "string") resolvePair(msg.connId);
      },
    });

    const clientPromise = openRelayChannel({
      parsed,
      preamble: { role: "client", slotId, token: relayToken || undefined },
      mode: "data",
      timeoutMs,
    });

    const connId = await Promise.race([
      pairPromise,
      new Promise((_, rej) => setTimeout(() => rej(new Error("Relay pair timeout")), timeoutMs)),
    ]);

    const [clientRes, hostDataRes] = await Promise.all([
      clientPromise,
      openRelayChannel({
        parsed,
        preamble: { role: "host-data", slotId, connId, token: relayToken || undefined },
        mode: "data",
        timeoutMs,
      }),
    ]);

    clientTransport = clientRes.transport;
    hostDataTransport = hostDataRes.transport;

    const nonce = crypto.randomBytes(24);
    const echoOk = await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("Relay data echo timeout")), timeoutMs);
      t.unref?.();
      let cBuf = Buffer.alloc(0);
      let hBuf = Buffer.alloc(0);
      hostDataTransport.on("data", (d) => {
        hBuf = Buffer.concat([hBuf, d]);
        if (hBuf.length >= nonce.length) {
          hostDataTransport.write(hBuf.subarray(0, nonce.length));
        }
      });
      clientTransport.on("data", (d) => {
        cBuf = Buffer.concat([cBuf, d]);
        if (cBuf.length >= nonce.length) {
          clearTimeout(t);
          resolve(cBuf.subarray(0, nonce.length).equals(nonce));
        }
      });
      clientTransport.write(nonce);
    });

    const rttMs = Date.now() - started;
    return { ok: echoOk, rttMs, blindVerified: echoOk };
  } catch (err) {
    return {
      ok: false,
      rttMs: null,
      blindVerified: false,
      error: err?.message || String(err),
    };
  } finally {
    try { clientTransport?.destroy(); } catch {}
    try { hostDataTransport?.destroy(); } catch {}
    try { ctl?.close(); } catch {}
  }
}
