import { irohIdFromPubKeyHex, pubKeyHexFromIrohId } from "./crypto.mjs";
import { loadIrohModule } from "./iroh-installer.mjs";
import { createFramedChannel } from "./wire.mjs";

export const PAIR_ALPN = "mshare-pair/1";
export const API_ALPN = "mshare-api/1";

const toAlpnBytes = (alpn) => Array.from(Buffer.from(alpn, "utf8"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function normalizeAddrs(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw.filter((a) => typeof a === "string" && a.trim().length > 0);
  if (typeof raw === "string" && raw.trim().length > 0) return [raw.trim()];
  return [];
}

function resolveTarget(target = {}) {
  const ep = target.ep && typeof target.ep === "object" ? target.ep : target;
  const expectedIrohId =
    target.targetIrohId ||
    target.irohEndpointId ||
    ep.irohEndpointId ||
    (target.hostPubKeyHex ? irohIdFromPubKeyHex(target.hostPubKeyHex) : "") ||
    (target.pk ? irohIdFromPubKeyHex(target.pk) : "");
  if (!expectedIrohId) {
    throw new Error("Target Iroh EndpointId is required");
  }
  const normalizedIrohId = irohIdFromPubKeyHex(pubKeyHexFromIrohId(expectedIrohId));
  const relayUrl = target.relayUrl ?? target.irohRelayUrl ?? ep.relayUrl ?? null;
  const directAddrs = normalizeAddrs(
    target.directAddrs ?? target.addrs ?? target.addr ?? ep.directAddrs ?? ep.addrs ?? ep.addr,
  );
  return { expectedIrohId: normalizedIrohId, relayUrl, directAddrs };
}

export function extractIrohLinkInfo(conn) {
  let paths = [];
  try {
    paths = typeof conn?.paths === "function" ? conn.paths() : [];
  } catch {
    paths = [];
  }
  const selected = paths.find((p) => p?.isSelected) || paths[0] || null;
  if (!selected) {
    return {
      mode: "p2p",
      linkType: "Iroh QUIC",
      isDirect: false,
      isIp: false,
      isRelay: false,
      rttMs: conn?.rtt?.() ?? null,
      remoteAddr: null,
    };
  }
  const isIp = Boolean(selected.isIp && !selected.isRelay);
  const rttMs = typeof selected.rttMs === "number" ? selected.rttMs : selected.stats?.rttMs ?? null;
  return {
    mode: "p2p",
    linkType: isIp ? "P2P 直连" : "盲中转加密",
    isDirect: isIp,
    isIp,
    isRelay: Boolean(selected.isRelay),
    rttMs,
    remoteAddr: selected.remoteAddr || null,
  };
}

async function bindIrohEndpoint(
  iroh,
  { seed32, alpns, relayMode = "default", irohRelayUrl = "", bindAddr, onlineTimeoutMs = 2500 },
) {
  const builder = iroh.Endpoint.builder();
  const effectiveMode =
    relayMode === "minimal" || relayMode === "disabled"
      ? relayMode
      : irohRelayUrl
        ? "custom"
        : "default";

  if (effectiveMode === "minimal") {
    iroh.presetMinimal(builder);
  } else if (effectiveMode === "disabled") {
    iroh.presetN0DisableRelay(builder);
  } else if (effectiveMode === "custom") {
    iroh.presetN0(builder);
    builder.relayMode(iroh.RelayMode.customFromUrls([irohRelayUrl]));
  } else {
    iroh.presetN0(builder);
    builder.relayMode(iroh.RelayMode.defaultMode());
  }

  builder.secretKey(Array.from(seed32));
  builder.alpns(alpns.map(toAlpnBytes));
  if (bindAddr) builder.bindAddr(bindAddr);

  const ep = await builder.bind();
  if ((effectiveMode === "default" || effectiveMode === "custom") && onlineTimeoutMs > 0) {
    await Promise.race([ep.online().catch(() => {}), sleep(onlineTimeoutMs)]);
  }
  return ep;
}

/**
 * Start the Mode 1 Iroh QUIC host listener with strict Ed25519 EndpointId authorization.
 */
export async function startIrohHost({
  identity,
  irohDir,
  relayMode = "default",
  irohRelayUrl = "",
  bindAddr,
  onlineTimeoutMs = 2500,
  isAuthorizedPeer,
  hasActiveInvite,
  onApiChannel,
  onPairChannel,
} = {}) {
  const iroh = loadIrohModule(irohDir);
  const ep = await bindIrohEndpoint(iroh, {
    seed32: identity.seed32,
    alpns: [PAIR_ALPN, API_ALPN],
    relayMode,
    irohRelayUrl,
    bindAddr,
    onlineTimeoutMs,
  });

  let stopped = false;
  const activePeers = new Map();

  function trackPeerConn(pubKeyHex, conn) {
    let set = activePeers.get(pubKeyHex);
    if (!set) {
      set = new Set();
      activePeers.set(pubKeyHex, set);
    }
    const entry = { conn, channels: new Set() };
    set.add(entry);
    return entry;
  }

  function untrackPeerConn(pubKeyHex, entry) {
    const set = activePeers.get(pubKeyHex);
    if (!set) return;
    set.delete(entry);
    if (set.size === 0) activePeers.delete(pubKeyHex);
  }

  async function handleIncoming(incoming) {
    let conn = null;
    try {
      const accepting = await incoming.accept();
      conn = await accepting.connect();
      const alpn = Buffer.from(conn.alpn()).toString("utf8");
      const remoteId = conn.remoteId().toString();

      let peerPubKeyHex;
      try {
        peerPubKeyHex = pubKeyHexFromIrohId(remoteId);
      } catch {
        try {
          conn.close(403n, toAlpnBytes("bad_peer_id"));
        } catch {}
        return;
      }

      if (alpn === API_ALPN) {
        const authorized = Boolean(await isAuthorizedPeer?.(peerPubKeyHex));
        if (!authorized) {
          try {
            conn.close(403n, toAlpnBytes("unauthorized"));
          } catch {}
          return;
        }
        const entry = trackPeerConn(peerPubKeyHex, conn);
        try {
          while (!stopped && !conn.closeReason?.()) {
            const bi = await conn.acceptBi();
            if (!bi || stopped) break;
            if (!Boolean(await isAuthorizedPeer?.(peerPubKeyHex))) {
              try {
                await bi.send.reset?.(403n);
                await bi.recv.stop?.(403n);
              } catch {}
              try {
                conn.close(403n, toAlpnBytes("revoked"));
              } catch {}
              break;
            }
            const channel = createFramedChannel(bi);
            entry.channels.add(channel);
            channel.onClose(() => entry.channels.delete(channel));
            const linkStats = extractIrohLinkInfo(conn);
            Promise.resolve(
              onApiChannel?.(channel, {
                peerPubKeyHex,
                peerCertPem: null,
                linkStats,
                linkInfo: linkStats,
              }),
            ).catch(() => channel.destroy());
          }
        } catch {
          // Connection closed by peer or locally
        } finally {
          untrackPeerConn(peerPubKeyHex, entry);
        }
        return;
      }

      if (alpn === PAIR_ALPN) {
        const inviteActive = Boolean(await hasActiveInvite?.());
        if (!inviteActive) {
          try {
            conn.close(403n, toAlpnBytes("no_active_invite"));
          } catch {}
          return;
        }
        const entry = trackPeerConn(peerPubKeyHex, conn);
        try {
          while (!stopped && !conn.closeReason?.()) {
            const bi = await conn.acceptBi();
            if (!bi || stopped) break;
            const channel = createFramedChannel(bi);
            entry.channels.add(channel);
            channel.onClose(() => entry.channels.delete(channel));
            const linkStats = extractIrohLinkInfo(conn);
            Promise.resolve(
              onPairChannel?.(channel, {
                peerPubKeyHex,
                peerCertPem: null,
                linkStats,
                linkInfo: linkStats,
              }),
            ).catch(() => channel.destroy());
          }
        } catch {
          // Pair connection closed
        } finally {
          untrackPeerConn(peerPubKeyHex, entry);
        }
        return;
      }

      try {
        conn.close(400n, toAlpnBytes("unsupported_alpn"));
      } catch {}
    } catch {
      if (conn) {
        try {
          conn.close(1n, toAlpnBytes("accept_error"));
        } catch {}
      }
    }
  }

  const acceptTask = (async () => {
    while (!stopped && !ep.isClosed()) {
      let incoming;
      try {
        incoming = await ep.acceptNext();
      } catch {
        break;
      }
      if (!incoming || stopped) break;
      handleIncoming(incoming);
    }
  })();

  function closePeer(pubKeyHex) {
    if (!pubKeyHex) return;
    const key = pubKeyHex.toLowerCase();
    const set = activePeers.get(key);
    if (!set) return;
    for (const entry of [...set]) {
      for (const ch of [...entry.channels]) {
        try {
          ch.destroy(new Error("Peer access revoked"));
        } catch {}
      }
      try {
        entry.conn.close(403n, toAlpnBytes("revoked"));
      } catch {}
    }
    activePeers.delete(key);
  }

  function getAddrInfo() {
    try {
      const addr = ep.addr();
      return {
        irohEndpointId: ep.id().toString(),
        relayUrl: addr.relayUrl() || null,
        directAddrs: addr.directAddresses() || [],
      };
    } catch {
      return {
        irohEndpointId: identity.irohEndpointId,
        relayUrl: irohRelayUrl || null,
        directAddrs: [],
      };
    }
  }

  return {
    endpointId: ep.id().toString(),
    getAddrInfo,
    closePeer,
    async close() {
      if (stopped) return;
      stopped = true;
      for (const pubKeyHex of [...activePeers.keys()]) {
        closePeer(pubKeyHex);
      }
      await ep.close().catch(() => {});
      await acceptTask.catch(() => {});
    },
  };
}

/**
 * Reusable Iroh client endpoint & connection pool for Mode 1 API calls.
 */
export function createIrohClientPool({
  identity,
  irohDir,
  relayMode = "default",
  irohRelayUrl = "",
  bindAddr,
  onlineTimeoutMs = 2500,
} = {}) {
  let endpointPromise = null;
  let closed = false;
  const conns = new Map();

  async function getEndpoint() {
    if (closed) throw new Error("Iroh client pool is closed");
    if (!endpointPromise) {
      endpointPromise = (async () => {
        const iroh = loadIrohModule(irohDir);
        const ep = await bindIrohEndpoint(iroh, {
          seed32: identity.seed32,
          alpns: [API_ALPN],
          relayMode,
          irohRelayUrl,
          bindAddr,
          onlineTimeoutMs,
        });
        return { iroh, ep };
      })();
    }
    return endpointPromise;
  }

  async function openApiStream(target) {
    const { expectedIrohId, relayUrl, directAddrs } = resolveTarget(target);
    const { iroh, ep } = await getEndpoint();

    const cacheKey = `${expectedIrohId}|${relayUrl || ""}|${directAddrs.join(",")}`;
    let conn = conns.get(cacheKey);
    if (conn) {
      try {
        if (conn.closeReason?.() !== null && conn.closeReason?.() !== undefined) {
          conn = null;
          conns.delete(cacheKey);
        } else {
          const bi = await conn.openBi();
          const channel = createFramedChannel(bi);
          const linkInfo = extractIrohLinkInfo(conn);
          const peerPubKeyHex = pubKeyHexFromIrohId(expectedIrohId);
          return {
            channel,
            peerPubKeyHex,
            hostPubKeyHex: peerPubKeyHex,
            hostCertPem: null,
            linkInfo,
            close: () => channel.close(),
          };
        }
      } catch {
        try {
          conn?.close(0n, []);
        } catch {}
        conns.delete(cacheKey);
        conn = null;
      }
    }

    const endpointId = iroh.EndpointId.fromString(expectedIrohId);
    const addr = new iroh.EndpointAddr(
      endpointId,
      relayUrl || undefined,
      directAddrs.length ? directAddrs : undefined,
    );
    conn = await ep.connect(addr, toAlpnBytes(API_ALPN));
    const actualRemoteId = conn.remoteId().toString();
    if (actualRemoteId !== expectedIrohId) {
      try {
        conn.close(403n, toAlpnBytes("id_mismatch"));
      } catch {}
      throw new Error(`Iroh EndpointId mismatch: expected ${expectedIrohId}, got ${actualRemoteId}`);
    }
    conns.set(cacheKey, conn);
    const bi = await conn.openBi();
    const channel = createFramedChannel(bi);
    const linkInfo = extractIrohLinkInfo(conn);
    const peerPubKeyHex = pubKeyHexFromIrohId(actualRemoteId);
    return {
      channel,
      peerPubKeyHex,
      hostPubKeyHex: peerPubKeyHex,
      hostCertPem: null,
      linkInfo,
      close: () => channel.close(),
    };
  }

  return {
    openApiStream,
    async close() {
      closed = true;
      for (const c of conns.values()) {
        try {
          c.close(0n, []);
        } catch {}
      }
      conns.clear();
      if (endpointPromise) {
        const p = endpointPromise;
        endpointPromise = null;
        try {
          const { ep } = await p;
          await ep.close();
        } catch {}
      }
    },
  };
}

async function dialSingle(identity, irohDir, target, alpn, opts = {}) {
  const { expectedIrohId, relayUrl, directAddrs } = resolveTarget(target);
  const iroh = loadIrohModule(irohDir);
  const effectiveMode =
    opts.relayMode ?? target?.relayMode ?? (relayUrl ? "custom" : "default");
  const ep = await bindIrohEndpoint(iroh, {
    seed32: identity.seed32,
    alpns: [alpn],
    relayMode: effectiveMode,
    irohRelayUrl: relayUrl || opts.irohRelayUrl || "",
    bindAddr: opts.bindAddr,
    onlineTimeoutMs: opts.onlineTimeoutMs ?? 2500,
  });

  let conn = null;
  let channel = null;
  try {
    const endpointId = iroh.EndpointId.fromString(expectedIrohId);
    const addr = new iroh.EndpointAddr(
      endpointId,
      relayUrl || undefined,
      directAddrs.length ? directAddrs : undefined,
    );
    conn = await ep.connect(addr, toAlpnBytes(alpn));
    const actualRemoteId = conn.remoteId().toString();
    if (actualRemoteId !== expectedIrohId) {
      throw new Error(`Iroh EndpointId mismatch: expected ${expectedIrohId}, got ${actualRemoteId}`);
    }
    const bi = await conn.openBi();
    channel = createFramedChannel(bi);
    const linkInfo = extractIrohLinkInfo(conn);
    const peerPubKeyHex = pubKeyHexFromIrohId(actualRemoteId);

    const close = async () => {
      await channel?.close().catch(() => {});
      try {
        conn?.close(0n, []);
      } catch {}
      await ep.close().catch(() => {});
    };

    return {
      channel,
      peerPubKeyHex,
      hostPubKeyHex: peerPubKeyHex,
      hostCertPem: null,
      linkInfo,
      close,
    };
  } catch (err) {
    try {
      channel?.destroy(err);
    } catch {}
    try {
      conn?.close(1n, []);
    } catch {}
    await ep.close().catch(() => {});
    throw err;
  }
}

export async function dialPair(identity, irohDir, target, opts = {}) {
  return dialSingle(identity, irohDir, target, PAIR_ALPN, opts);
}

export async function dialApi(identity, irohDir, target, opts = {}) {
  if (opts.pool && typeof opts.pool.openApiStream === "function") {
    return opts.pool.openApiStream(target);
  }
  return dialSingle(identity, irohDir, target, API_ALPN, opts);
}
