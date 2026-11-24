import net from "node:net";
import os from "node:os";
import { getIrohStatus } from "./iroh-installer.mjs";
import {
  API_ALPN,
  PAIR_ALPN,
  createIrohClientPool,
  dialApi as dialIrohApi,
  dialPair as dialIrohPair,
  startIrohHost,
} from "./transport-iroh.mjs";
import {
  dialDirectMtls,
  dialRelayMtls,
  startDirectHost,
  startRelayHost,
  testBlindRelayConnectivity,
} from "./transport-mtls.mjs";
import { serveHttpRequestOnChannel } from "./wire.mjs";

function jsonErrorResponse(status, code, message) {
  return {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
    body: JSON.stringify({ code, error: { code, message } }),
  };
}

function listLocalAddresses() {
  const ifaces = os.networkInterfaces();
  const publicIpv6 = [];
  const ipv4 = [];
  for (const entries of Object.values(ifaces)) {
    if (!Array.isArray(entries)) continue;
    for (const info of entries) {
      if (!info || info.internal) continue;
      if (info.family === "IPv6") {
        const lower = info.address.toLowerCase();
        const isLinkLocal = lower.startsWith("fe80:");
        const isUniqueLocal = lower.startsWith("fc") || lower.startsWith("fd");
        if (!isLinkLocal && !isUniqueLocal && lower !== "::1") {
          publicIpv6.push(info.address.split("%")[0]);
        }
      } else if (info.family === "IPv4") {
        ipv4.push(info.address);
      }
    }
  }
  return { publicIpv6, ipv4 };
}

async function probeTcpReachable(host, port, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const sock = net.createConnection({ host, port });
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(ok);
    };
    const t = setTimeout(() => finish(false), timeoutMs);
    t.unref?.();
    sock.once("connect", () => {
      clearTimeout(t);
      finish(true);
    });
    sock.once("error", () => {
      clearTimeout(t);
      finish(false);
    });
  });
}

/**
 * Unified transport manager orchestrating Mode 1 (Iroh QUIC), Mode 2 (Blind Relay mTLS),
 * and Mode 3 (Direct IPv6/IPv4 mTLS) with strict no-fallback guarantees.
 */
export function createTransportManager({
  identity,
  irohDir,
  store,
  onApiRequest,
  onPairSession,
  irohOptions = {},
  directBindHost = "::",
  onStatusChange,
} = {}) {
  let hostHandle = null;
  let activeKey = null;
  let hostError = null;
  let irohPool = null;
  let irohPoolKey = null;
  let mutex = Promise.resolve();
  let stopped = false;
  const activeChannels = new Map(); // pubKeyHexLower -> Set<channel>

  const runExclusive = (fn) => {
    const next = mutex.catch(() => {}).then(fn);
    mutex = next;
    return next;
  };

  function getAuthorizedMembersMap() {
    const state = store.get();
    const map = new Map();
    for (const m of state.members || []) {
      if (m && m.status !== "revoked" && m.clientPubKeyHex && m.clientCertPem) {
        map.set(m.clientPubKeyHex.toLowerCase(), m);
      }
    }
    return { state, map };
  }

  function isAuthorizedPeer(pubKeyHex) {
    if (typeof pubKeyHex !== "string") return false;
    return getAuthorizedMembersMap().map.has(pubKeyHex.toLowerCase());
  }

  function getAuthorizedCertPems() {
    return [...getAuthorizedMembersMap().map.values()].map((m) => m.clientCertPem);
  }

  function hasActiveInvite() {
    const state = store.get();
    if (!state.sharingEnabled) return false;
    const now = Date.now();
    const hasUnusedInvite = (state.invites || []).some(
      (inv) =>
        inv &&
        !inv.used &&
        !inv.revoked &&
        (Number(inv.attempts) || 0) < 5 &&
        Number(inv.exp) > now,
    );
    const hasPending = Array.isArray(state.pending) && state.pending.length > 0;
    return hasUnusedInvite || hasPending;
  }

  function trackChannel(pubKeyHex, channel) {
    const key = pubKeyHex.toLowerCase();
    let set = activeChannels.get(key);
    if (!set) {
      set = new Set();
      activeChannels.set(key, set);
    }
    set.add(channel);
    channel.onClose(() => {
      set.delete(channel);
      if (set.size === 0) activeChannels.delete(key);
    });
  }

  function closePeerChannels(pubKeyHex) {
    const key = pubKeyHex.toLowerCase();
    const set = activeChannels.get(key);
    if (set) {
      for (const ch of [...set]) {
        try {
          ch.destroy(new Error("Peer access revoked"));
        } catch {}
      }
      activeChannels.delete(key);
    }
    hostHandle?.closePeer?.(key);
  }

  function handleIncomingApiChannel(channel, meta) {
    const peerPubKeyHex = meta.peerPubKeyHex.toLowerCase();
    trackChannel(peerPubKeyHex, channel);
    const stopServe = serveHttpRequestOnChannel(channel, async (req, { signal }) => {
      const { state, map } = getAuthorizedMembersMap();
      if (!state.sharingEnabled) {
        return jsonErrorResponse(503, "share_offline", "Host sharing is disabled");
      }
      const member = map.get(peerPubKeyHex);
      if (!member) {
        setTimeout(() => closePeerChannels(peerPubKeyHex), 0);
        return jsonErrorResponse(403, "share_revoked", "Member access has been revoked");
      }
      if (typeof onApiRequest !== "function") {
        return jsonErrorResponse(503, "gateway_unconfigured", "Host gateway handler not configured");
      }
      return onApiRequest(member.id, req, {
        signal,
        member,
        peerPubKeyHex,
        linkInfo: meta.linkInfo || meta.linkStats || null,
      });
    });
    channel.onClose(() => stopServe());
  }

  function handleIncomingPairChannel(channel, meta) {
    Promise.resolve(
      onPairSession?.(channel, {
        peerPubKeyHex: meta.peerPubKeyHex,
        peerCertPem: meta.peerCertPem || null,
        linkInfo: meta.linkInfo || meta.linkStats || null,
      }),
    ).catch(() => channel.destroy());
  }

  async function stopHostListener() {
    const prev = hostHandle;
    hostHandle = null;
    activeKey = null;
    for (const peerKey of [...activeChannels.keys()]) {
      closePeerChannels(peerKey);
    }
    if (prev) {
      await prev.close().catch(() => {});
    }
  }

  function evictUnauthorizedPeers() {
    const { map } = getAuthorizedMembersMap();
    for (const peerKey of [...activeChannels.keys()]) {
      if (!map.has(peerKey)) {
        closePeerChannels(peerKey);
      }
    }
  }

  function desiredHostSpec(state) {
    if (!state.sharingEnabled) return { key: null, error: null };
    const netCfg = state.network || {};
    if (state.mode === "p2p") {
      const irohStatus = getIrohStatus(irohDir);
      if (!irohStatus.supported) {
        return {
          key: null,
          error: irohStatus.unsupportedReason || "当前平台暂不支持 Mode 1 (@number0/iroh)，请切换到模式 2 或模式 3",
        };
      }
      if (!irohStatus.installed || !irohStatus.integrityOk) {
        return {
          key: null,
          error: "Mode 1 (@number0/iroh) 组件尚未就绪，请先在「连接与安全」下载安装",
        };
      }
      const relayUrl = String(netCfg.irohRelayUrl || "").trim();
      const relayMode = irohOptions.relayMode || (relayUrl ? "custom" : "default");
      return {
        key: `p2p|${relayMode}|${relayUrl}|${irohOptions.bindAddr || ""}`,
        mode: "p2p",
        relayMode,
        irohRelayUrl: relayUrl,
      };
    }
    if (state.mode === "self-relay") {
      const relayAddr = String(netCfg.relayAddr || "").trim();
      if (!relayAddr) {
        return { key: null, error: "未配置自建盲中转地址" };
      }
      const relayToken = String(netCfg.relayToken || "");
      return {
        key: `self-relay|${relayAddr}|${relayToken}`,
        mode: "self-relay",
        relayAddr,
        relayToken,
      };
    }
    if (state.mode === "direct") {
      const port = Number(netCfg.directPort || 3497);
      return {
        key: `direct|${directBindHost}|${port}`,
        mode: "direct",
        host: directBindHost,
        port,
      };
    }
    return { key: null, error: `未知传输模式: ${String(state.mode)}` };
  }

  async function applyReconfigure() {
    if (stopped) return getHostStatus();
    evictUnauthorizedPeers();
    const state = store.get();
    const spec = desiredHostSpec(state);

    if (!spec.key) {
      await stopHostListener();
      hostError = spec.error;
      const st = getHostStatus();
      onStatusChange?.(st);
      return st;
    }

    if (activeKey === spec.key && hostHandle) {
      hostError = null;
      return getHostStatus();
    }

    await stopHostListener();
    hostError = null;

    try {
      const callbacks = {
        identity,
        isAuthorizedPeer,
        getAuthorizedCertPems,
        hasActiveInvite,
        onApiChannel: handleIncomingApiChannel,
        onPairChannel: handleIncomingPairChannel,
      };

      if (spec.mode === "p2p") {
        const h = await startIrohHost({
          ...callbacks,
          irohDir,
          relayMode: spec.relayMode,
          irohRelayUrl: spec.irohRelayUrl,
          bindAddr: irohOptions.bindAddr,
          onlineTimeoutMs: irohOptions.onlineTimeoutMs ?? 2500,
        });
        hostHandle = { ...h, mode: "p2p", boundPort: null };
      } else if (spec.mode === "self-relay") {
        const h = await startRelayHost({
          ...callbacks,
          relayAddr: spec.relayAddr,
          relayToken: spec.relayToken,
          onStatusChange: (s) => {
            hostError = s.connected ? null : s.error || "relay_disconnected";
            onStatusChange?.(getHostStatus());
          },
        });
        hostHandle = { ...h, mode: "self-relay", boundPort: null };
      } else if (spec.mode === "direct") {
        const h = await startDirectHost({
          ...callbacks,
          host: spec.host,
          port: spec.port,
        });
        hostHandle = { ...h, mode: "direct", boundPort: h.port };
      }
      activeKey = spec.key;
    } catch (err) {
      hostHandle = null;
      activeKey = null;
      hostError = err?.message || String(err);
    }

    const st = getHostStatus();
    onStatusChange?.(st);
    return st;
  }

  function getHostStatus() {
    const state = store.get();
    if (!state.sharingEnabled) {
      return {
        listening: false,
        activeMode: state.mode,
        linkLabel: "分享已暂停",
        error: null,
        boundPort: null,
        irohEndpointId: identity.irohEndpointId,
      };
    }
    if (hostError) {
      return {
        listening: false,
        activeMode: state.mode,
        linkLabel: `通道异常：${hostError}`,
        error: hostError,
        boundPort: null,
        irohEndpointId: identity.irohEndpointId,
      };
    }
    if (hostHandle && hostHandle.mode === state.mode) {
      let linkLabel = "通道已就绪";
      if (state.mode === "p2p") linkLabel = "Iroh QUIC P2P 监听中";
      else if (state.mode === "self-relay") linkLabel = `自建盲中转已连接 (${state.network?.relayAddr || ""})`;
      else if (state.mode === "direct") linkLabel = `公网直连 mTLS 监听中 (:${hostHandle.boundPort})`;
      return {
        listening: true,
        activeMode: state.mode,
        linkLabel,
        error: null,
        boundPort: hostHandle.boundPort ?? null,
        irohEndpointId: identity.irohEndpointId,
      };
    }
    return {
      listening: false,
      activeMode: state.mode,
      linkLabel: "通道准备中…",
      error: null,
      boundPort: null,
      irohEndpointId: identity.irohEndpointId,
    };
  }

  function getHostEndpointPayload(modeOverride) {
    const state = store.get();
    const mode = modeOverride || state.mode;
    const netCfg = state.network || {};
    if (mode === "p2p") {
      const addrInfo = hostHandle?.mode === "p2p" ? hostHandle.getAddrInfo?.() : null;
      return {
        irohEndpointId: identity.irohEndpointId,
        relayUrl: netCfg.irohRelayUrl || addrInfo?.relayUrl || null,
        directAddrs: addrInfo?.directAddrs || [],
      };
    }
    if (mode === "self-relay") {
      return {
        relayAddr: netCfg.relayAddr || "",
        relayToken: netCfg.relayToken || "",
      };
    }
    if (mode === "direct") {
      const boundPort = hostHandle?.mode === "direct" ? hostHandle.boundPort : null;
      return {
        directHost: netCfg.directHost || "",
        directPort: Number(boundPort || netCfg.directPort || 3497),
      };
    }
    throw new Error(`Unsupported mode for endpoint payload: ${String(mode)}`);
  }

  async function getOrCreateIrohPool(relayUrl) {
    const relayMode = irohOptions.relayMode || (relayUrl ? "custom" : "default");
    const key = `${relayMode}|${relayUrl || ""}|${irohOptions.bindAddr || ""}`;
    if (irohPool && irohPoolKey !== key) {
      await irohPool.close().catch(() => {});
      irohPool = null;
      irohPoolKey = null;
    }
    if (!irohPool) {
      irohPool = createIrohClientPool({
        identity,
        irohDir,
        relayMode,
        irohRelayUrl: relayUrl || "",
        bindAddr: irohOptions.bindAddr,
        onlineTimeoutMs: irohOptions.onlineTimeoutMs ?? 2500,
      });
      irohPoolKey = key;
    }
    return irohPool;
  }

  async function dialBySpec(target, alpn) {
    const mode = target?.m || target?.mode;
    const ep = target?.ep && typeof target.ep === "object" ? target.ep : target || {};
    const expectedHostPubKeyHex = target?.pk || target?.hostPubKeyHex;
    const expectedHostCertPem = target?.hostCertPem;
    const state = store.get();

    if (!expectedHostPubKeyHex) {
      throw new Error("Target host public key is required");
    }

    if (mode === "p2p") {
      const relayUrl = ep.relayUrl ?? state.network?.irohRelayUrl ?? null;
      const effectiveRelayMode = irohOptions.relayMode || (relayUrl ? "custom" : "default");
      const dialTarget = {
        targetIrohId: ep.irohEndpointId,
        hostPubKeyHex: expectedHostPubKeyHex,
        relayUrl,
        directAddrs: ep.directAddrs,
        relayMode: effectiveRelayMode,
      };
      if (alpn === PAIR_ALPN) {
        return dialIrohPair(identity, irohDir, dialTarget, {
          relayMode: effectiveRelayMode,
          bindAddr: irohOptions.bindAddr,
          onlineTimeoutMs: irohOptions.onlineTimeoutMs ?? 2500,
        });
      }
      const pool = await getOrCreateIrohPool(relayUrl);
      return dialIrohApi(identity, irohDir, dialTarget, { pool });
    }

    if (mode === "self-relay") {
      const relayAddr = ep.relayAddr || target?.relayAddr;
      const relayToken = ep.relayToken ?? target?.relayToken ?? state.network?.relayToken ?? "";
      if (!relayAddr) throw new Error("Mode 2 invite/share missing relayAddr");
      return dialRelayMtls(identity, {
        relayAddr,
        relayToken,
        expectedHostPubKeyHex,
        expectedHostCertPem,
        alpn,
      });
    }

    if (mode === "direct") {
      const directHost = ep.directHost || target?.directHost;
      const directPort = Number(ep.directPort || target?.directPort || 3497);
      if (!directHost) throw new Error("Mode 3 invite/share missing directHost");
      return dialDirectMtls(identity, {
        host: directHost,
        port: directPort,
        expectedHostPubKeyHex,
        expectedHostCertPem,
        alpn,
      });
    }

    throw new Error(`Unsupported transport mode: ${String(mode)}`);
  }

  return {
    start: () =>
      runExclusive(async () => {
        stopped = false;
        return applyReconfigure();
      }),
    reconfigure: () => runExclusive(applyReconfigure),
    stop: () =>
      runExclusive(async () => {
        stopped = true;
        await stopHostListener();
        for (const pubKeyHex of [...activeChannels.keys()]) {
          closePeerChannels(pubKeyHex);
        }
        if (irohPool) {
          await irohPool.close().catch(() => {});
          irohPool = null;
          irohPoolKey = null;
        }
      }),
    getHostStatus,
    getHostEndpointPayload,
    dialPair: (invite) => dialBySpec(invite, PAIR_ALPN),
    dialApi: (share) => dialBySpec(share, API_ALPN),
    testRelay: ({ relayAddr, relayToken = "" } = {}) =>
      testBlindRelayConnectivity({ relayAddr, relayToken }),
    testDirect: async ({ directHost = "", directPort = 3497 } = {}) => {
      const { publicIpv6, ipv4 } = listLocalAddresses();
      const port = Number(directPort || 3497);
      let reachable = false;
      if (directHost && String(directHost).trim()) {
        reachable = await probeTcpReachable(String(directHost).trim(), port);
      } else if (hostHandle?.mode === "direct") {
        reachable = true;
      }
      const hasPublicIpv6 = publicIpv6.length > 0;
      const addresses = hasPublicIpv6 ? publicIpv6 : ipv4;
      let message;
      if (directHost && reachable) {
        message = `公网直连端口 ${directHost}:${port} 可达${hasPublicIpv6 ? "（已检测到公网 IPv6）" : ""}`;
      } else if (directHost && !reachable) {
        message = `端口 ${directHost}:${port} 暂不可达，请确认路由器/光猫已放行入站端口 ${port}`;
      } else if (hasPublicIpv6) {
        message = `已检测到公网 IPv6 地址，请在路由器放行入站端口 ${port}`;
      } else {
        message = `未检测到公网 IPv6（检测到内网/IPv4 地址），若无公网 IPv4 端口映射建议使用模式 1 或模式 2`;
      }
      return { ok: true, hasPublicIpv6, reachable, addresses, message };
    },
  };
}
