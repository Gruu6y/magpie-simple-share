import crypto from "node:crypto";
import { readFile } from "node:fs/promises";
import http from "node:http";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { loadOrCreateIdentity, timingSafeEqualStr } from "./crypto.mjs";
import { createHostGatewayHandler } from "./host-gateway.mjs";
import { getIrohStatus, installIroh } from "./iroh-installer.mjs";
import {
  addRemoteMagpieProvider,
  createMemberGatewayKey,
  discoverMagpieGateway,
  fetchLocalModels,
  removeMemberGatewayKey,
  removeRemoteMagpieProvider,
  updateMemberGatewayKey,
} from "./magpie-cli.mjs";
import { createPairingManager, PairingError } from "./pairing.mjs";
import { identityPath, irohDir, pluginDataDir, statePath } from "./paths.mjs";
import { BridgeError, createReceiverBridge } from "./receiver-bridge.mjs";
import { createStore, sanitizeStateSnapshot } from "./store.mjs";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const PACKAGE_ROOT = normalize(join(HERE, ".."));
const UI_ROOT = join(PACKAGE_ROOT, "ui");

export const TOKEN_HEADER = "x-simple-share-token";
const TOKEN_PLACEHOLDER = "__SIMPLE_SHARE_TOKEN__";
const MAX_JSON_BODY = 256 * 1024;
const VALID_MODES = new Set(["p2p", "self-relay", "direct"]);
const VALID_RANGES = new Set(["7d", "month", "all"]);

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".woff2": "font/woff2",
};

let packageVersion = "0.1.1";
try {
  const pkg = JSON.parse(await readFile(join(PACKAGE_ROOT, "package.json"), "utf8"));
  if (pkg?.version) packageVersion = String(pkg.version);
} catch {
  // Keep fallback version when package metadata is unavailable.
}

export class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.code = code;
  }
}

function inside(root, rel) {
  const full = normalize(join(root, rel));
  return full === root || full.startsWith(root + sep);
}

function originAllowed(origin, ownOrigins) {
  return origin === undefined || origin === "null" || ownOrigins.has(origin);
}

function applyCors(res, origin) {
  res.setHeader("access-control-allow-origin", origin ?? "*");
  res.setHeader("vary", "Origin");
}

function sendJson(res, status, payload) {
  if (res.headersSent) return;
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(JSON.stringify(payload));
}

function methodNotAllowed(res, allow) {
  res.writeHead(405, {
    allow,
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(JSON.stringify({ error: "method_not_allowed", code: "method_not_allowed", message: "Method not allowed." }));
}

async function readJson(req, { optional = false, maxBytes = MAX_JSON_BODY } = {}) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) {
      throw new HttpError(413, "payload_too_large", "Request body is too large.");
    }
    chunks.push(chunk);
  }
  if (size === 0) {
    if (optional) return {};
    throw new HttpError(400, "invalid_body", "Request body must be a JSON object.");
  }
  let parsed;
  try {
    parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, "invalid_json", "Request body must be valid JSON.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new HttpError(400, "invalid_body", "Request body must be a JSON object.");
  }
  return parsed;
}

function sendError(res, err) {
  if (res.headersSent) {
    res.end();
    return;
  }
  if (err instanceof HttpError || err instanceof PairingError || err instanceof BridgeError) {
    sendJson(res, err.status, {
      error: err.code,
      code: err.code,
      message: err.message,
    });
    return;
  }
  sendJson(res, 500, {
    error: "internal_error",
    code: "internal_error",
    message: String(err?.message || "Internal server error"),
  });
}

async function listenWithPortRetry(server, port, { windowMs = 0, abortSignal } = {}) {
  const startMs = Date.now();
  const tryListen = () =>
    new Promise((resolve, reject) => {
      const onErr = (err) => {
        server.removeListener("listening", onOk);
        reject(err);
      };
      const onOk = () => {
        server.removeListener("error", onErr);
        resolve(server.address().port);
      };
      server.once("error", onErr);
      server.once("listening", onOk);
      server.listen(port, "127.0.0.1");
    });

  while (true) {
    try {
      return await tryListen();
    } catch (err) {
      if (err?.code !== "EADDRINUSE" || port === 0 || windowMs <= 0) {
        throw err;
      }
      if (abortSignal?.aborted || Date.now() - startMs >= windowMs) {
        throw err;
      }
      await new Promise((r) => setTimeout(r, 250));
    }
  }
}

function decodeSegment(raw) {
  try {
    return decodeURIComponent(raw);
  } catch {
    throw new HttpError(400, "invalid_id", "Invalid identifier");
  }
}

function startOfLocalDayMs(now = Date.now()) {
  const d = new Date(now);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

function computeSecurityChecks({ state, magpieGateway, transportStatus }) {
  const mode = state?.mode || "p2p";
  return [
    {
      label: "双向公钥钉死（TLS 1.3 mTLS / QUIC）",
      ok: true,
      detail: "不信任任何第三方 CA；未批准的公钥在加密握手层直接被拒绝，0 字节触达应用层。",
    },
    {
      label: "零虚拟网卡（No TUN）",
      ok: true,
      detail: "绝不把对方接入宿主局域网，不触碰系统路由表，与本机代理工具和平共处。",
    },
    {
      label: "gateway-key 永不出宿主",
      ok: true,
      detail: "接收端不保存宿主任何真实密钥；宿主验明对端公钥后仅在本机回环注入受限 key。",
    },
    {
      label: "127.0.0.1 Fail-Closed 验活",
      ok: Boolean(magpieGateway?.ok),
      detail: magpieGateway?.ok
        ? `每次转发前校验 ${magpieGateway.addr}/v1/magpie/limit，防止手工删 key 后提权，无需开放 0.0.0.0。`
        : "本机 Magpie 网关暂未运行；所有转发均被拦截，绝不放行未验活请求。",
    },
    {
      label: "严格路径白名单 + 控制面隔离",
      ok: true,
      detail: "仅放行推理与 /v1/models；封死 admin/native/memory/mcp，控制面仅监听 127.0.0.1 并校验随机 session token。",
    },
    {
      label: "撤销即时断流 + 严禁偷偷回落",
      ok: !state?.sharingEnabled || !transportStatus?.error,
      detail:
        mode === "p2p"
          ? "撤销成员立刻掐断进行中的流式连接；当前模式 1 使用 Iroh QUIC 打洞与盲中转。"
          : `撤销成员立刻掐断进行中的流式连接；当前模式 (${mode}) 严禁偷偷回落第三方公共节点。`,
    },
  ];
}

/**
 * Starts the Magpie Simple Share local loopback control-plane HTTP server (`127.0.0.1`)
 * along with host gateway, pairing manager, receiver bridge, and transport manager.
 */
export async function startServer({
  port = 3494,
  portRetryMs = 0,
  env = process.env,
  dataDir,
  identity: identityOpt,
  store: storeOpt,
  transportManager: transportManagerOpt,
  hostGateway: hostGatewayOpt,
  pairing: pairingOpt,
  receiverBridge: receiverBridgeOpt,
  discoverGatewayFn = discoverMagpieGateway,
  fetchModelsFn = fetchLocalModels,
  createKeyFn = createMemberGatewayKey,
  updateKeyFn = updateMemberGatewayKey,
  removeKeyFn = removeMemberGatewayKey,
  addProviderFn = addRemoteMagpieProvider,
  removeProviderFn = removeRemoteMagpieProvider,
  installIrohFn = installIroh,
  getIrohStatusFn = getIrohStatus,
  transportOptions = {},
} = {}) {
  const effectiveEnv = dataDir
    ? { ...env, MAGPIE_SIMPLE_SHARE_DATA: dataDir }
    : env;

  const resolvedDataDir = dataDir || pluginDataDir(effectiveEnv);
  const resolvedIrohDir = join(resolvedDataDir, "iroh");
  const resolvedIdentityPath = dataDir ? join(dataDir, "identity.json") : identityPath(effectiveEnv);
  const resolvedStatePath = dataDir ? join(dataDir, "state.json") : statePath(effectiveEnv);

  const identity = identityOpt || (await loadOrCreateIdentity(resolvedIdentityPath));
  const store = storeOpt || createStore(resolvedStatePath);
  await store.load();

  const hostGateway =
    hostGatewayOpt ||
    createHostGatewayHandler({
      store,
      getGatewayUrl: async () => {
        const gw = await discoverGatewayFn({ env: effectiveEnv });
        return gw.ok ? gw.url : "";
      },
      onUsage: async ({ memberId, model, inputTokens, outputTokens }) => {
        await store.recordUsage(memberId, model, {
          turns: 1,
          inputTokens,
          outputTokens,
          costUsd: 0,
        });
      },
    });

  let transportManager = transportManagerOpt || null;
  let pairing = pairingOpt || null;

  if (!transportManager) {
    const { createTransportManager } = await import("./transport-manager.mjs");
    transportManager = createTransportManager({
      identity,
      irohDir: resolvedIrohDir,
      store,
      onApiRequest: (memberId, req, ctx) => hostGateway.handleHttpRequest(memberId, req, ctx),
      onPairSession: (channel, meta) => pairing?.handleIncomingPairChannel(channel, meta),
      ...transportOptions,
    });
  }

  const receiverBridge =
    receiverBridgeOpt ||
    createReceiverBridge({
      store,
      transportManager,
      env: effectiveEnv,
      addProviderFn,
      removeProviderFn,
    });

  if (!pairing) {
    pairing = createPairingManager({
      store,
      identity,
      transportManager,
      receiverBridge,
      env: effectiveEnv,
      createKeyFn,
      removeKeyFn,
      addProviderFn,
    });
  }

  const sessionToken = crypto.randomBytes(32).toString("hex");
  const serverAbort = new AbortController();

  let actualPort = port;
  let allowedHosts = new Set();
  let ownOrigins = new Set();

  function buildUsageByMember(state) {
    const out = {};
    for (const m of state.members || []) {
      if (!m?.id) continue;
      out[m.id] = {
        "7d": store.queryUsage(m.id, "7d").byModel,
        month: store.queryUsage(m.id, "month").byModel,
        all: store.queryUsage(m.id, "all").byModel,
      };
    }
    return out;
  }

  function buildTodayUsageMap(state) {
    const cutoff = startOfLocalDayMs();
    const map = new Map();
    for (const ev of state.usageEvents || []) {
      if (!ev || typeof ev.ts !== "number" || ev.ts < cutoff) continue;
      let cur = map.get(ev.memberId);
      if (!cur) {
        cur = { tokens: 0, cost: 0 };
        map.set(ev.memberId, cur);
      }
      cur.tokens += (Number(ev.inputTokens) || 0) + (Number(ev.outputTokens) || 0);
      cur.cost += Number(ev.costUsd) || 0;
    }
    return map;
  }

  async function buildStateResponse() {
    const rawState = store.get();
    const clean = sanitizeStateSnapshot(rawState);
    const magpieGateway = await discoverGatewayFn({ env: effectiveEnv });
    const availableModels = magpieGateway.ok
      ? await fetchModelsFn(magpieGateway.url, { env: effectiveEnv })
      : [];
    const transportStatus = transportManager.getHostStatus?.() || {
      listening: false,
      activeMode: clean.mode,
      linkLabel: "",
      error: null,
    };
    const irohStatus = getIrohStatusFn(resolvedIrohDir);
    const todayMap = buildTodayUsageMap(rawState);
    const usageByMember = buildUsageByMember(rawState);

    const pending = (clean.pending || []).map((p) => ({
      id: p.id,
      name: p.name,
      clientFp: p.clientFp,
      sas: p.sas,
      mode: p.mode,
      requestedAt: p.requestedAt,
    }));

    const members = (clean.members || []).map((m) => {
      const today = todayMap.get(m.id) || { tokens: 0, cost: 0 };
      return {
        id: m.id,
        name: m.name,
        clientFp: m.clientFp,
        magpieKeyName: m.magpieKeyName,
        status: m.status,
        running: hostGateway.activeCount(m.id),
        joinedAt: m.joinedAt,
        lastUsedAt: m.lastUsedAt,
        period: m.period,
        tokenLimitWan: m.tokenLimitWan,
        costLimit: m.costLimit,
        concurrency: m.concurrency,
        models: Array.isArray(m.models) ? m.models : [],
        usedTodayTokens: today.tokens,
        usedTodayCost: Number(today.cost.toFixed(4)),
      };
    });

    const receiverPending = clean.receiverPending
      ? {
          id: clean.receiverPending.id,
          hostName: clean.receiverPending.hostName,
          hostFp: clean.receiverPending.hostFp,
          mode: clean.receiverPending.mode,
          deviceName: clean.receiverPending.deviceName,
          sas: clean.receiverPending.sas,
        }
      : null;

    const received = (clean.received || []).map((r) => ({
      id: r.id,
      hostName: r.hostName,
      hostFp: r.hostFp,
      bridgePort: r.bridgePort,
      providerId: r.providerId,
      mode: r.mode,
      linkStatus: r.linkStatus,
      status: r.status,
      period: r.period,
      usedTokens: Number(r.usedTokens) || 0,
      tokenLimitWan: Number(r.tokenLimitWan) || 0,
      usedCost: Number(r.usedCost) || 0,
      costLimit: Number(r.costLimit) || 0,
      limitVisible: r.limitVisible !== false,
      models: Array.isArray(r.models) ? r.models : [],
    }));

    return {
      version: packageVersion,
      identity: {
        fingerprint: identity.fingerprint,
        pubKeyHex: identity.pubKeyHex,
        hostName: clean.hostName,
        irohEndpointId: identity.irohEndpointId,
      },
      sharingEnabled: clean.sharingEnabled,
      tosAcknowledged: clean.tosAcknowledged,
      mode: clean.mode,
      network: clean.network,
      transportStatus,
      irohStatus,
      visibility: clean.visibility,
      pending,
      members,
      usageByMember,
      receiverPending,
      received,
      availableModels,
      magpieGateway,
      securityChecks: computeSecurityChecks({
        state: clean,
        magpieGateway,
        transportStatus,
      }),
    };
  }

  const server = http.createServer(async (req, res) => {
    const host = String(req.headers.host || "").toLowerCase();
    if (!allowedHosts.has(host)) {
      res.writeHead(403, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
      res.end("Forbidden");
      return;
    }

    let url;
    try {
      url = new URL(req.url || "/", `http://${host}`);
    } catch {
      res.writeHead(400, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
      res.end("Bad Request");
      return;
    }

    const origin = req.headers.origin;
    const path = url.pathname;

    if (path.startsWith("/api/")) {
      if (!originAllowed(origin, ownOrigins)) {
        sendJson(res, 403, {
          error: "forbidden_origin",
          code: "forbidden_origin",
          message: "This origin is not allowed to access Simple Share.",
        });
        return;
      }
      applyCors(res, origin);

      if (req.method === "OPTIONS") {
        res.writeHead(204, {
          "access-control-allow-methods": "GET, POST, PATCH, DELETE",
          "access-control-allow-headers": `${TOKEN_HEADER}, content-type`,
          "access-control-max-age": "600",
        });
        res.end();
        return;
      }

      if (path === "/api/health") {
        if (req.method !== "GET") return methodNotAllowed(res, "GET");
        sendJson(res, 200, { ok: true, version: packageVersion });
        return;
      }

      if (!timingSafeEqualStr(String(req.headers[TOKEN_HEADER] || ""), sessionToken)) {
        sendJson(res, 401, {
          error: "unauthorized",
          code: "unauthorized",
          message: "Missing or invalid control-plane session token.",
          reload: true,
        });
        return;
      }
    }

    try {
      if (path === "/api/state") {
        if (req.method !== "GET") return methodNotAllowed(res, "GET");
        sendJson(res, 200, await buildStateResponse());
        return;
      }

      if (path === "/api/host/toggle") {
        if (req.method !== "POST") return methodNotAllowed(res, "POST");
        const body = await readJson(req);
        if (typeof body.enabled !== "boolean") {
          throw new HttpError(400, "invalid_body", "Boolean field 'enabled' is required.");
        }
        const current = store.get();
        if (body.enabled && !current.tosAcknowledged && body.tosAcknowledged !== true) {
          throw new HttpError(400, "tos_required", "请先阅读并确认首次开启分享声明。");
        }
        const updated = await store.update((draft) => {
          draft.sharingEnabled = body.enabled;
          if (body.tosAcknowledged === true) draft.tosAcknowledged = true;
        });
        if (!body.enabled) {
          for (const m of updated.members || []) {
            if (m?.id) hostGateway.abortMemberStreams(m.id);
          }
        }
        await transportManager.reconfigure();
        sendJson(res, 200, {
          ok: true,
          sharingEnabled: updated.sharingEnabled,
          tosAcknowledged: updated.tosAcknowledged,
          transportStatus: transportManager.getHostStatus(),
        });
        return;
      }

      if (path === "/api/host/name") {
        if (req.method !== "POST") return methodNotAllowed(res, "POST");
        const body = await readJson(req);
        const hostName = typeof body.hostName === "string" ? body.hostName.replace(/[\r\n\0]/g, " ").trim() : "";
        if (!hostName || hostName.length > 64) {
          throw new HttpError(400, "invalid_host_name", "hostName must be 1..64 characters.");
        }
        await store.update((draft) => {
          draft.hostName = hostName;
        });
        sendJson(res, 200, { ok: true, hostName });
        return;
      }

      if (path === "/api/host/visibility") {
        if (req.method !== "POST") return methodNotAllowed(res, "POST");
        const body = await readJson(req);
        const updated = await store.update((draft) => {
          if (typeof body.limit === "boolean") draft.visibility.limit = body.limit;
          if (typeof body.quotas === "boolean") draft.visibility.quotas = body.quotas;
        });
        if (typeof body.quotas === "boolean") {
          for (const m of updated.members || []) {
            if (m?.magpieKeyId) {
              await updateKeyFn({ keyId: m.magpieKeyId, quotas: body.quotas, env: effectiveEnv }).catch(() => {});
            }
          }
        }
        sendJson(res, 200, { ok: true, visibility: updated.visibility });
        return;
      }

      if (path === "/api/host/invites") {
        if (req.method !== "POST") return methodNotAllowed(res, "POST");
        if (!store.get().sharingEnabled) {
          throw new HttpError(409, "share_offline", "请先开启本机对外分享后再生成邀请码。");
        }
        sendJson(res, 200, await pairing.createInvite());
        return;
      }

      const inviteMatch = /^\/api\/host\/invites\/([^/]+)$/.exec(path);
      if (inviteMatch) {
        if (req.method !== "DELETE") return methodNotAllowed(res, "DELETE");
        const id = decodeSegment(inviteMatch[1]);
        sendJson(res, 200, await pairing.revokeInvite(id));
        return;
      }

      const pendingActionMatch = /^\/api\/host\/pending\/([^/]+)\/(approve|reject)$/.exec(path);
      if (pendingActionMatch) {
        if (req.method !== "POST") return methodNotAllowed(res, "POST");
        const id = decodeSegment(pendingActionMatch[1]);
        const action = pendingActionMatch[2];
        if (action === "approve") {
          const body = await readJson(req);
          const member = await pairing.approvePending(id, body);
          sendJson(res, 200, { ok: true, member });
        } else {
          sendJson(res, 200, await pairing.rejectPending(id));
        }
        return;
      }

      const memberPauseMatch = /^\/api\/host\/members\/([^/]+)\/pause$/.exec(path);
      if (memberPauseMatch) {
        if (req.method !== "POST") return methodNotAllowed(res, "POST");
        const id = decodeSegment(memberPauseMatch[1]);
        const body = await readJson(req);
        if (typeof body.paused !== "boolean") {
          throw new HttpError(400, "invalid_body", "Boolean field 'paused' is required.");
        }
        let found = false;
        await store.update((draft) => {
          const m = (draft.members || []).find((x) => x && x.id === id);
          if (m) {
            found = true;
            m.status = body.paused ? "paused" : "active";
          }
        });
        if (!found) throw new HttpError(404, "member_not_found", "Member not found.");
        await transportManager.reconfigure();
        sendJson(res, 200, { ok: true, id, status: body.paused ? "paused" : "active" });
        return;
      }

      const memberMatch = /^\/api\/host\/members\/([^/]+)$/.exec(path);
      if (memberMatch) {
        const id = decodeSegment(memberMatch[1]);
        if (req.method === "PATCH") {
          const body = await readJson(req);
          const curMember = (store.get().members || []).find((x) => x && x.id === id);
          if (!curMember) throw new HttpError(404, "member_not_found", "Member not found.");

          const hasKeyUpdate =
            body.models !== undefined ||
            body.period !== undefined ||
            body.tokenLimitWan !== undefined ||
            body.costLimit !== undefined ||
            body.concurrency !== undefined;

          if (hasKeyUpdate && curMember.magpieKeyId) {
            await updateKeyFn({
              keyId: curMember.magpieKeyId,
              models: body.models,
              period: body.period ?? curMember.period,
              tokenLimitWan: body.tokenLimitWan ?? curMember.tokenLimitWan,
              costLimit: body.costLimit ?? curMember.costLimit,
              concurrency: body.concurrency ?? curMember.concurrency,
              env: effectiveEnv,
            });
          }

          let updatedMember = null;
          await store.update((draft) => {
            const m = (draft.members || []).find((x) => x && x.id === id);
            if (!m) return;
            if (typeof body.name === "string" && body.name.trim()) {
              m.name = body.name.replace(/[\r\n\0]/g, " ").trim().slice(0, 64);
            }
            if (Array.isArray(body.models) && body.models.length > 0) m.models = body.models;
            if (typeof body.period === "string" && body.period) m.period = body.period;
            if (body.tokenLimitWan !== undefined) m.tokenLimitWan = Number(body.tokenLimitWan) || 0;
            if (body.costLimit !== undefined) m.costLimit = Number(body.costLimit) || 0;
            if (body.concurrency !== undefined) m.concurrency = Number(body.concurrency) || 2;
            updatedMember = m;
          });
          sendJson(res, 200, { ok: true, member: sanitizeStateSnapshot(updatedMember) });
          return;
        }
        if (req.method === "DELETE") {
          let removed = null;
          await store.update((draft) => {
            const idx = (draft.members || []).findIndex((x) => x && x.id === id);
            if (idx >= 0) {
              [removed] = draft.members.splice(idx, 1);
            }
          });
          if (!removed) throw new HttpError(404, "member_not_found", "Member not found.");
          hostGateway.abortMemberStreams(id);
          await transportManager.reconfigure();
          if (removed.magpieKeyId) {
            await removeKeyFn({ keyId: removed.magpieKeyId, env: effectiveEnv }).catch(() => {});
          }
          sendJson(res, 200, { ok: true, id });
          return;
        }
        return methodNotAllowed(res, "PATCH, DELETE");
      }

      if (path === "/api/host/usage") {
        if (req.method !== "GET") return methodNotAllowed(res, "GET");
        const range = url.searchParams.get("range") || "7d";
        if (!VALID_RANGES.has(range)) {
          throw new HttpError(400, "invalid_range", "range must be 7d, month, or all.");
        }
        const state = store.get();
        sendJson(res, 200, { range, usageByMember: buildUsageByMember(state) });
        return;
      }

      if (path === "/api/receiver/parse") {
        if (req.method !== "POST") return methodNotAllowed(res, "POST");
        const body = await readJson(req);
        sendJson(res, 200, pairing.parseInviteCode(body.code));
        return;
      }

      if (path === "/api/receiver/apply") {
        if (req.method !== "POST") return methodNotAllowed(res, "POST");
        const body = await readJson(req);
        sendJson(res, 200, await pairing.applyToInvite(body.code, body.deviceName));
        return;
      }

      const receiverPendingMatch = /^\/api\/receiver\/pending\/([^/]+)$/.exec(path);
      if (receiverPendingMatch) {
        if (req.method !== "DELETE") return methodNotAllowed(res, "DELETE");
        const id = decodeSegment(receiverPendingMatch[1]);
        sendJson(res, 200, await pairing.withdrawPending(id));
        return;
      }

      const shareTestMatch = /^\/api\/receiver\/shares\/([^/]+)\/test$/.exec(path);
      if (shareTestMatch) {
        if (req.method !== "POST") return methodNotAllowed(res, "POST");
        const id = decodeSegment(shareTestMatch[1]);
        const body = await readJson(req, { optional: true });
        sendJson(res, 200, await receiverBridge.testShareConnection(id, { model: body.model }));
        return;
      }

      const shareMatch = /^\/api\/receiver\/shares\/([^/]+)$/.exec(path);
      if (shareMatch) {
        if (req.method !== "DELETE") return methodNotAllowed(res, "DELETE");
        const id = decodeSegment(shareMatch[1]);
        sendJson(res, 200, await receiverBridge.leaveShare(id));
        return;
      }

      if (path === "/api/network/mode") {
        if (req.method !== "POST") return methodNotAllowed(res, "POST");
        const body = await readJson(req);
        if (!VALID_MODES.has(body.mode)) {
          throw new HttpError(400, "invalid_mode", "mode must be p2p, self-relay, or direct.");
        }
        const net = body.network && typeof body.network === "object" && !Array.isArray(body.network)
          ? body.network
          : {};
        if (net.directPort !== undefined) {
          const dp = Number(net.directPort);
          if (!Number.isInteger(dp) || dp < 1 || dp > 65535) {
            throw new HttpError(400, "invalid_port", "directPort must be 1..65535.");
          }
        }
        const updated = await store.update((draft) => {
          draft.mode = body.mode;
          if (typeof net.irohRelayUrl === "string") draft.network.irohRelayUrl = net.irohRelayUrl.trim();
          if (typeof net.relayAddr === "string") draft.network.relayAddr = net.relayAddr.trim();
          if (typeof net.relayToken === "string") draft.network.relayToken = net.relayToken.trim();
          if (typeof net.directHost === "string") draft.network.directHost = net.directHost.trim();
          if (net.directPort !== undefined) draft.network.directPort = Number(net.directPort);
        });
        await transportManager.reconfigure();
        sendJson(res, 200, {
          ok: true,
          mode: updated.mode,
          network: updated.network,
          transportStatus: transportManager.getHostStatus(),
        });
        return;
      }

      if (path === "/api/network/iroh/install") {
        if (req.method !== "POST") return methodNotAllowed(res, "POST");
        const status = await installIrohFn(resolvedIrohDir);
        sendJson(res, 200, { ok: Boolean(status?.integrityOk), irohStatus: status });
        return;
      }

      if (path === "/api/network/test-relay") {
        if (req.method !== "POST") return methodNotAllowed(res, "POST");
        const body = await readJson(req);
        const relayAddr = typeof body.relayAddr === "string" ? body.relayAddr.trim() : "";
        if (!relayAddr) throw new HttpError(400, "invalid_relay", "relayAddr is required.");
        sendJson(
          res,
          200,
          await transportManager.testRelay({
            relayAddr,
            relayToken: typeof body.relayToken === "string" ? body.relayToken.trim() : "",
          }),
        );
        return;
      }

      if (path === "/api/network/test-direct") {
        if (req.method !== "POST") return methodNotAllowed(res, "POST");
        const body = await readJson(req, { optional: true });
        sendJson(
          res,
          200,
          await transportManager.testDirect({
            directHost: typeof body.directHost === "string" ? body.directHost.trim() : "",
            directPort: body.directPort !== undefined ? Number(body.directPort) : undefined,
          }),
        );
        return;
      }

      if (path.startsWith("/api/")) {
        throw new HttpError(404, "not_found", "API route not found.");
      }

      if (req.method !== "GET" && req.method !== "HEAD") {
        return methodNotAllowed(res, "GET, HEAD");
      }

      if (path === "/" || path === "/index.html") {
        const fetchDest = req.headers["sec-fetch-dest"];
        if (fetchDest && !["iframe", "document", "empty"].includes(fetchDest)) {
          res.writeHead(200, {
            "content-type": MIME[".html"],
            "cache-control": "no-store",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
          });
          res.end(
            req.method === "HEAD"
              ? undefined
              : "<!doctype html><title>Simple Share</title><p>This page only works inside magpie.</p>",
          );
          return;
        }
        const html = (await readFile(join(UI_ROOT, "index.html"), "utf8")).replaceAll(
          TOKEN_PLACEHOLDER,
          sessionToken,
        );
        res.writeHead(200, {
          "content-type": MIME[".html"],
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
          "referrer-policy": "no-referrer",
          "content-security-policy":
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; " +
            "connect-src 'self' http: https:; font-src 'self'; object-src 'none'; base-uri 'none'; " +
            "form-action 'none'",
        });
        res.end(req.method === "HEAD" ? undefined : html);
        return;
      }

      let relative;
      try {
        relative = decodeURIComponent(path.slice(1));
      } catch {
        throw new HttpError(400, "invalid_path", "Invalid percent-encoding.");
      }
      if (!relative || relative.includes("\0") || !inside(UI_ROOT, relative)) {
        res.writeHead(404, { "cache-control": "no-store" });
        res.end();
        return;
      }
      try {
        const type = extname(relative).toLowerCase();
        if (type === ".html") {
          res.writeHead(404, { "cache-control": "no-store" });
          res.end();
          return;
        }
        const body = await readFile(join(UI_ROOT, relative));
        applyCors(res, origin);
        res.writeHead(200, {
          "content-type": MIME[type] || "application/octet-stream",
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
        });
        res.end(req.method === "HEAD" ? undefined : body);
      } catch {
        res.writeHead(404, { "cache-control": "no-store" });
        res.end();
      }
    } catch (err) {
      sendError(res, err);
    }
  });

  server.on("clientError", (_err, socket) => {
    socket.destroy();
  });

  actualPort = await listenWithPortRetry(server, port, {
    windowMs: portRetryMs,
    abortSignal: serverAbort.signal,
  });

  allowedHosts = new Set([
    `127.0.0.1:${actualPort}`,
    `localhost:${actualPort}`,
    `[::1]:${actualPort}`,
  ]);
  ownOrigins = new Set([
    `http://127.0.0.1:${actualPort}`,
    `http://localhost:${actualPort}`,
    `http://[::1]:${actualPort}`,
  ]);

  await receiverBridge.syncAll();
  await transportManager.start();
  await pairing.restoreReceiverWatcher();

  return {
    port: actualPort,
    url: `http://127.0.0.1:${actualPort}`,
    token: sessionToken,
    dataDir: resolvedDataDir,
    identity,
    store,
    hostGateway,
    pairing,
    receiverBridge,
    transportManager,
    close: async () => {
      serverAbort.abort();
      await pairing.close().catch(() => {});
      await receiverBridge.stopAll().catch(() => {});
      await transportManager.stop().catch(() => {});
      await new Promise((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections?.();
      });
    },
  };
}
