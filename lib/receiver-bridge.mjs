import http from "node:http";
import { Readable } from "node:stream";
import { timingSafeEqualStr } from "./crypto.mjs";
import { addRemoteMagpieProvider, removeRemoteMagpieProvider } from "./magpie-cli.mjs";
import { FRAME, sendHttpRequestOverChannel } from "./wire.mjs";

const STRIPPED_BRIDGE_REQ_HEADERS = new Set([
  "host",
  "authorization",
  "x-api-key",
  "x-goog-api-key",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
  "proxy-authorization",
]);

const STRIPPED_BRIDGE_RES_HEADERS = new Set([
  "transfer-encoding",
  "connection",
  "keep-alive",
  "set-cookie",
]);

export class BridgeError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "BridgeError";
    this.status = status;
    this.code = code;
  }
}

function isLoopbackHostHeader(hostHeader, port) {
  if (typeof hostHeader !== "string" || !hostHeader) return false;
  const h = hostHeader.trim().toLowerCase();
  return (
    h === `127.0.0.1:${port}` ||
    h === `localhost:${port}` ||
    h === `[::1]:${port}` ||
    h === "127.0.0.1" ||
    h === "localhost" ||
    h === "[::1]"
  );
}

function extractBearerOrApiKey(headers) {
  const auth = typeof headers?.authorization === "string" ? headers.authorization : "";
  if (/^bearer\s+/i.test(auth)) {
    return auth.replace(/^bearer\s+/i, "").trim();
  }
  const apiKey = typeof headers?.["x-api-key"] === "string" ? headers["x-api-key"].trim() : "";
  if (apiKey) return apiKey;
  const googKey = typeof headers?.["x-goog-api-key"] === "string" ? headers["x-goog-api-key"].trim() : "";
  return googKey;
}

function sanitizeBridgeReqHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    const key = k.toLowerCase();
    if (STRIPPED_BRIDGE_REQ_HEADERS.has(key) || v === undefined) continue;
    out[key] = Array.isArray(v) ? v.join(", ") : String(v);
  }
  return out;
}

function sanitizeBridgeResHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    const key = k.toLowerCase();
    if (STRIPPED_BRIDGE_RES_HEADERS.has(key) || v === undefined) continue;
    out[key] = Array.isArray(v) ? v.join(", ") : String(v);
  }
  return out;
}

function writeJson(res, status, payload) {
  if (res.headersSent) return;
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

function listenServer(server, port) {
  return new Promise((resolve, reject) => {
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
}

function parsePreviewAndUsageFromText(text) {
  let preview = "";
  let inputTokens = 0;
  let outputTokens = 0;
  let sawUsage = false;

  const trimmed = String(text || "").trim();
  if (!trimmed) return { preview: "", usage: null };

  // Try single JSON payload first
  if (trimmed.startsWith("{")) {
    try {
      const obj = JSON.parse(trimmed);
      const content = obj?.choices?.[0]?.message?.content;
      if (typeof content === "string") preview = content.slice(0, 120);
      const u = obj?.usage;
      if (u && typeof u === "object") {
        inputTokens = Number(u.input_tokens ?? u.prompt_tokens ?? 0) || 0;
        outputTokens = Number(u.output_tokens ?? u.completion_tokens ?? 0) || 0;
        sawUsage = true;
      }
      return {
        preview,
        usage: sawUsage ? { inputTokens, outputTokens, totalTokens: inputTokens + outputTokens } : null,
      };
    } catch {
      // Fall through to SSE lines
    }
  }

  for (const rawLine of trimmed.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line.startsWith("data:")) continue;
    const payload = line.slice(5).trim();
    if (!payload || payload === "[DONE]" || !payload.startsWith("{")) continue;
    try {
      const obj = JSON.parse(payload);
      const deltaText =
        obj?.choices?.[0]?.delta?.content ??
        obj?.choices?.[0]?.message?.content ??
        obj?.delta?.text ??
        "";
      if (typeof deltaText === "string" && preview.length < 120) {
        preview += deltaText.slice(0, 120 - preview.length);
      }
      const u = obj?.usage || obj?.message?.usage || obj?.response?.usage;
      if (u && typeof u === "object") {
        const i = Number(u.input_tokens ?? u.prompt_tokens);
        const o = Number(u.output_tokens ?? u.completion_tokens);
        if (Number.isFinite(i)) {
          inputTokens = Math.max(inputTokens, i);
          sawUsage = true;
        }
        if (Number.isFinite(o)) {
          outputTokens = Math.max(outputTokens, o);
          sawUsage = true;
        }
      }
    } catch {
      // Ignore malformed SSE chunk
    }
  }

  return {
    preview: preview.trim(),
    usage: sawUsage ? { inputTokens, outputTokens, totalTokens: inputTokens + outputTokens } : null,
  };
}

function formatLinkLabel(linkInfo, fallbackMode) {
  if (!linkInfo) return fallbackMode || "已连接";
  const base = linkInfo.linkType || fallbackMode || "已连接";
  return typeof linkInfo.rttMs === "number" && Number.isFinite(linkInfo.rttMs)
    ? `${base} · ${Math.round(linkInfo.rttMs)}ms`
    : base;
}

/**
 * Manages per-share local loopback HTTP bridges (`127.0.0.1:<port>`) for `remote-magpie`.
 */
export function createReceiverBridge({
  store,
  transportManager,
  env = process.env,
  addProviderFn = addRemoteMagpieProvider,
  removeProviderFn = removeRemoteMagpieProvider,
} = {}) {
  if (!store) throw new Error("createReceiverBridge requires store");

  /** @type {Map<string, { server: http.Server, port: number, url: string }>} */
  const bridges = new Map();

  async function patchShareInStore(shareId, patchFn) {
    try {
      await store.update((draft) => {
        const s = (draft.received || []).find((r) => r && r.id === shareId);
        if (s) patchFn(s);
      });
    } catch {
      // Non-fatal metadata sync failure.
    }
  }

  function applyErrorStatusSync(shareId, code) {
    if (code === "share_paused") {
      return patchShareInStore(shareId, (s) => {
        s.status = "paused";
      });
    }
    if (code === "share_revoked" || code === "key_revoked_or_invalid") {
      return patchShareInStore(shareId, (s) => {
        s.status = "revoked";
      });
    }
    if (code === "share_offline") {
      return patchShareInStore(shareId, (s) => {
        s.status = "offline";
        s.linkStatus = "对方已关闭分享";
      });
    }
    return Promise.resolve();
  }

  function applyLimitJsonSync(shareId, data) {
    if (!data || typeof data !== "object") return Promise.resolve();
    return patchShareInStore(shareId, (s) => {
      if (typeof data.period === "string" && data.period) s.period = data.period;
      if (typeof data.usedTokens === "number") s.usedTokens = data.usedTokens;
      if (typeof data.tokensUsed === "number") s.usedTokens = data.tokensUsed;
      if (typeof data.used_tokens === "number") s.usedTokens = data.used_tokens;
      if (typeof data.tokenLimit === "number" && data.tokenLimit > 0) {
        s.tokenLimitWan = Number((data.tokenLimit / 10000).toFixed(2));
      }
      if (typeof data.usedCost === "number") s.usedCost = data.usedCost;
      if (typeof data.costUsed === "number") s.usedCost = data.costUsed;
      if (typeof data.costLimit === "number" && data.costLimit > 0) s.costLimit = data.costLimit;
      if (data.limited === false && data.key === "") {
        s.status = "revoked";
      }
    });
  }

  async function startBridge(shareOrId) {
    const shareObj =
      typeof shareOrId === "string"
        ? (store.get().received || []).find((r) => r && r.id === shareOrId)
        : shareOrId;
    if (!shareObj || !shareObj.id) {
      throw new BridgeError(404, "share_not_found", "Share record not found");
    }

    const existing = bridges.get(shareObj.id);
    if (existing) {
      return { port: existing.port, url: existing.url };
    }

    let boundPort = 0;

    const server = http.createServer(async (req, res) => {
      if (!isLoopbackHostHeader(req.headers.host, boundPort)) {
        writeJson(res, 403, { error: "forbidden_host", message: "Loopback host required" });
        return;
      }

      const currentShare =
        (store.get().received || []).find((r) => r && r.id === shareObj.id) || shareObj;

      const gotToken = extractBearerOrApiKey(req.headers);
      if (!gotToken || !currentShare.bridgeToken || !timingSafeEqualStr(gotToken, currentShare.bridgeToken)) {
        writeJson(res, 401, { error: "unauthorized", message: "Invalid bridge token" });
        return;
      }

      if (!transportManager?.dialApi) {
        writeJson(res, 503, { error: "transport_unavailable", message: "Transport manager unavailable" });
        return;
      }

      const ac = new AbortController();
      const onResClose = () => {
        if (!res.writableEnded) {
          ac.abort(new DOMException("Client disconnected", "AbortError"));
        }
      };
      res.on("close", onResClose);

      let conn = null;
      try {
        conn = await transportManager.dialApi(currentShare);
        if (ac.signal.aborted) {
          await conn?.close?.().catch(() => {});
          return;
        }

        const linkLabel = formatLinkLabel(conn.linkInfo, currentShare.mode);
        const method = String(req.method || "GET").toUpperCase();
        const rawPath = req.url || "/";
        const hasBody = method !== "GET" && method !== "HEAD";
        const bodyStream = hasBody ? Readable.toWeb(req) : null;

        const upstream = await sendHttpRequestOverChannel(conn.channel, {
          method,
          path: rawPath,
          headers: sanitizeBridgeReqHeaders(req.headers),
          bodyStream,
          signal: ac.signal,
        });

        const outHeaders = sanitizeBridgeResHeaders(upstream.headers);
        res.writeHead(upstream.status, outHeaders);

        const pathnameOnly = rawPath.split("?")[0];
        const shouldCaptureSmallJson =
          upstream.status === 403 ||
          upstream.status === 503 ||
          (upstream.status === 200 &&
            (pathnameOnly === "/v1/models" ||
              pathnameOnly === "/models" ||
              pathnameOnly === "/v1/magpie/limit"));

        const capturedChunks = [];
        let capturedBytes = 0;

        if (upstream.body) {
          const reader = upstream.body.getReader();
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value && value.byteLength > 0) {
              res.write(value);
              if (shouldCaptureSmallJson && capturedBytes + value.byteLength <= 128 * 1024) {
                capturedChunks.push(value);
                capturedBytes += value.byteLength;
              }
            }
          }
        }
        res.end();

        if (shouldCaptureSmallJson && capturedBytes > 0) {
          try {
            const parsed = JSON.parse(Buffer.concat(capturedChunks).toString("utf8"));
            if (upstream.status === 200) {
              if (pathnameOnly === "/v1/models" || pathnameOnly === "/models") {
                const list = Array.isArray(parsed?.data) ? parsed.data.map((m) => m?.id).filter(Boolean) : [];
                await patchShareInStore(currentShare.id, (s) => {
                  s.status = "active";
                  s.linkStatus = linkLabel;
                  if (list.length > 0) s.models = list;
                });
              } else if (pathnameOnly === "/v1/magpie/limit") {
                await patchShareInStore(currentShare.id, (s) => {
                  s.status = "active";
                  s.linkStatus = linkLabel;
                });
                await applyLimitJsonSync(currentShare.id, parsed);
              }
            } else {
              await applyErrorStatusSync(currentShare.id, parsed?.code);
            }
          } catch {
            // Ignore non-JSON metadata tap
          }
        } else if (upstream.status >= 200 && upstream.status < 300) {
          await patchShareInStore(currentShare.id, (s) => {
            s.status = "active";
            s.linkStatus = linkLabel;
          });
        }
      } catch (err) {
        if (!ac.signal.aborted) {
          await patchShareInStore(currentShare.id, (s) => {
            s.status = "offline";
            s.linkStatus = err?.message || "连接中断";
          });
          if (res.headersSent) {
            res.destroy(err);
          } else {
            writeJson(res, 502, {
              error: "bridge_upstream_failed",
              message: err?.message || "Failed to reach host",
            });
          }
        } else if (res.headersSent && !res.writableEnded) {
          res.destroy();
        }
      } finally {
        res.removeListener("close", onResClose);
        await conn?.close?.().catch(() => {});
      }
    });

    server.on("clientError", (_err, socket) => {
      socket.destroy();
    });

    const preferredPort =
      Number.isInteger(Number(shareObj.bridgePort)) && Number(shareObj.bridgePort) > 0
        ? Number(shareObj.bridgePort)
        : 0;

    try {
      boundPort = await listenServer(server, preferredPort);
    } catch (err) {
      if (preferredPort > 0 && err?.code === "EADDRINUSE") {
        boundPort = await listenServer(server, 0);
      } else {
        throw err;
      }
    }

    const url = `http://127.0.0.1:${boundPort}`;
    bridges.set(shareObj.id, { server, port: boundPort, url });

    // If port changed from persisted value, update store and Magpie's remote-magpie provider URL.
    if (boundPort !== shareObj.bridgePort) {
      const inStore = (store.get().received || []).some((r) => r && r.id === shareObj.id);
      if (inStore) {
        await patchShareInStore(shareObj.id, (s) => {
          s.bridgePort = boundPort;
        });
        if (shareObj.bridgePort > 0 && shareObj.providerId) {
          await addProviderFn({
            id: shareObj.providerId,
            bridgeUrl: url,
            bridgeToken: shareObj.bridgeToken,
            updateIfExists: true,
            env,
          }).catch(() => {});
        }
      }
    }

    return { port: boundPort, url };
  }

  async function stopBridge(shareId) {
    const entry = bridges.get(shareId);
    if (!entry) return;
    bridges.delete(shareId);
    await new Promise((resolve) => {
      entry.server.close(() => resolve());
      entry.server.closeAllConnections?.();
    });
  }

  async function stopAll() {
    const ids = [...bridges.keys()];
    await Promise.all(ids.map((id) => stopBridge(id)));
  }

  async function syncAll() {
    const shares = store.get().received || [];
    for (const share of shares) {
      if (!share || !share.id) continue;
      try {
        await startBridge(share);
      } catch {
        // Keep other bridges starting cleanly.
      }
    }
  }

  async function testShareConnection(shareId, { model } = {}) {
    const share = (store.get().received || []).find((r) => r && r.id === shareId);
    if (!share) {
      throw new BridgeError(404, "share_not_found", "Share not found");
    }
    if (!transportManager?.dialApi) {
      throw new BridgeError(503, "transport_unavailable", "Transport manager unavailable");
    }

    const steps = [];
    const t0 = Date.now();
    let conn = null;
    try {
      conn = await transportManager.dialApi(share);
      const rttMs = Math.max(1, Math.round(conn.linkInfo?.rttMs ?? Date.now() - t0));
      const linkType = conn.linkInfo?.linkType || share.mode || "p2p";
      steps.push({
        ok: true,
        label: "端到端加密握手",
        detail: `${linkType} (${rttMs}ms)`,
      });

      // 1. Probe /v1/models
      const modelsRes = await sendHttpRequestOverChannel(conn.channel, {
        method: "GET",
        path: "/v1/models",
        headers: {},
      });
      const modelsText = modelsRes.body ? await new Response(modelsRes.body).text() : "";
      let modelsJson = null;
      try {
        modelsJson = JSON.parse(modelsText);
      } catch {}

      if (modelsRes.status === 403 || modelsRes.status === 503) {
        const code = modelsJson?.code || "share_denied";
        await applyErrorStatusSync(share.id, code);
        throw new BridgeError(
          modelsRes.status,
          code,
          code === "share_paused"
            ? "分享者已暂停你的访问"
            : code === "share_offline"
              ? "分享者当前已关闭对外分享"
              : "分享已被撤销或密钥已失效",
        );
      }

      if (modelsRes.status !== 200) {
        throw new BridgeError(502, "models_probe_failed", `获取模型列表失败（HTTP ${modelsRes.status}）`);
      }

      const modelList = Array.isArray(modelsJson?.data)
        ? modelsJson.data.map((m) => m?.id).filter(Boolean)
        : [];
      if (modelList.length > 0) {
        await patchShareInStore(share.id, (s) => {
          s.models = modelList;
        });
      }
      steps.push({
        ok: true,
        label: "同步可用模型列表",
        detail: `${modelList.length} 个模型`,
      });

      // 2. Probe /v1/magpie/limit
      const limitRes = await sendHttpRequestOverChannel(conn.channel, {
        method: "GET",
        path: "/v1/magpie/limit",
        headers: {},
      });
      const limitText = limitRes.body ? await new Response(limitRes.body).text() : "";
      let limitJson = null;
      try {
        limitJson = JSON.parse(limitText);
      } catch {}
      if (limitRes.status === 200 && limitJson) {
        await applyLimitJsonSync(share.id, limitJson);
      }
      steps.push({
        ok: limitRes.status === 200,
        label: "校验宿主 Fail-Closed 限额",
        detail: limitRes.status === 200 ? `key ${limitJson?.key || "valid"}` : `HTTP ${limitRes.status}`,
      });

      // 3. Minimal streaming inference test if a target model is selected or available
      const targetModel = model || modelList[0] || share.models?.[0] || "";
      let preview = "";
      let usage = null;
      if (targetModel) {
        const chatRes = await sendHttpRequestOverChannel(conn.channel, {
          method: "POST",
          path: "/v1/chat/completions",
          headers: { "content-type": "application/json" },
          bodyStream: JSON.stringify({
            model: targetModel,
            max_tokens: 16,
            stream: true,
            messages: [{ role: "user", content: "Reply with OK" }],
          }),
        });
        const chatText = chatRes.body ? await new Response(chatRes.body).text() : "";
        if (chatRes.status >= 200 && chatRes.status < 300) {
          const parsed = parsePreviewAndUsageFromText(chatText);
          preview = parsed.preview || "流式响应正常";
          usage = parsed.usage;
          steps.push({
            ok: true,
            label: "流式推理端到端测试",
            detail: `${targetModel} 响应正常`,
          });
        } else {
          steps.push({
            ok: false,
            label: "流式推理端到端测试",
            detail: `HTTP ${chatRes.status}`,
          });
        }
      }

      const linkLabel = formatLinkLabel({ linkType, rttMs }, share.mode);
      await patchShareInStore(share.id, (s) => {
        s.status = "active";
        s.linkStatus = linkLabel;
      });

      return {
        ok: true,
        steps,
        rttMs,
        linkType,
        model: targetModel,
        preview,
        usage,
      };
    } catch (err) {
      if (err instanceof BridgeError) throw err;
      await patchShareInStore(share.id, (s) => {
        s.status = "offline";
        s.linkStatus = err?.message || "连接失败";
      });
      throw new BridgeError(502, "test_failed", err?.message || "连接测试失败");
    } finally {
      await conn?.close?.().catch(() => {});
    }
  }

  async function leaveShare(shareId) {
    const share = (store.get().received || []).find((r) => r && r.id === shareId);
    if (!share) {
      throw new BridgeError(404, "share_not_found", "Share not found");
    }
    await stopBridge(shareId);
    if (share.providerId) {
      await removeProviderFn({ id: share.providerId, env }).catch(() => {});
    }
    await store.update((draft) => {
      draft.received = (draft.received || []).filter((r) => r && r.id !== shareId);
    });
    return { ok: true, id: shareId };
  }

  return {
    startBridge,
    stopBridge,
    stopAll,
    syncAll,
    testShareConnection,
    leaveShare,
    getPort: (shareId) => bridges.get(shareId)?.port ?? null,
  };
}
