import { isLoopbackUrl } from "./magpie-cli.mjs";

const ALLOWED_GET_PATHS = new Set([
  "/v1/models",
  "/models",
  "/v1/magpie/limit",
]);

const ALLOWED_POST_EXACT_PATHS = new Set([
  "/v1/chat/completions",
  "/v1/responses",
  "/v1/messages",
  "/v1/messages/count_tokens",
]);

const GEMINI_PATH_RE = /^\/v1beta\/models\/([^/?#\\]+):(generateContent|streamGenerateContent)$/;
const GEMINI_MODEL_RE = /^[A-Za-z0-9._:@+-]{1,160}$/;

const STRIPPED_REQUEST_HEADERS = new Set([
  "authorization",
  "x-api-key",
  "x-goog-api-key",
  "x-forwarded-for",
  "forwarded",
  "x-real-ip",
  "host",
  "cookie",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
  "proxy-authorization",
  "content-length",
]);

const STRIPPED_RESPONSE_HEADERS = new Set([
  "transfer-encoding",
  "connection",
  "keep-alive",
  "set-cookie",
]);

function forbidden(reason) {
  return { allowed: false, code: "forbidden_path", reason };
}

/**
 * Strictly validates HTTP method + raw request path against the host gateway allowlist.
 * Rejects path traversal, encoded dots/slashes, backslashes, double slashes, and fragments.
 */
export function isAllowedGatewayPath(method, rawPath, { allowQuotas = false } = {}) {
  if (typeof method !== "string" || typeof rawPath !== "string") {
    return forbidden("invalid_input");
  }
  const m = method.trim().toUpperCase();
  if (!m) return forbidden("empty_method");
  if (!rawPath.startsWith("/")) return forbidden("must_start_with_slash");
  if (/[\x00-\x20\x7f]/.test(rawPath)) return forbidden("control_or_whitespace");
  if (rawPath.includes("#") || /%23/i.test(rawPath)) return forbidden("fragment");
  if (rawPath.includes("\\") || /%5c/i.test(rawPath)) return forbidden("backslash");
  if (rawPath.includes("..") || /%2e/i.test(rawPath)) return forbidden("dot_dot");

  const qIdx = rawPath.indexOf("?");
  const rawPathPart = qIdx >= 0 ? rawPath.slice(0, qIdx) : rawPath;
  const search = qIdx >= 0 ? rawPath.slice(qIdx) : "";

  if (rawPathPart.includes("//") || /%2f/i.test(rawPathPart)) {
    return forbidden("double_or_encoded_slash");
  }

  let decodedPath;
  try {
    decodedPath = decodeURIComponent(rawPathPart);
  } catch {
    return forbidden("malformed_encoding");
  }

  if (
    decodedPath.includes("%") ||
    decodedPath.includes("..") ||
    decodedPath.includes("\\") ||
    decodedPath.includes("//") ||
    decodedPath.includes("#") ||
    /[\x00-\x20\x7f]/.test(decodedPath)
  ) {
    return forbidden("normalized_anomaly");
  }

  const segments = decodedPath.split("/");
  for (const seg of segments) {
    if (seg === "." || seg === "..") return forbidden("dot_segment");
  }

  if (m === "GET") {
    if (ALLOWED_GET_PATHS.has(decodedPath)) {
      return { allowed: true, method: m, path: decodedPath, search, pathModel: "" };
    }
    if (decodedPath === "/v1/magpie/quotas" && allowQuotas === true) {
      return { allowed: true, method: m, path: decodedPath, search, pathModel: "" };
    }
    return forbidden("not_in_get_allowlist");
  }

  if (m === "POST") {
    if (ALLOWED_POST_EXACT_PATHS.has(decodedPath)) {
      return { allowed: true, method: m, path: decodedPath, search, pathModel: "" };
    }
    const gm = decodedPath.match(GEMINI_PATH_RE);
    if (gm) {
      const modelName = gm[1];
      if (
        modelName !== "." &&
        !modelName.includes("..") &&
        !modelName.includes("/") &&
        GEMINI_MODEL_RE.test(modelName)
      ) {
        return { allowed: true, method: m, path: decodedPath, search, pathModel: modelName };
      }
      return forbidden("invalid_gemini_model");
    }
    return forbidden("not_in_post_allowlist");
  }

  return forbidden("method_not_allowed");
}

function encodeJsonBody(obj) {
  return new TextEncoder().encode(JSON.stringify(obj));
}

function jsonError(status, code, message) {
  return {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
    body: encodeJsonBody({ code, error: { code, message } }),
  };
}

function extractRawPath(req) {
  if (typeof req?.path === "string" && req.path.length > 0) return req.path;
  if (typeof req?.url === "string" && req.url.length > 0) {
    const raw = req.url;
    if (raw.startsWith("/")) return raw;
    const schemeIdx = raw.indexOf("://");
    if (schemeIdx > 0) {
      const slashIdx = raw.indexOf("/", schemeIdx + 3);
      return slashIdx >= 0 ? raw.slice(slashIdx) : "/";
    }
    return raw;
  }
  return "/";
}

function sanitizeIncomingHeaders(rawHeaders, secret) {
  const out = {};
  const entries =
    rawHeaders instanceof Headers
      ? rawHeaders.entries()
      : Array.isArray(rawHeaders)
        ? rawHeaders
        : rawHeaders && typeof rawHeaders === "object"
          ? Object.entries(rawHeaders)
          : [];

  for (const [k, v] of entries) {
    const key = String(k).toLowerCase();
    if (STRIPPED_REQUEST_HEADERS.has(key)) continue;
    if (v === undefined || v === null) continue;
    out[key] = Array.isArray(v) ? v.join(", ") : String(v);
  }
  out.authorization = `Bearer ${secret}`;
  return out;
}

function sanitizeOutgoingHeaders(headers) {
  const out = {};
  if (!headers) return out;
  const entries =
    headers instanceof Headers
      ? headers.entries()
      : Array.isArray(headers)
        ? headers
        : typeof headers === "object"
          ? Object.entries(headers)
          : [];
  for (const [k, v] of entries) {
    const key = String(k).toLowerCase();
    if (STRIPPED_RESPONSE_HEADERS.has(key)) continue;
    out[key] = Array.isArray(v) ? v.join(", ") : String(v);
  }
  return out;
}

function extractModelFromRequestBody(body) {
  if (!body) return "";
  try {
    let text = "";
    if (typeof body === "string") {
      if (body.length > 512 * 1024) return "";
      text = body;
    } else if (body instanceof Uint8Array || ArrayBuffer.isView(body)) {
      if (body.byteLength > 512 * 1024) return "";
      text = new TextDecoder().decode(body);
    } else {
      return "";
    }
    const parsed = JSON.parse(text);
    return typeof parsed?.model === "string" ? parsed.model.trim() : "";
  } catch {
    return "";
  }
}

function toIntOrNull(val) {
  if (typeof val !== "number" || !Number.isFinite(val) || val < 0) return null;
  return Math.floor(val);
}

function applyUsageFromJson(obj, acc) {
  if (!obj || typeof obj !== "object") return;

  const model =
    (typeof obj.model === "string" && obj.model) ||
    (typeof obj.modelVersion === "string" && obj.modelVersion) ||
    (typeof obj.message?.model === "string" && obj.message.model) ||
    (typeof obj.response?.model === "string" && obj.response.model) ||
    "";
  if (model) acc.model = model;

  const u = obj.usage || obj.message?.usage || obj.response?.usage;
  if (u && typeof u === "object") {
    const inTok = toIntOrNull(u.input_tokens ?? u.prompt_tokens);
    const outTok = toIntOrNull(u.output_tokens ?? u.completion_tokens);
    if (inTok !== null) {
      acc.inputTokens = Math.max(acc.inputTokens, inTok);
      acc.sawUsage = true;
    }
    if (outTok !== null) {
      acc.outputTokens = Math.max(acc.outputTokens, outTok);
      acc.sawUsage = true;
    }
  }

  const gm = obj.usageMetadata;
  if (gm && typeof gm === "object") {
    const inTok = toIntOrNull(gm.promptTokenCount);
    let outTok = toIntOrNull(gm.candidatesTokenCount);
    if (outTok === null && gm.totalTokenCount != null && inTok !== null) {
      outTok = toIntOrNull(gm.totalTokenCount - inTok);
    }
    if (inTok !== null) {
      acc.inputTokens = Math.max(acc.inputTokens, inTok);
      acc.sawUsage = true;
    }
    if (outTok !== null) {
      acc.outputTokens = Math.max(acc.outputTokens, outTok);
      acc.sawUsage = true;
    }
  }
}

function createUsageExtractor(contentType) {
  const ct = String(contentType || "").toLowerCase();
  const isSse = ct.includes("text/event-stream");
  const isJson = ct.includes("application/json");
  const decoder = new TextDecoder();
  const acc = { model: "", inputTokens: 0, outputTokens: 0, sawUsage: false };
  let trailing = "";
  let jsonBuf = "";
  let jsonOverflow = false;

  const inspectLine = (rawLine) => {
    let line = rawLine.trim();
    if (!line) return;
    if (line.startsWith("data:")) {
      line = line.slice(5).trim();
    } else if (line.startsWith("[") || line.startsWith(",")) {
      line = line.replace(/^[\[,]+/, "").trim();
    }
    line = line.replace(/[\],]+$/, "").trim();
    if (!line || line === "[DONE]" || !line.startsWith("{")) return;
    if (
      !line.includes('"usage"') &&
      !line.includes('"usageMetadata"') &&
      !line.includes('"model"') &&
      !line.includes('"modelVersion"')
    ) {
      return;
    }
    try {
      applyUsageFromJson(JSON.parse(line), acc);
    } catch {
      // Ignore partial or non-JSON lines; never keep raw text.
    }
  };

  return {
    push(chunk) {
      if (!(chunk instanceof Uint8Array) || chunk.byteLength === 0) return;
      const text = decoder.decode(chunk, { stream: true });
      if (isJson && !isSse) {
        if (!jsonOverflow) {
          if (jsonBuf.length + text.length <= 128 * 1024) {
            jsonBuf += text;
          } else {
            jsonBuf = "";
            jsonOverflow = true;
          }
        }
        return;
      }

      const combined = trailing + text;
      const lines = combined.split(/\r?\n/);
      trailing = lines.pop() ?? "";
      if (trailing.length > 64 * 1024) {
        trailing = "";
      }
      for (const line of lines) {
        inspectLine(line);
      }
    },
    finish() {
      const tail = decoder.decode();
      if (isJson && !isSse) {
        if (!jsonOverflow && jsonBuf) {
          jsonBuf += tail;
          try {
            applyUsageFromJson(JSON.parse(jsonBuf), acc);
          } catch {
            // Ignore malformed JSON responses.
          }
        }
        jsonBuf = "";
        return acc;
      }
      if (trailing || tail) {
        inspectLine(trailing + tail);
        trailing = "";
      }
      return acc;
    },
  };
}

function readStoreState(store) {
  return typeof store?.get === "function" ? store.get() : store;
}

function normalizeGatewayBase(raw) {
  if (typeof raw !== "string") return "";
  const trimmed = raw.trim();
  if (!trimmed) return "";
  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed) ? trimmed : `http://${trimmed}`;
  return withScheme.replace(/\/+$/, "");
}

/**
 * Creates the host-side HTTP inference gateway handler with:
 * - Member active/paused/revoked & global sharingEnabled enforcement
 * - Strict path allowlist
 * - Mandatory 1ms Fail-Closed `/v1/magpie/limit` oracle (blocking loopback privilege escalation)
 * - Header sanitization & host-local key injection
 * - Per-member AbortController tracking for instant stream revocation
 * - Unbuffered SSE passthrough with metadata-only usage attribution
 */
export function createHostGatewayHandler({
  store,
  getGatewayUrl,
  onUsage,
  fetchImpl = fetch,
} = {}) {
  /** @type {Map<string, Set<AbortController>>} */
  const activeControllers = new Map();

  function registerController(memberId, controller) {
    let set = activeControllers.get(memberId);
    if (!set) {
      set = new Set();
      activeControllers.set(memberId, set);
    }
    set.add(controller);
  }

  function unregisterController(memberId, controller) {
    const set = activeControllers.get(memberId);
    if (!set) return;
    set.delete(controller);
    if (set.size === 0) activeControllers.delete(memberId);
  }

  function activeCount(memberId) {
    return activeControllers.get(memberId)?.size ?? 0;
  }

  function abortMemberStreams(memberId) {
    const set = activeControllers.get(memberId);
    if (!set) return 0;
    const controllers = [...set];
    activeControllers.delete(memberId);
    const reason = new DOMException("Member stream aborted", "AbortError");
    for (const ctrl of controllers) {
      try {
        ctrl.abort(reason);
      } catch {
        // Ignore already-aborted controllers.
      }
    }
    return controllers.length;
  }

  async function handleHttpRequest(memberId, req, { signal } = {}) {
    const state = readStoreState(store);
    if (!state || !state.sharingEnabled) {
      return jsonError(503, "share_offline", "Host sharing is disabled");
    }

    const member = Array.isArray(state.members)
      ? state.members.find((m) => m && m.id === memberId)
      : null;
    if (!member || member.status === "revoked") {
      return jsonError(403, "share_revoked", "Member access has been revoked");
    }
    if (member.status === "paused") {
      return jsonError(403, "share_paused", "Member access is paused");
    }
    if (!member.magpieKeySecret || !member.magpieKeyName) {
      return jsonError(403, "key_revoked_or_invalid", "Member gateway key is missing");
    }

    const rawPath = extractRawPath(req);
    const pathCheck = isAllowedGatewayPath(req?.method, rawPath, {
      allowQuotas: Boolean(state.visibility?.quotas),
    });
    if (!pathCheck.allowed) {
      return jsonError(403, "forbidden_path", "Requested path is not allowed");
    }

    const rawGwUrl = typeof getGatewayUrl === "function" ? await getGatewayUrl() : getGatewayUrl;
    const gatewayUrl = normalizeGatewayBase(rawGwUrl);
    if (!isLoopbackUrl(gatewayUrl)) {
      return jsonError(503, "magpie_unavailable", "Local Magpie gateway is unavailable");
    }

    if (signal?.aborted) {
      return jsonError(499, "request_aborted", "Client aborted request");
    }

    const memberAbort = new AbortController();
    registerController(memberId, memberAbort);

    let cleaned = false;
    const onCallerAbort = () => {
      try {
        memberAbort.abort(signal?.reason ?? new DOMException("Client aborted", "AbortError"));
      } catch {}
    };
    signal?.addEventListener("abort", onCallerAbort, { once: true });

    const cleanup = () => {
      if (cleaned) return;
      cleaned = true;
      unregisterController(memberId, memberAbort);
      signal?.removeEventListener("abort", onCallerAbort);
    };

    try {
      // Mandatory Fail-Closed oracle (~1ms): an invalid/revoked key on 127.0.0.1 silently
      // degrades to unrestricted local agent access unless verified via /v1/magpie/limit.
      const oracleController = new AbortController();
      const oracleTimer = setTimeout(() => oracleController.abort(new Error("oracle_timeout")), 5000);
      const onMemberAbortOracle = () => oracleController.abort(memberAbort.signal.reason);
      memberAbort.signal.addEventListener("abort", onMemberAbortOracle, { once: true });

      let oracleRes;
      try {
        oracleRes = await fetchImpl(`${gatewayUrl}/v1/magpie/limit`, {
          method: "GET",
          headers: { authorization: `Bearer ${member.magpieKeySecret}` },
          signal: oracleController.signal,
        });
      } catch (err) {
        if (memberAbort.signal.aborted) {
          cleanup();
          return jsonError(403, "share_revoked", "Member stream aborted");
        }
        cleanup();
        return jsonError(503, "magpie_unavailable", `Magpie oracle unreachable: ${err?.message || "error"}`);
      } finally {
        clearTimeout(oracleTimer);
        memberAbort.signal.removeEventListener("abort", onMemberAbortOracle);
      }

      const oracleData = await oracleRes.json().catch(() => null);
      const validKey =
        oracleRes.status === 200 &&
        oracleData &&
        typeof oracleData.key === "string" &&
        oracleData.key.length > 0 &&
        oracleData.key === member.magpieKeyName;

      if (!validKey) {
        cleanup();
        return jsonError(403, "key_revoked_or_invalid", "Gateway key is invalid or revoked");
      }

      // Re-check store state right before forwarding in case status changed mid-oracle.
      const latestState = readStoreState(store);
      const latestMember = Array.isArray(latestState?.members)
        ? latestState.members.find((m) => m && m.id === memberId)
        : null;
      if (!latestState?.sharingEnabled) {
        cleanup();
        return jsonError(503, "share_offline", "Host sharing is disabled");
      }
      if (!latestMember || latestMember.status === "revoked") {
        cleanup();
        return jsonError(403, "share_revoked", "Member access has been revoked");
      }
      if (latestMember.status === "paused") {
        cleanup();
        return jsonError(403, "share_paused", "Member access is paused");
      }

      const requestModel = extractModelFromRequestBody(req?.body);
      const forwardHeaders = sanitizeIncomingHeaders(req?.headers, member.magpieKeySecret);
      const upstreamUrl = `${gatewayUrl}${pathCheck.path}${pathCheck.search}`;
      const fetchInit = {
        method: pathCheck.method,
        headers: forwardHeaders,
        signal: memberAbort.signal,
      };
      if (pathCheck.method !== "GET" && pathCheck.method !== "HEAD" && req?.body !== undefined && req?.body !== null) {
        fetchInit.body = req.body;
        if (typeof req.body?.getReader === "function") {
          fetchInit.duplex = "half";
        }
      }

      let upstreamRes;
      try {
        upstreamRes = await fetchImpl(upstreamUrl, fetchInit);
      } catch (err) {
        cleanup();
        if (memberAbort.signal.aborted) {
          return jsonError(403, "share_revoked", "Member stream aborted");
        }
        return jsonError(502, "upstream_error", `Upstream request failed: ${err?.message || "error"}`);
      }

      const resHeaders = sanitizeOutgoingHeaders(upstreamRes.headers);
      if (!upstreamRes.body) {
        cleanup();
        return { status: upstreamRes.status, headers: resHeaders, body: new Uint8Array(0) };
      }

      const usageTracker = createUsageExtractor(resHeaders["content-type"]);
      const reader = upstreamRes.body.getReader();
      let streamFinished = false;

      const stream = new ReadableStream({
        start(controller) {
          const onAbort = () => {
            if (streamFinished) return;
            streamFinished = true;
            try {
              reader.cancel(memberAbort.signal.reason).catch(() => {});
            } catch {}
            try {
              controller.error(
                memberAbort.signal.reason instanceof Error
                  ? memberAbort.signal.reason
                  : new DOMException("Stream aborted", "AbortError"),
              );
            } catch {}
            cleanup();
          };

          if (memberAbort.signal.aborted) {
            onAbort();
            return;
          }
          memberAbort.signal.addEventListener("abort", onAbort, { once: true });

          (async () => {
            try {
              while (!streamFinished) {
                const { done, value } = await reader.read();
                if (streamFinished) break;
                if (done) {
                  streamFinished = true;
                  memberAbort.signal.removeEventListener("abort", onAbort);
                  const summary = usageTracker.finish();
                  if (upstreamRes.status >= 200 && upstreamRes.status < 300 && summary.sawUsage && typeof onUsage === "function") {
                    const resolvedModel =
                      summary.model && requestModel && requestModel.endsWith(`/${summary.model}`)
                        ? requestModel
                        : summary.model || requestModel || pathCheck.pathModel || "unknown";
                    try {
                      Promise.resolve(
                        onUsage({
                          memberId,
                          model: resolvedModel,
                          inputTokens: summary.inputTokens,
                          outputTokens: summary.outputTokens,
                        }),
                      ).catch(() => {});
                    } catch {}
                  }
                  try {
                    controller.close();
                  } catch {}
                  cleanup();
                  break;
                }
                if (value && value.byteLength > 0) {
                  // Enqueue immediately for unbuffered SSE passthrough before inspecting usage metadata.
                  controller.enqueue(value);
                  usageTracker.push(value);
                }
              }
            } catch (err) {
              if (!streamFinished) {
                streamFinished = true;
                memberAbort.signal.removeEventListener("abort", onAbort);
                try {
                  controller.error(err);
                } catch {}
                cleanup();
              }
            }
          })();
        },
        cancel(reason) {
          if (streamFinished) return;
          streamFinished = true;
          try {
            reader.cancel(reason).catch(() => {});
          } catch {}
          try {
            memberAbort.abort(reason);
          } catch {}
          cleanup();
        },
      });

      return {
        status: upstreamRes.status,
        headers: resHeaders,
        body: stream,
      };
    } catch (err) {
      cleanup();
      throw err;
    }
  }

  return {
    handleHttpRequest,
    abortMemberStreams,
    activeCount,
  };
}
