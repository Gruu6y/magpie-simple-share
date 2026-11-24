import { execFile as nodeExecFile } from "node:child_process";
import { accessSync, constants as fsConstants, existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

import { magpieConfigDir } from "./paths.mjs";

const ANSI_RE = /\u001b\[[0-9;]*[A-Za-z]/g;
const KEY_SECRET_RE = /\bsk-magpie-key-[A-Za-z0-9_-]+\b/;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const PROVIDER_ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const PERIOD_RE = /^(?:day|week|month|\d+[dh])$/;

/**
 * Known personal subscription / agent-login providers in Magpie.
 * API vendors and routing groups (e.g. deepseek, openrouter, group) classify as "api".
 */
const SUBSCRIPTION_PROVIDERS = new Set([
  "claude",
  "codex",
  "copilot",
  "kiro",
  "cursor",
  "workbuddy",
  "qoder",
  "gemini-web",
  "gemini",
  "gemini-cli",
  "doubao",
  "kimi-work",
  "devin",
  "zed",
  "warp",
  "cline",
  "trae",
  "loomy",
  "catpaw",
  "orcaterm",
  "codearts",
  "agy",
  "antigravity",
  "qwen-cli",
  "windsurf",
  "augment",
  "iflow",
]);

function stripAnsi(text) {
  return String(text ?? "").replace(ANSI_RE, "");
}

function resolveConfigDir(env = process.env, configDir) {
  if (configDir) return configDir;
  return magpieConfigDir(env);
}

/**
 * Resolves the Magpie CLI binary across PATH and standard Windows / macOS / Linux install locations.
 * Ignores boolean MAGPIE_CLI flags such as "1" used by Magpie's install script.
 */
export function resolveMagpieBinary(
  env = process.env,
  { platform = process.platform, existsSync: existsFn = existsSync, accessSync: accessFn = accessSync } = {},
) {
  const e = env ?? process.env;
  for (const key of ["MAGPIE_BIN", "SIMPLE_SHARE_MAGPIE_BIN"]) {
    const val = typeof e[key] === "string" ? e[key].trim() : "";
    if (val) return val;
  }

  const cliOverride = typeof e.MAGPIE_CLI === "string" ? e.MAGPIE_CLI.trim() : "";
  if (cliOverride && !/^(?:0|1|true|false|yes|no)$/i.test(cliOverride)) {
    return cliOverride;
  }

  const binName = platform === "win32" ? "magpie.exe" : "magpie";
  const isExecutable = (candidate) => {
    if (!candidate || !existsFn(candidate)) return false;
    if (platform !== "win32" && typeof accessFn === "function") {
      try {
        accessFn(candidate, fsConstants.X_OK);
        return true;
      } catch {
        return false;
      }
    }
    return true;
  };

  const pathEnv = e.PATH || (platform === "win32" ? e.Path : "") || "";
  if (pathEnv) {
    const delim = platform === "win32" ? ";" : ":";
    for (const rawDir of pathEnv.split(delim)) {
      const dir = rawDir.trim().replace(/^"(.*)"$/, "$1");
      if (!dir) continue;
      const candidate = join(dir, binName);
      if (isExecutable(candidate)) return candidate;
    }
  }

  const home =
    platform === "win32"
      ? e.USERPROFILE || e.HOME || homedir()
      : e.HOME || e.USERPROFILE || homedir();

  let candidates = [];
  if (platform === "darwin") {
    candidates = [
      join(home, ".local", "bin", "magpie"),
      "/opt/homebrew/bin/magpie",
      "/usr/local/bin/magpie",
      "/Applications/magpie.app/Contents/MacOS/magpie",
      "/Applications/Magpie.app/Contents/MacOS/magpie",
      join(home, "Applications", "magpie.app", "Contents", "MacOS", "magpie"),
      join(home, "Applications", "Magpie.app", "Contents", "MacOS", "magpie"),
      join(home, ".magpie", "bin", "magpie"),
    ];
  } else if (platform === "linux") {
    candidates = [
      join(home, ".local", "bin", "magpie"),
      "/usr/local/bin/magpie",
      "/usr/bin/magpie",
      join(home, ".magpie", "bin", "magpie"),
      join(home, "bin", "magpie"),
    ];
  } else if (platform === "win32") {
    candidates = [
      e.LOCALAPPDATA ? join(e.LOCALAPPDATA, "Programs", "magpie", "magpie.exe") : "",
      join(home, "AppData", "Local", "Programs", "magpie", "magpie.exe"),
    ];
  }

  for (const candidate of candidates) {
    if (isExecutable(candidate)) return candidate;
  }

  return binName;
}

function normalizeCandidateUrl(raw) {
  if (typeof raw !== "string") return "";
  const trimmed = raw.trim();
  if (!trimmed || /[\s\r\n\0]/.test(trimmed)) return "";
  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)
    ? trimmed
    : `http://${trimmed}`;
  return withScheme.replace(/\/+$/, "");
}

/**
 * Strictly validates that a URL points to http on 127.0.0.1, [::1], or localhost
 * with no credentials, query, or hash.
 */
export function isLoopbackUrl(u) {
  if (typeof u !== "string") return false;
  const trimmed = u.trim();
  if (!trimmed || /[\s\r\n\0]/.test(trimmed)) return false;
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:") return false;
  if (parsed.username || parsed.password) return false;
  if (parsed.hash) return false;
  const host = parsed.hostname.toLowerCase();
  const isLoopbackHost =
    host === "127.0.0.1" || host === "localhost" || host === "[::1]" || host === "::1";
  if (!isLoopbackHost) return false;
  if (parsed.port !== "") {
    const portNum = Number(parsed.port);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) return false;
  }
  return true;
}

function isOriginLoopbackUrl(u) {
  if (!isLoopbackUrl(u)) return false;
  const parsed = new URL(u.trim());
  return !parsed.search && (!parsed.pathname || parsed.pathname === "/");
}

async function runMagpie(args, { env = process.env, execMagpie, timeoutMs = 15000 } = {}) {
  if (typeof execMagpie === "function") {
    const res = await execMagpie(args, { env });
    if (typeof res === "string") {
      return { code: 0, stdout: stripAnsi(res).trim(), stderr: "" };
    }
    const code = res?.code ?? res?.exitCode ?? (res?.ok === false ? 1 : 0);
    return {
      code,
      stdout: stripAnsi(res?.stdout ?? "").trim(),
      stderr: stripAnsi(res?.stderr ?? "").trim(),
    };
  }

  const bin = resolveMagpieBinary(env);
  return new Promise((resolve, reject) => {
    try {
      const child = nodeExecFile(
        bin,
        args,
        { env, timeout: timeoutMs, windowsHide: true, maxBuffer: 2 * 1024 * 1024 },
        (error, stdout, stderr) => {
          const out = stripAnsi(stdout).trim();
          const err = stripAnsi(stderr).trim();
          if (error) {
            const code = typeof error.code === "number" ? error.code : 1;
            resolve({ code, stdout: out, stderr: err || stripAnsi(error.message).trim() });
            return;
          }
          resolve({ code: 0, stdout: out, stderr: err });
        },
      );
      child?.once?.("error", (err) => reject(err));
    } catch (err) {
      reject(err);
    }
  });
}

async function probeHello(url, { fetchImpl = fetch, timeoutMs = 2000 } = {}) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error("timeout")), timeoutMs);
    try {
      const res = await fetchImpl(`${url}/api/hello`, {
        method: "GET",
        signal: controller.signal,
      });
      if (!res.ok) return { ok: false };
      const data = await res.json().catch(() => null);
      if (!data || typeof data !== "object") return { ok: false };
      if (data.name !== "magpie" && data.ok !== true && typeof data.version !== "string") {
        return { ok: false };
      }
      return {
        ok: true,
        version: typeof data.version === "string" ? data.version : "",
      };
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return { ok: false };
  }
}

/**
 * Discovers a running local Magpie gateway via env.MAGPIE_ADDR, <configDir>/gateway.json,
 * or `magpie status --json`, strictly enforcing loopback URLs and probing `/api/hello`.
 */
export async function discoverMagpieGateway({
  env = process.env,
  configDir,
  execMagpie,
  fetchImpl = fetch,
  timeoutMs = 2000,
} = {}) {
  const probeCandidate = async (url, version = "") => {
    const parsed = new URL(url);
    const addr = parsed.host;
    const hello = await probeHello(url, { fetchImpl, timeoutMs });
    if (hello.ok) {
      return {
        ok: true,
        running: true,
        url,
        addr,
        version: hello.version || version || "",
      };
    }
    return { ok: false, running: false, url, addr, version: version || "" };
  };

  if (typeof env.MAGPIE_ADDR === "string" && env.MAGPIE_ADDR.trim()) {
    const url = normalizeCandidateUrl(env.MAGPIE_ADDR);
    if (!isOriginLoopbackUrl(url)) {
      return {
        ok: false,
        running: false,
        url: "",
        addr: "",
        version: "",
        error: "non_loopback_gateway_addr",
      };
    }
    return await probeCandidate(url);
  }

  let fallback = { ok: false, running: false, url: "", addr: "", version: "" };

  const cfgDir = resolveConfigDir(env, configDir);
  try {
    const raw = await readFile(join(cfgDir, "gateway.json"), "utf8");
    const doc = JSON.parse(raw);
    const url = normalizeCandidateUrl(doc?.url || doc?.addr || "");
    if (isOriginLoopbackUrl(url)) {
      const res = await probeCandidate(url, typeof doc?.version === "string" ? doc.version : "");
      if (res.ok) return res;
      fallback = res;
    }
  } catch {
    // Missing or unreadable gateway.json falls through to CLI status.
  }

  try {
    const st = await runMagpie(["status", "--json"], { env, execMagpie, timeoutMs: 4000 });
    if (st.code === 0 && st.stdout) {
      const doc = JSON.parse(st.stdout);
      const url = normalizeCandidateUrl(doc?.url || doc?.addr || "");
      if (isOriginLoopbackUrl(url)) {
        const res = await probeCandidate(url, typeof doc?.version === "string" ? doc.version : "");
        if (res.ok) return res;
        if (!fallback.url) fallback = res;
      }
    }
  } catch {
    // magpie CLI absent or status parse failed.
  }

  return fallback;
}

/**
 * Classifies a Magpie model's provider into personal subscription ("sub") vs API/router ("api").
 */
export function classifyProviderKind(provider, modelId = "", meta = null) {
  if (meta && (meta.kind === "sub" || meta.billing === "subscription" || meta.billing === "sub")) {
    return "sub";
  }
  const raw = String(provider || "").trim() || (String(modelId).includes("/") ? String(modelId).split("/")[0] : "");
  const norm = raw.toLowerCase();
  if (!norm) return "api";
  for (const sub of SUBSCRIPTION_PROVIDERS) {
    if (norm === sub || norm.startsWith(`${sub}-`) || norm.startsWith(`${sub}_`)) {
      return "sub";
    }
  }
  return "api";
}

/**
 * Queries GET <gatewayUrl>/v1/models and returns normalized model descriptors.
 * Returns [] gracefully when Magpie is offline or unreachable.
 */
export async function fetchLocalModels(
  gatewayUrl,
  { env = process.env, fetchImpl = fetch, timeoutMs = 3000 } = {},
) {
  void env;
  const url = normalizeCandidateUrl(gatewayUrl);
  if (!isOriginLoopbackUrl(url)) return [];

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("timeout")), timeoutMs);
  try {
    const res = await fetchImpl(`${url}/v1/models`, {
      method: "GET",
      signal: controller.signal,
    });
    if (!res.ok) return [];
    const payload = await res.json().catch(() => null);
    const list = Array.isArray(payload?.data)
      ? payload.data
      : Array.isArray(payload)
        ? payload
        : [];
    const out = [];
    const seen = new Set();
    for (const item of list) {
      const id = typeof item?.id === "string" ? item.id.trim() : "";
      if (!id || seen.has(id)) continue;
      seen.add(id);
      const slash = id.indexOf("/");
      const provider =
        (typeof item?.owned_by === "string" && item.owned_by.trim()) ||
        (slash > 0 ? id.slice(0, slash) : "unknown");
      const rawLabel =
        (typeof item?.display_name === "string" && item.display_name.trim()) ||
        (typeof item?.name === "string" && item.name.trim()) ||
        (slash > 0 ? id.slice(slash + 1) : id);
      const label = id.startsWith("group/") && !item?.display_name ? id : rawLabel || id;
      out.push({
        id,
        label,
        provider,
        kind: classifyProviderKind(provider, id, item),
      });
    }
    return out;
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

function parseKeyIdFromList(listStdout, name, keySecret) {
  const lines = stripAnsi(listStdout)
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  const suffix = keySecret && keySecret.length >= 6 ? keySecret.slice(-6) : "";

  // First pass: exact key suffix match (handles duplicate key names & spaces cleanly).
  if (suffix) {
    for (const line of lines) {
      if (/^ID\b/i.test(line)) continue;
      if (line.includes(suffix) || (keySecret && line.includes(keySecret))) {
        const m = line.match(/^([A-Za-z0-9_-]{4,})\s+/);
        if (m) return m[1];
      }
    }
  }

  // Second pass: match Magpie table columns `ID  NAME  enabled|disabled  ...`.
  for (const line of lines) {
    if (/^ID\b/i.test(line)) continue;
    const m = line.match(/^([A-Za-z0-9_-]{4,})\s+(.+?)\s+(?:enabled|disabled)\s+/);
    if (m && m[2].trim() === name) {
      return m[1];
    }
  }

  // Fallback for simplified mock list outputs: `<id> <name> ...`.
  for (const line of lines) {
    if (/^ID\b/i.test(line)) continue;
    const tokens = line.split(/\s+/);
    if (tokens.length >= 2 && tokens[1] === name) {
      return tokens[0];
    }
  }

  return "";
}

function validateModelList(models) {
  if (models === undefined || models === null) return ["all"];
  const arr = Array.isArray(models) ? models : [models];
  if (arr.length === 0 || arr.includes("all")) return ["all"];
  const cleaned = [];
  for (const entry of arr) {
    if (typeof entry !== "string") throw new Error("Invalid model identifier");
    const m = entry.trim();
    if (!m || m.startsWith("-") || /[\s\r\n\0]/.test(m)) {
      throw new Error(`Invalid model identifier: ${entry}`);
    }
    cleaned.push(m);
  }
  return cleaned;
}

function validateKeyId(keyId) {
  if (typeof keyId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(keyId.trim())) {
    throw new Error("Invalid gateway keyId");
  }
  return keyId.trim();
}

function buildLimitArgs(keyId, { period, tokenLimitWan, costLimit }) {
  if (period === "off") return ["gateway-key", "limit", keyId, "off"];
  const p = period ?? "day";
  if (!PERIOD_RE.test(String(p))) {
    throw new Error(`Invalid limit period: ${String(p)}`);
  }
  const tokens =
    tokenLimitWan !== undefined && tokenLimitWan !== null && Number(tokenLimitWan) > 0
      ? Math.round(Number(tokenLimitWan) * 10000)
      : 0;
  const cost =
    costLimit !== undefined && costLimit !== null && Number(costLimit) > 0
      ? Number(costLimit)
      : 0;

  if (tokens <= 0 && cost <= 0) {
    return ["gateway-key", "limit", keyId, "off"];
  }
  const args = ["gateway-key", "limit", keyId, String(p)];
  if (tokens > 0) args.push("--tokens", String(tokens));
  if (cost > 0) args.push("--cost", String(Number(cost.toFixed(6))));
  return args;
}

async function execOrThrow(args, opts, context) {
  const res = await runMagpie(args, opts);
  if (res.code !== 0) {
    throw new Error(`${context} failed: ${res.stderr || res.stdout || `exit ${res.code}`}`);
  }
  return res;
}

/**
 * Creates a hardened per-member gateway key in Magpie (`mcp none`, `memory off`,
 * `admin off`, `quotas off|on`, model allowlist, period/token/cost limit, concurrency).
 * Rolls back by deleting the created key if any hardening step fails.
 */
export async function createMemberGatewayKey({
  name,
  models,
  period = "day",
  tokenLimitWan,
  costLimit,
  concurrency,
  quotas = false,
  env = process.env,
  execMagpie,
} = {}) {
  const cleanName = typeof name === "string" ? name.trim() : "";
  if (!cleanName || cleanName.length > 64 || cleanName.startsWith("-") || /[\r\n\0]/.test(cleanName)) {
    throw new Error("Invalid member gateway key name");
  }
  const modelArgs = validateModelList(models);
  const opts = { env, execMagpie };

  const addRes = await execOrThrow(["gateway-key", "add", cleanName], opts, "magpie gateway-key add");
  const secretMatch = addRes.stdout.match(KEY_SECRET_RE);
  if (!secretMatch) {
    throw new Error("magpie gateway-key add did not return a key secret");
  }
  const keySecret = secretMatch[0];

  const listRes = await execOrThrow(["gateway-key", "list"], opts, "magpie gateway-key list");
  const keyId = parseKeyIdFromList(listRes.stdout, cleanName, keySecret);
  if (!keyId) {
    throw new Error(`Unable to locate keyId for newly created key "${cleanName}"`);
  }

  try {
    await execOrThrow(["gateway-key", "models", keyId, ...modelArgs], opts, "magpie gateway-key models");
    await execOrThrow(buildLimitArgs(keyId, { period, tokenLimitWan, costLimit }), opts, "magpie gateway-key limit");

    if (concurrency !== undefined) {
      const concVal = Number(concurrency);
      const concArg = Number.isFinite(concVal) && concVal > 0 ? String(Math.floor(concVal)) : "off";
      await execOrThrow(["gateway-key", "concurrency", keyId, concArg], opts, "magpie gateway-key concurrency");
    }

    await execOrThrow(["gateway-key", "mcp", keyId, "none"], opts, "magpie gateway-key mcp");
    await execOrThrow(["gateway-key", "memory", keyId, "off"], opts, "magpie gateway-key memory");
    await execOrThrow(["gateway-key", "admin", keyId, "off"], opts, "magpie gateway-key admin");
    await execOrThrow(
      ["gateway-key", "quotas", keyId, quotas ? "on" : "off"],
      opts,
      "magpie gateway-key quotas",
    );
  } catch (err) {
    await removeMemberGatewayKey({ keyId, env, execMagpie }).catch(() => {});
    throw err;
  }

  return { keyId, keyName: cleanName, keySecret };
}

/**
 * Updates models, limits, concurrency, and/or quotas visibility on an existing gateway key.
 */
export async function updateMemberGatewayKey({
  keyId,
  models,
  period,
  tokenLimitWan,
  costLimit,
  concurrency,
  quotas,
  env = process.env,
  execMagpie,
} = {}) {
  const id = validateKeyId(keyId);
  const opts = { env, execMagpie };

  if (models !== undefined) {
    const modelArgs = validateModelList(models);
    await execOrThrow(["gateway-key", "models", id, ...modelArgs], opts, "magpie gateway-key models");
  }

  if (period !== undefined || tokenLimitWan !== undefined || costLimit !== undefined) {
    await execOrThrow(buildLimitArgs(id, { period, tokenLimitWan, costLimit }), opts, "magpie gateway-key limit");
  }

  if (concurrency !== undefined) {
    const concVal = Number(concurrency);
    const concArg = Number.isFinite(concVal) && concVal > 0 ? String(Math.floor(concVal)) : "off";
    await execOrThrow(["gateway-key", "concurrency", id, concArg], opts, "magpie gateway-key concurrency");
  }

  if (quotas !== undefined) {
    await execOrThrow(
      ["gateway-key", "quotas", id, quotas ? "on" : "off"],
      opts,
      "magpie gateway-key quotas",
    );
  }

  return { ok: true, keyId: id };
}

/**
 * Removes a gateway key from Magpie. Treats already-missing keys as idempotent success.
 */
export async function removeMemberGatewayKey({ keyId, env = process.env, execMagpie } = {}) {
  const id = validateKeyId(keyId);
  const res = await runMagpie(["gateway-key", "remove", id], { env, execMagpie });
  if (res.code !== 0) {
    if (/not found/i.test(`${res.stderr}\n${res.stdout}`)) {
      return { ok: true, keyId: id, alreadyMissing: true };
    }
    throw new Error(`magpie gateway-key remove failed: ${res.stderr || res.stdout || `exit ${res.code}`}`);
  }
  return { ok: true, keyId: id };
}

async function gatewayHasProviderModels(gatewayUrl, providerId) {
  const models = await fetchLocalModels(gatewayUrl, { timeoutMs: 500 });
  const prefix = `${providerId}/`;
  return models.some((m) => typeof m?.id === "string" && m.id.startsWith(prefix));
}

export async function ensureGatewayLoadedProviderModels(
  providerId,
  {
    env = process.env,
    discoverGatewayFn = discoverMagpieGateway,
    hasProviderModelsFn = gatewayHasProviderModels,
    runSyncFn,
    sleepFn = (ms) => new Promise((r) => setTimeout(r, ms)),
    pollIntervalMs = 100,
    initialWaitMs = 2000,
    postSyncWaitMs = 1500,
    maxSyncRetries = 2,
  } = {},
) {
  const gw = await discoverGatewayFn({ env, timeoutMs: 500 }).catch(() => null);
  if (!gw?.ok || !gw.url) return { loaded: false, synced: 0 };

  const interval = Math.max(1, Number(pollIntervalMs) || 100);
  const pollUntilLoaded = async (budgetMs) => {
    const steps = Math.max(1, Math.ceil((Number(budgetMs) || 0) / interval));
    for (let i = 0; i < steps; i++) {
      if (await hasProviderModelsFn(gw.url, providerId)) return true;
      if (i + 1 < steps) await sleepFn(interval);
    }
    return false;
  };

  if (await pollUntilLoaded(initialWaitMs)) {
    return { loaded: true, synced: 0 };
  }

  const doSync = runSyncFn || (() => runMagpie(["sync"], { env, timeoutMs: 10_000 }));
  const retries = Math.max(0, Number(maxSyncRetries) || 0);
  for (let attempt = 1; attempt <= retries; attempt++) {
    await doSync().catch(() => {});
    const waitMs = attempt === 1 ? postSyncWaitMs : Math.min(postSyncWaitMs, 1000);
    if (await pollUntilLoaded(waitMs)) {
      return { loaded: true, synced: attempt };
    }
  }

  return { loaded: false, synced: retries };
}

/**
 * Registers a local loopback receiver bridge as a `remote-magpie` provider in Magpie.
 */
export async function addRemoteMagpieProvider({
  id,
  bridgeUrl,
  bridgeToken,
  updateIfExists = false,
  env = process.env,
  execMagpie,
} = {}) {
  const cleanId = typeof id === "string" ? id.trim() : "";
  if (!PROVIDER_ID_RE.test(cleanId)) {
    throw new Error("Invalid remote-magpie provider id");
  }
  const normalizedUrl = normalizeCandidateUrl(bridgeUrl);
  if (!isLoopbackUrl(normalizedUrl)) {
    throw new Error("bridgeUrl must be a loopback http URL");
  }
  const token = typeof bridgeToken === "string" ? bridgeToken.trim() : "";
  if (!token || /[\s\r\n\0]/.test(token)) {
    throw new Error("Invalid bridgeToken");
  }

  let res = null;
  if (updateIfExists) {
    const setRes = await runMagpie(
      ["provider", "set", cleanId, `key=${token}`, `url=${normalizedUrl}`],
      { env, execMagpie },
    );
    if (setRes.code === 0) {
      res = setRes;
    }
  }
  if (!res) {
    res = await execOrThrow(
      ["provider", "add", "remote-magpie", token, `url=${normalizedUrl}`, `id=${cleanId}`],
      { env, execMagpie },
      "magpie provider add remote-magpie",
    );
  }

  // Real `magpie serve` can lag refreshing `/v1/models` after CLI writes providers.json;
  // check briefly and run `magpie sync` best-effort if the new provider is not yet visible.
  if (typeof execMagpie !== "function") {
    await ensureGatewayLoadedProviderModels(cleanId, { env }).catch(() => {});
  }

  return { ok: true, id: cleanId, url: normalizedUrl, output: res.stdout };
}

/**
 * Removes a `remote-magpie` provider from Magpie. Treats already-missing providers as idempotent.
 */
export async function removeRemoteMagpieProvider({ id, env = process.env, execMagpie } = {}) {
  const cleanId = typeof id === "string" ? id.trim() : "";
  if (!PROVIDER_ID_RE.test(cleanId)) {
    throw new Error("Invalid remote-magpie provider id");
  }
  const res = await runMagpie(["provider", "rm", cleanId], { env, execMagpie });
  if (res.code !== 0) {
    if (/not found|no provider/i.test(`${res.stderr}\n${res.stdout}`)) {
      return { ok: true, id: cleanId, alreadyMissing: true };
    }
    throw new Error(`magpie provider rm failed: ${res.stderr || res.stdout || `exit ${res.code}`}`);
  }
  return { ok: true, id: cleanId };
}
