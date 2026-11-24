import crypto from "node:crypto";
import { chmod, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import { dirname, resolve } from "node:path";

const VALID_MODES = new Set(["p2p", "self-relay", "direct"]);
const MAX_USAGE_EVENTS = 50_000;

const SENSITIVE_KEYS_ANYWHERE = new Set([
  "magpieKeySecret",
  "bridgeToken",
  "inviteSecret",
  "inviteSecretHex",
  "keySecret",
  "seedHex",
  "keyPem",
  "privateKey",
]);

const SENSITIVE_KEYS_IN_RECORDS = new Set(["s", "secret"]);

export function createDefaultState() {
  return {
    version: 1,
    hostName: (hostname() || "Simple Share").replace(/\.local$/i, "") || "Simple Share",
    sharingEnabled: false,
    tosAcknowledged: false,
    mode: "p2p",
    network: {
      irohRelayUrl: "",
      relayAddr: "",
      relayToken: "",
      directHost: "",
      directPort: 3497,
    },
    visibility: {
      limit: true,
      quotas: false,
    },
    invites: [],
    pending: [],
    members: [],
    usageEvents: [],
    receiverPending: null,
    received: [],
  };
}

function deepClone(val) {
  return structuredClone(val);
}

function normalizeState(raw) {
  const base = createDefaultState();
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return base;
  }
  const merged = {
    ...base,
    ...raw,
    version: 1,
    hostName: typeof raw.hostName === "string" && raw.hostName ? raw.hostName : base.hostName,
    sharingEnabled: Boolean(raw.sharingEnabled),
    tosAcknowledged: Boolean(raw.tosAcknowledged),
    mode: VALID_MODES.has(raw.mode) ? raw.mode : base.mode,
    network: {
      ...base.network,
      ...(raw.network && typeof raw.network === "object" && !Array.isArray(raw.network) ? raw.network : {}),
    },
    visibility: {
      ...base.visibility,
      ...(raw.visibility && typeof raw.visibility === "object" && !Array.isArray(raw.visibility) ? raw.visibility : {}),
    },
    invites: Array.isArray(raw.invites) ? deepClone(raw.invites) : [],
    pending: Array.isArray(raw.pending) ? deepClone(raw.pending) : [],
    members: Array.isArray(raw.members) ? deepClone(raw.members) : [],
    usageEvents: Array.isArray(raw.usageEvents) ? deepClone(raw.usageEvents) : [],
    receiverPending:
      raw.receiverPending && typeof raw.receiverPending === "object" && !Array.isArray(raw.receiverPending)
        ? deepClone(raw.receiverPending)
        : null,
    received: Array.isArray(raw.received) ? deepClone(raw.received) : [],
  };
  merged.network.directPort =
    Number.isInteger(Number(merged.network.directPort)) && Number(merged.network.directPort) > 0
      ? Number(merged.network.directPort)
      : 3497;
  merged.visibility.limit = Boolean(merged.visibility.limit);
  merged.visibility.quotas = Boolean(merged.visibility.quotas);
  return merged;
}

function stripSecretsRecursive(node, inSensitiveRecordCollection = false) {
  if (Array.isArray(node)) {
    return node.map((item) => stripSecretsRecursive(item, inSensitiveRecordCollection));
  }
  if (!node || typeof node !== "object") {
    return node;
  }
  const out = {};
  for (const [k, v] of Object.entries(node)) {
    if (SENSITIVE_KEYS_ANYWHERE.has(k)) {
      continue;
    }
    if (inSensitiveRecordCollection && SENSITIVE_KEYS_IN_RECORDS.has(k)) {
      continue;
    }
    const childInSensitive =
      k === "invites" ||
      k === "pending" ||
      k === "members" ||
      k === "received" ||
      k === "receiverPending";
    out[k] = stripSecretsRecursive(v, inSensitiveRecordCollection || childInSensitive);
  }
  return out;
}

/**
 * Return a deep-cloned snapshot of state with all sensitive secrets
 * (magpieKeySecret, bridgeToken, invite secrets, private key material) removed.
 */
export function sanitizeStateSnapshot(state) {
  if (state === null || state === undefined) {
    return null;
  }
  return stripSecretsRecursive(deepClone(state), false);
}

async function atomicWriteJson(filePath, obj) {
  const dir = dirname(filePath);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const resolvedDir = resolve(dir);
  if (resolvedDir !== resolve(tmpdir()) && resolvedDir !== "/tmp" && resolvedDir !== "/private/tmp") {
    await chmod(dir, 0o700).catch(() => {});
  }
  const payload = JSON.stringify(obj, null, 2) + "\n";
  const tmpPath = `${filePath}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  try {
    await writeFile(tmpPath, payload, { encoding: "utf8", mode: 0o600 });
    await chmod(tmpPath, 0o600).catch(() => {});
    for (let attempt = 0; attempt < 4; attempt += 1) {
      try {
        await rename(tmpPath, filePath);
        break;
      } catch (err) {
        if ((err?.code === "EPERM" || err?.code === "EBUSY") && attempt < 3) {
          await new Promise((r) => setTimeout(r, 10 * (attempt + 1)));
          continue;
        }
        throw err;
      }
    }
    await chmod(filePath, 0o600).catch(() => {});
  } catch (err) {
    await rm(tmpPath, { force: true }).catch(() => {});
    throw err;
  }
}

/**
 * Create an atomic JSON persistence store with serialized async write mutex.
 */
export function createStore(filePath) {
  if (typeof filePath !== "string" || !filePath) {
    throw new Error("store filePath is required");
  }

  let loaded = false;
  let current = createDefaultState();
  let mutex = Promise.resolve();

  function runExclusive(task) {
    const next = mutex.catch(() => {}).then(task);
    mutex = next;
    return next;
  }

  async function readFromDiskOrInit() {
    try {
      const raw = await readFile(filePath, "utf8");
      const parsed = JSON.parse(raw);
      current = normalizeState(parsed);
      loaded = true;
      return deepClone(current);
    } catch (err) {
      if (err?.code === "ENOENT") {
        current = createDefaultState();
        loaded = true;
        return deepClone(current);
      }
      throw err;
    }
  }

  async function load() {
    return runExclusive(() => readFromDiskOrInit());
  }

  function get() {
    return deepClone(current);
  }

  async function update(fn) {
    if (typeof fn !== "function") {
      throw new Error("store.update(fn) requires a function");
    }
    return runExclusive(async () => {
      if (!loaded) {
        await readFromDiskOrInit();
      }
      const draft = deepClone(current);
      const result = await fn(draft);
      const nextState = normalizeState(result !== undefined ? result : draft);
      await atomicWriteJson(filePath, nextState);
      current = nextState;
      return deepClone(current);
    });
  }

  async function recordUsage(
    memberId,
    model,
    { turns = 1, inputTokens = 0, outputTokens = 0, costUsd = 0, ts } = {},
  ) {
    if (typeof memberId !== "string" || !memberId) {
      throw new Error("recordUsage requires a non-empty memberId");
    }
    const eventTs = typeof ts === "number" && Number.isFinite(ts) ? ts : Date.now();
    const event = {
      id: crypto.randomUUID(),
      ts: eventTs,
      memberId,
      model: typeof model === "string" && model ? model : "unknown",
      turns: Math.max(0, Number(turns) || 0),
      inputTokens: Math.max(0, Number(inputTokens) || 0),
      outputTokens: Math.max(0, Number(outputTokens) || 0),
      costUsd: Math.max(0, Number(costUsd) || 0),
    };

    await update((state) => {
      state.usageEvents.push(event);
      if (state.usageEvents.length > MAX_USAGE_EVENTS) {
        state.usageEvents = state.usageEvents.slice(state.usageEvents.length - MAX_USAGE_EVENTS);
      }
      const member = state.members.find((m) => m && m.id === memberId);
      if (member) {
        member.lastUsedAt = eventTs;
      }
    });

    return deepClone(event);
  }

  function queryUsage(memberId, range = "7d") {
    const now = Date.now();
    let cutoff = 0;
    if (range === "7d") {
      cutoff = now - 7 * 24 * 60 * 60 * 1000;
    } else if (range === "month") {
      cutoff = now - 30 * 24 * 60 * 60 * 1000;
    } else if (range === "all") {
      cutoff = 0;
    } else {
      throw new Error(`Invalid usage query range: ${String(range)}`);
    }

    const byModelMap = new Map();
    const totals = {
      turns: 0,
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      costUsd: 0,
    };

    for (const ev of current.usageEvents) {
      if (!ev || typeof ev !== "object") continue;
      if (memberId !== undefined && memberId !== null && memberId !== "*" && ev.memberId !== memberId) {
        continue;
      }
      if (range !== "all" && (typeof ev.ts !== "number" || ev.ts < cutoff)) {
        continue;
      }
      const modelName = ev.model || "unknown";
      let entry = byModelMap.get(modelName);
      if (!entry) {
        entry = {
          model: modelName,
          turns: 0,
          inputTokens: 0,
          outputTokens: 0,
          totalTokens: 0,
          costUsd: 0,
        };
        byModelMap.set(modelName, entry);
      }
      const t = Number(ev.turns) || 0;
      const inp = Number(ev.inputTokens) || 0;
      const out = Number(ev.outputTokens) || 0;
      const cost = Number(ev.costUsd) || 0;

      entry.turns += t;
      entry.inputTokens += inp;
      entry.outputTokens += out;
      entry.totalTokens += inp + out;
      entry.costUsd = Number((entry.costUsd + cost).toFixed(8));

      totals.turns += t;
      totals.inputTokens += inp;
      totals.outputTokens += out;
      totals.totalTokens += inp + out;
      totals.costUsd = Number((totals.costUsd + cost).toFixed(8));
    }

    const byModel = Array.from(byModelMap.values()).sort(
      (a, b) => b.costUsd - a.costUsd || b.totalTokens - a.totalTokens,
    );

    return {
      memberId: memberId ?? null,
      range,
      totals,
      byModel,
    };
  }

  return {
    filePath,
    load,
    get,
    update,
    recordUsage,
    queryUsage,
    sanitizeStateSnapshot,
  };
}
