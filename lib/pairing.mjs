import crypto from "node:crypto";
import {
  computeSas,
  decodeInvite,
  encodeInvite,
  fingerprintFromPubKey,
  slotIdForHost,
  timingSafeEqualStr,
  verifySelfSignedEd25519Cert,
} from "./crypto.mjs";
import {
  addRemoteMagpieProvider,
  createMemberGatewayKey,
  removeMemberGatewayKey,
} from "./magpie-cli.mjs";
import { sanitizeStateSnapshot } from "./store.mjs";
import { FRAME } from "./wire.mjs";

const DEFAULT_INVITE_TTL_SEC = 300;
const MAX_INVITE_ATTEMPTS = 5;
const PAIR_FRAME_TIMEOUT_MS = 15_000;
const STATUS_POLL_INTERVAL_MS = 2_000;
const OUTCOME_TTL_MS = 5 * 60_000;

export class PairingError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "PairingError";
    this.status = status;
    this.code = code;
  }
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value ?? ""), "utf8").digest("hex");
}

function parseFrameJson(payload) {
  return JSON.parse(Buffer.from(payload).toString("utf8"));
}

function normalizeDeviceName(name, fallback = "新设备") {
  const clean = String(name ?? "")
    .replace(/[\r\n\0]/g, " ")
    .trim()
    .slice(0, 64);
  return clean || fallback;
}

/**
 * Derives a Magpie-compatible provider id (lowercase letters, digits, and single dashes only).
 */
export function makeProviderId(hostName, shareId) {
  const rawSlug = String(hostName || "host")
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 20)
    .replace(/-+$/g, "");
  const shortId =
    String(shareId || "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "")
      .slice(-8) || crypto.randomBytes(4).toString("hex");
  const candidate = `mshare-${rawSlug ? `${rawSlug}-` : ""}${shortId}`;
  return /^[a-z0-9][a-z0-9-]{0,63}$/.test(candidate)
    ? candidate
    : `mshare-${shortId}`;
}

function buildFallbackEndpointPayload(state, identity, mode) {
  const net = state?.network || {};
  if (mode === "self-relay") {
    return {
      relayAddr: String(net.relayAddr || "").trim(),
      slotId: slotIdForHost(identity.pubKeyHex),
      hasRelayToken: Boolean(net.relayToken),
    };
  }
  if (mode === "direct") {
    return {
      directHost: String(net.directHost || "").trim(),
      directPort: Number(net.directPort) || 3497,
    };
  }
  return {
    irohEndpointId: identity.irohEndpointId,
    relayUrl: String(net.irohRelayUrl || "").trim(),
  };
}

function validateClientIdentity(req, peerPubKeyHex, peerCertPem) {
  const claimedPub = typeof req?.clientPubKeyHex === "string" ? req.clientPubKeyHex.trim().toLowerCase() : "";
  const authPub = typeof peerPubKeyHex === "string" ? peerPubKeyHex.trim().toLowerCase() : "";
  if (!/^[0-9a-f]{64}$/.test(claimedPub) || !timingSafeEqualStr(authPub, claimedPub)) {
    return { ok: false, reason: "Client public key does not match authenticated peer" };
  }

  let certPem = typeof req?.clientCertPem === "string" ? req.clientCertPem.trim() : "";
  if (!certPem && typeof peerCertPem === "string") {
    certPem = peerCertPem.trim();
  }
  if (!certPem) {
    return { ok: false, reason: "Missing client self-signed Ed25519 certificate" };
  }

  try {
    const x509 = new crypto.X509Certificate(certPem);
    const verified = verifySelfSignedEd25519Cert(x509.raw, claimedPub);
    if (!verified.ok) {
      return { ok: false, reason: "Invalid client self-signed Ed25519 certificate" };
    }
    if (peerCertPem && typeof peerCertPem === "string") {
      const peerX509 = new crypto.X509Certificate(peerCertPem);
      const peerVerified = verifySelfSignedEd25519Cert(peerX509.raw, claimedPub);
      if (!peerVerified.ok) {
        return { ok: false, reason: "Transport peer certificate verification failed" };
      }
    }
    return { ok: true, clientPubKeyHex: claimedPub, clientCertPem: verified.certPem };
  } catch {
    return { ok: false, reason: "Malformed client certificate" };
  }
}

/**
 * Decodes and validates an `mshare1:` invite code without mutating state.
 */
export function parseInviteCode(code) {
  try {
    const decoded = decodeInvite(code, { checkExpiry: true });
    return {
      v: decoded.v,
      h: decoded.h,
      fp: fingerprintFromPubKey(decoded.pk),
      pk: decoded.pk,
      m: decoded.m,
      id: decoded.id,
      ep: decoded.ep,
      expiresAt: decoded.exp,
    };
  } catch (err) {
    throw new PairingError(400, err?.code || "invalid_invite", err?.message || "Invalid invite code");
  }
}

export function createPairingManager({
  store,
  identity,
  transportManager,
  receiverBridge,
  env = process.env,
  createKeyFn = createMemberGatewayKey,
  removeKeyFn = removeMemberGatewayKey,
  addProviderFn = addRemoteMagpieProvider,
  nowFn = () => Date.now(),
} = {}) {
  if (!store || !identity) {
    throw new Error("createPairingManager requires store and identity");
  }

  /** @type {Map<string, { channel: any, inviteId: string, clientPubKeyHex: string, close: Function }>} */
  const waitingPairChannels = new Map();
  /** @type {Map<string, { secretHash: string, clientPubKeyHex: string, payload: object, exp: number }>} */
  const pairOutcomes = new Map();

  let activeReceiverWatcher = null;
  let closed = false;

  function prunePairOutcomes() {
    const now = nowFn();
    for (const [k, v] of pairOutcomes.entries()) {
      if (v.exp <= now) pairOutcomes.delete(k);
    }
  }

  function registerWaitingChannel(pendingId, entry) {
    const prev = waitingPairChannels.get(pendingId);
    if (prev && prev.channel !== entry.channel) {
      try {
        prev.channel.close?.().catch(() => {});
      } catch {}
    }
    waitingPairChannels.set(pendingId, entry);
    entry.channel.onClose?.(() => {
      if (waitingPairChannels.get(pendingId)?.channel === entry.channel) {
        waitingPairChannels.delete(pendingId);
      }
    });
  }

  async function pushAndCloseWaiting(pendingId, payload) {
    const entry = waitingPairChannels.get(pendingId);
    if (!entry) return;
    waitingPairChannels.delete(pendingId);
    try {
      await entry.channel.sendFrame(FRAME.PAIR_STATUS, payload);
    } catch {
      // Receiver may reconnect via status poll fallback.
    }
    try {
      await entry.channel.close();
    } catch {}
  }

  async function createInvite() {
    const state = store.get();
    const mode = state.mode || "p2p";
    const ep =
      (await transportManager?.getHostEndpointPayload?.(mode)) ||
      buildFallbackEndpointPayload(state, identity, mode);

    if (mode === "self-relay" && !ep?.relayAddr) {
      throw new PairingError(400, "relay_not_configured", "请先配置并保存模式 2 自建盲中转地址");
    }
    if (mode === "direct" && !ep?.directHost) {
      throw new PairingError(400, "direct_host_not_configured", "请先配置并保存模式 3 公网地址或 DDNS");
    }

    const id = `inv-${crypto.randomBytes(6).toString("hex")}`;
    const s = crypto.randomBytes(16).toString("hex");
    const ttlSec = DEFAULT_INVITE_TTL_SEC;
    const now = nowFn();
    const exp = now + ttlSec * 1000;
    const hostName = state.hostName || "Simple Share";

    const code = encodeInvite({
      v: 1,
      m: mode,
      h: hostName,
      pk: identity.pubKeyHex,
      id,
      s,
      exp,
      ep,
    });

    await store.update((draft) => {
      draft.invites = (draft.invites || []).filter(
        (inv) => inv && !inv.revoked && inv.exp > now - 60_000,
      );
      draft.invites.push({
        id,
        m: mode,
        s,
        exp,
        ep,
        used: false,
        revoked: false,
        attempts: 0,
        createdAt: now,
      });
    });

    if (state.sharingEnabled) {
      await transportManager?.reconfigure?.();
    }

    return { id, code, mode, expiresAt: exp, ttlSec };
  }

  async function revokeInvite(id) {
    if (typeof id !== "string" || !id.trim()) {
      throw new PairingError(400, "invalid_invite_id", "Invite id is required");
    }
    let found = false;
    await store.update((draft) => {
      const inv = (draft.invites || []).find((x) => x && x.id === id);
      if (inv) {
        found = true;
        inv.revoked = true;
        inv.s = "";
      }
    });
    if (!found) {
      throw new PairingError(404, "invite_not_found", "Invite not found");
    }
    if (store.get().sharingEnabled) {
      await transportManager?.reconfigure?.();
    }
    return { ok: true, id };
  }

  async function handleIncomingPairChannel(channel, { peerPubKeyHex, peerCertPem } = {}) {
    if (!channel) return;
    let reqFrame;
    try {
      reqFrame = await channel.onceFrame(FRAME.PAIR_REQ, PAIR_FRAME_TIMEOUT_MS);
    } catch {
      await channel.close?.().catch(() => {});
      return;
    }

    let req;
    try {
      req = parseFrameJson(reqFrame.payload);
    } catch {
      await channel
        .sendFrame(FRAME.PAIR_STATUS, { status: "error", code: "bad_request", message: "Malformed PAIR_REQ" })
        .catch(() => {});
      await channel.close?.().catch(() => {});
      return;
    }

    const action = req?.action === "status" ? "status" : "apply";

    if (action === "status") {
      const claimedPub = typeof req?.clientPubKeyHex === "string" ? req.clientPubKeyHex.trim().toLowerCase() : "";
      const authPub = typeof peerPubKeyHex === "string" ? peerPubKeyHex.trim().toLowerCase() : "";
      if (!/^[0-9a-f]{64}$/.test(claimedPub) || !timingSafeEqualStr(authPub, claimedPub)) {
        await channel
          .sendFrame(FRAME.PAIR_STATUS, { status: "error", code: "invalid_client_identity", message: "Client identity mismatch" })
          .catch(() => {});
        await channel.close?.().catch(() => {});
        return;
      }

      const secretHash = sha256Hex(req?.inviteSecret);
      const state = store.get();
      const pend = (state.pending || []).find(
        (p) =>
          p &&
          p.inviteId === req?.inviteId &&
          timingSafeEqualStr(p.clientPubKeyHex, claimedPub) &&
          timingSafeEqualStr(p.secretHash, secretHash),
      );
      if (pend) {
        await channel
          .sendFrame(FRAME.PAIR_STATUS, {
            status: "pending",
            pendingId: pend.id,
            sas: pend.sas,
            hostName: state.hostName,
            hostFp: identity.fingerprint,
          })
          .catch(() => {});
        registerWaitingChannel(pend.id, {
          channel,
          inviteId: pend.inviteId,
          clientPubKeyHex: claimedPub,
        });
        return;
      }

      prunePairOutcomes();
      const outcome = pairOutcomes.get(String(req?.inviteId || ""));
      if (
        outcome &&
        timingSafeEqualStr(outcome.clientPubKeyHex, claimedPub) &&
        timingSafeEqualStr(outcome.secretHash, secretHash)
      ) {
        await channel.sendFrame(FRAME.PAIR_STATUS, outcome.payload).catch(() => {});
        await channel.close?.().catch(() => {});
        return;
      }

      await channel
        .sendFrame(FRAME.PAIR_STATUS, { status: "unknown", code: "pair_not_found" })
        .catch(() => {});
      await channel.close?.().catch(() => {});
      return;
    }

    const idCheck = validateClientIdentity(req, peerPubKeyHex, peerCertPem);
    if (!idCheck.ok) {
      await channel
        .sendFrame(FRAME.PAIR_STATUS, {
          status: "error",
          code: "invalid_client_identity",
          message: idCheck.reason,
        })
        .catch(() => {});
      await channel.close?.().catch(() => {});
      return;
    }

    let claimResult = { ok: false, code: "invite_invalid", message: "Invite is invalid" };
    await store.update((draft) => {
      if (!draft.sharingEnabled) {
        claimResult = { ok: false, code: "share_offline", message: "Host sharing is disabled" };
        return;
      }
      const inv = (draft.invites || []).find((i) => i && i.id === req?.inviteId);
      if (!inv || inv.revoked) {
        claimResult = { ok: false, code: "invite_invalid", message: "Invite not found or revoked" };
        return;
      }
      if (nowFn() > inv.exp) {
        inv.revoked = true;
        inv.s = "";
        claimResult = { ok: false, code: "invite_expired", message: "Invite code has expired" };
        return;
      }
      if (inv.used) {
        claimResult = { ok: false, code: "invite_already_used", message: "Invite code was already used" };
        return;
      }
      if ((inv.attempts || 0) >= MAX_INVITE_ATTEMPTS) {
        inv.revoked = true;
        inv.s = "";
        claimResult = { ok: false, code: "invite_locked", message: "Invite code burned after failed attempts" };
        return;
      }

      const providedSecret = typeof req?.inviteSecret === "string" ? req.inviteSecret : "";
      if (!inv.s || !timingSafeEqualStr(providedSecret, inv.s)) {
        inv.attempts = (inv.attempts || 0) + 1;
        if (inv.attempts >= MAX_INVITE_ATTEMPTS) {
          inv.revoked = true;
          inv.s = "";
        }
        claimResult = {
          ok: false,
          code: inv.revoked ? "invite_locked" : "invite_secret_mismatch",
          message: "Invite secret mismatch",
        };
        return;
      }

      // Single-use claim: compute SAS, hash secret for reconnect status check, and burn raw secret.
      const sas = computeSas(inv.s, identity.pubKeyHex, idCheck.clientPubKeyHex);
      const secretHash = sha256Hex(inv.s);
      inv.used = true;
      inv.s = "";

      const pendingId = `pend-${crypto.randomBytes(6).toString("hex")}`;
      const deviceName = normalizeDeviceName(req?.deviceName, "新设备");
      const pendingEntry = {
        id: pendingId,
        inviteId: inv.id,
        secretHash,
        name: deviceName,
        clientPubKeyHex: idCheck.clientPubKeyHex,
        clientCertPem: idCheck.clientCertPem,
        clientFp: fingerprintFromPubKey(idCheck.clientPubKeyHex),
        sas,
        mode: inv.m,
        requestedAt: nowFn(),
      };
      draft.pending.push(pendingEntry);

      claimResult = {
        ok: true,
        pendingId,
        inviteId: inv.id,
        sas,
        hostName: draft.hostName,
      };
    });

    if (!claimResult.ok) {
      await channel
        .sendFrame(FRAME.PAIR_STATUS, {
          status: "error",
          code: claimResult.code,
          message: claimResult.message,
        })
        .catch(() => {});
      await channel.close?.().catch(() => {});
      return;
    }

    await channel
      .sendFrame(FRAME.PAIR_STATUS, {
        status: "pending",
        pendingId: claimResult.pendingId,
        sas: claimResult.sas,
        hostName: claimResult.hostName,
        hostFp: identity.fingerprint,
      })
      .catch(() => {});

    registerWaitingChannel(claimResult.pendingId, {
      channel,
      inviteId: claimResult.inviteId,
      clientPubKeyHex: idCheck.clientPubKeyHex,
    });
  }

  async function approvePending(
    pendingId,
    { models, period = "day", costLimit = 3, tokenLimitWan = 100, concurrency = 2, note } = {},
  ) {
    const initial = store.get();
    const pendingItem = (initial.pending || []).find((p) => p && p.id === pendingId);
    if (!pendingItem) {
      throw new PairingError(404, "pending_not_found", "Pending application not found");
    }

    const cleanModels = Array.isArray(models)
      ? models.map((m) => String(m || "").trim()).filter(Boolean)
      : [];
    if (cleanModels.length === 0) {
      throw new PairingError(400, "models_required", "At least one allowed model must be selected");
    }

    const memberId = `m-${crypto.randomBytes(6).toString("hex")}`;
    const magpieKeyName = `ss-${memberId.slice(2, 10)}`;
    const memberName = normalizeDeviceName(note, pendingItem.name);

    const createdKey = await createKeyFn({
      name: magpieKeyName,
      models: cleanModels,
      period: period || "day",
      tokenLimitWan: Number(tokenLimitWan) || 0,
      costLimit: Number(costLimit) || 0,
      concurrency: Number(concurrency) || 2,
      quotas: Boolean(initial.visibility?.quotas),
      env,
    });

    let memberRecord;
    let updatedState;
    try {
      updatedState = await store.update((draft) => {
        const idx = (draft.pending || []).findIndex((p) => p && p.id === pendingId);
        if (idx === -1) {
          throw new PairingError(409, "pending_already_handled", "Pending application was already handled");
        }
        draft.pending.splice(idx, 1);

        const inv = (draft.invites || []).find((i) => i && i.id === pendingItem.inviteId);
        if (inv) {
          inv.used = true;
          inv.revoked = true;
          inv.s = "";
        }

        memberRecord = {
          id: memberId,
          name: memberName,
          clientFp: pendingItem.clientFp,
          clientPubKeyHex: pendingItem.clientPubKeyHex,
          clientCertPem: pendingItem.clientCertPem || "",
          magpieKeyId: createdKey.keyId,
          magpieKeyName: createdKey.keyName,
          magpieKeySecret: createdKey.keySecret,
          status: "active",
          joinedAt: nowFn(),
          lastUsedAt: null,
          period: period || "day",
          tokenLimitWan: Number(tokenLimitWan) || 0,
          costLimit: Number(costLimit) || 0,
          concurrency: Number(concurrency) || 2,
          models: cleanModels,
        };
        draft.members.push(memberRecord);
      });
    } catch (err) {
      await removeKeyFn({ keyId: createdKey.keyId, env }).catch(() => {});
      throw err;
    }

    // Reconfigure transport BEFORE notifying peer so API_ALPN already pins the new member cert/key.
    await transportManager?.reconfigure?.();

    const approvedPayload = {
      status: "approved",
      shareId: memberId,
      hostName: updatedState.hostName,
      hostFp: identity.fingerprint,
      hostPubKeyHex: identity.pubKeyHex,
      hostCertPem: identity.certPem,
      models: memberRecord.models,
      period: memberRecord.period,
      costLimit: memberRecord.costLimit,
      tokenLimitWan: memberRecord.tokenLimitWan,
      limitVisible: Boolean(updatedState.visibility?.limit),
    };

    prunePairOutcomes();
    pairOutcomes.set(pendingItem.inviteId, {
      secretHash: pendingItem.secretHash,
      clientPubKeyHex: pendingItem.clientPubKeyHex,
      payload: approvedPayload,
      exp: nowFn() + OUTCOME_TTL_MS,
    });

    await pushAndCloseWaiting(pendingId, approvedPayload);
    return sanitizeStateSnapshot(memberRecord);
  }

  async function rejectPending(pendingId) {
    let removed = null;
    await store.update((draft) => {
      const idx = (draft.pending || []).findIndex((p) => p && p.id === pendingId);
      if (idx === -1) {
        throw new PairingError(404, "pending_not_found", "Pending application not found");
      }
      [removed] = draft.pending.splice(idx, 1);
      const inv = (draft.invites || []).find((i) => i && i.id === removed.inviteId);
      if (inv) {
        inv.used = true;
        inv.revoked = true;
        inv.s = "";
      }
    });

    prunePairOutcomes();
    pairOutcomes.set(removed.inviteId, {
      secretHash: removed.secretHash,
      clientPubKeyHex: removed.clientPubKeyHex,
      payload: { status: "rejected" },
      exp: nowFn() + OUTCOME_TTL_MS,
    });

    await pushAndCloseWaiting(pendingId, { status: "rejected" });
    return { ok: true, id: pendingId };
  }

  async function finalizeApprovedShare(pendingRecord, msg) {
    const current = store.get();
    if (!current.receiverPending || current.receiverPending.id !== pendingRecord.id) {
      return null;
    }

    const shareId = typeof msg?.shareId === "string" && msg.shareId ? msg.shareId : `r-${crypto.randomBytes(6).toString("hex")}`;
    const hostName = msg?.hostName || pendingRecord.hostName;
    const providerId = makeProviderId(hostName, shareId);
    const bridgeToken = crypto.randomBytes(32).toString("hex");

    const shareRecord = {
      id: shareId,
      hostName,
      hostPubKeyHex: pendingRecord.hostPubKeyHex,
      hostCertPem: msg?.hostCertPem || pendingRecord.hostCertPem || "",
      hostFp: msg?.hostFp || pendingRecord.hostFp,
      mode: pendingRecord.mode,
      ep: pendingRecord.ep,
      providerId,
      bridgePort: 0,
      bridgeToken,
      status: "active",
      linkStatus: "已连接",
      models: Array.isArray(msg?.models) ? msg.models : [],
      period: msg?.period || "day",
      tokenLimitWan: Number(msg?.tokenLimitWan) || 0,
      costLimit: Number(msg?.costLimit) || 0,
      usedTokens: 0,
      usedCost: 0,
      limitVisible: msg?.limitVisible !== false,
      joinedAt: nowFn(),
    };

    if (receiverBridge?.startBridge) {
      const started = await receiverBridge.startBridge(shareRecord);
      shareRecord.bridgePort = started.port;
      const bridgeUrl = `http://127.0.0.1:${started.port}`;
      try {
        await addProviderFn({
          id: shareRecord.providerId,
          bridgeUrl,
          bridgeToken,
          env,
        });
      } catch (err) {
        shareRecord.providerSyncError = String(err?.message || err);
      }
    }

    await store.update((draft) => {
      if (draft.receiverPending?.id !== pendingRecord.id) return;
      draft.receiverPending = null;
      const existingIdx = (draft.received || []).findIndex((r) => r && r.id === shareRecord.id);
      if (existingIdx >= 0) {
        draft.received[existingIdx] = shareRecord;
      } else {
        draft.received.push(shareRecord);
      }
    });

    return sanitizeStateSnapshot(shareRecord);
  }

  function stopReceiverWatcher() {
    if (!activeReceiverWatcher) return;
    activeReceiverWatcher.stopped = true;
    if (activeReceiverWatcher.timer) clearTimeout(activeReceiverWatcher.timer);
    try {
      activeReceiverWatcher.conn?.close?.();
    } catch {}
    activeReceiverWatcher = null;
  }

  function watchPendingApproval(pendingRecord, inviteObj, initialConn = null) {
    stopReceiverWatcher();
    const watcher = {
      id: pendingRecord.id,
      stopped: false,
      timer: null,
      conn: initialConn,
    };
    activeReceiverWatcher = watcher;

    const stillPending = () =>
      !closed &&
      !watcher.stopped &&
      store.get().receiverPending?.id === pendingRecord.id;

    const handleStatusMessage = async (msg, conn) => {
      if (!stillPending()) {
        try { await conn?.close?.(); } catch {}
        return true;
      }
      if (msg?.status === "approved") {
        watcher.stopped = true;
        try { await conn?.close?.(); } catch {}
        await finalizeApprovedShare(pendingRecord, msg).catch(() => {});
        if (activeReceiverWatcher === watcher) activeReceiverWatcher = null;
        return true;
      }
      if (msg?.status === "rejected" || msg?.status === "unknown") {
        watcher.stopped = true;
        try { await conn?.close?.(); } catch {}
        await store.update((draft) => {
          if (draft.receiverPending?.id === pendingRecord.id) {
            draft.receiverPending = null;
          }
        }).catch(() => {});
        if (activeReceiverWatcher === watcher) activeReceiverWatcher = null;
        return true;
      }
      return false;
    };

    const scheduleReconnectPoll = (delayMs = STATUS_POLL_INTERVAL_MS) => {
      if (!stillPending()) return;
      watcher.timer = setTimeout(async () => {
        if (!stillPending()) return;
        let conn = null;
        try {
          conn = await transportManager.dialPair(inviteObj);
          if (!timingSafeEqualStr(conn.hostPubKeyHex, inviteObj.pk)) {
            await conn.close?.();
            scheduleReconnectPoll();
            return;
          }
          watcher.conn = conn;
          await conn.channel.sendFrame(FRAME.PAIR_REQ, {
            action: "status",
            inviteId: inviteObj.id,
            inviteSecret: inviteObj.s,
            clientPubKeyHex: identity.pubKeyHex,
            clientCertPem: identity.certPem,
          });
          const frame = await conn.channel.onceFrame(FRAME.PAIR_STATUS, PAIR_FRAME_TIMEOUT_MS);
          const msg = parseFrameJson(frame.payload);
          const terminal = await handleStatusMessage(msg, conn);
          if (!terminal) {
            // Keep channel open for instant push!
            listenOnChannel(conn);
          }
        } catch {
          try { await conn?.close?.(); } catch {}
          scheduleReconnectPoll();
        }
      }, delayMs);
    };

    const listenOnChannel = (conn) => {
      if (!conn?.channel) {
        scheduleReconnectPoll();
        return;
      }
      let handled = false;
      const offFrame = conn.channel.onFrame((frame) => {
        if (handled || frame.type !== FRAME.PAIR_STATUS) return;
        let msg;
        try {
          msg = parseFrameJson(frame.payload);
        } catch {
          return;
        }
        if (msg?.status === "approved" || msg?.status === "rejected" || msg?.status === "unknown") {
          handled = true;
          offFrame();
          offClose();
          handleStatusMessage(msg, conn);
        }
      });
      const offClose = conn.channel.onClose(() => {
        offFrame();
        if (!handled && stillPending()) {
          scheduleReconnectPoll(STATUS_POLL_INTERVAL_MS);
        }
      });
    };

    if (initialConn) {
      listenOnChannel(initialConn);
    } else {
      scheduleReconnectPoll(500);
    }
  }

  async function applyToInvite(code, deviceName) {
    let invite;
    try {
      invite = decodeInvite(code, { checkExpiry: true });
    } catch (err) {
      throw new PairingError(400, err?.code || "invalid_invite", err?.message || "Invalid invite code");
    }

    const devName = normalizeDeviceName(deviceName, store.get().hostName || "我的设备");
    const expectedSas = computeSas(invite.s, invite.pk, identity.pubKeyHex);

    stopReceiverWatcher();

    let conn;
    try {
      conn = await transportManager.dialPair(invite);
    } catch (err) {
      throw new PairingError(502, "pair_connect_failed", `无法连接对方节点：${err?.message || err}`);
    }

    if (!timingSafeEqualStr(String(conn?.hostPubKeyHex || "").toLowerCase(), invite.pk)) {
      await conn?.close?.().catch(() => {});
      throw new PairingError(403, "host_identity_mismatch", "对方公钥与邀请码不匹配，已拒绝连接");
    }

    try {
      await conn.channel.sendFrame(FRAME.PAIR_REQ, {
        action: "apply",
        inviteId: invite.id,
        inviteSecret: invite.s,
        deviceName: devName,
        clientPubKeyHex: identity.pubKeyHex,
        clientCertPem: identity.certPem,
      });

      const frame = await conn.channel.onceFrame(FRAME.PAIR_STATUS, PAIR_FRAME_TIMEOUT_MS);
      const msg = parseFrameJson(frame.payload);

      if (msg?.status === "error") {
        throw new PairingError(400, msg.code || "pair_rejected", msg.message || "Pair request failed");
      }
      if (msg?.status === "rejected") {
        throw new PairingError(403, "pair_rejected", "分享者拒绝了你的申请");
      }
      if (msg?.sas && !timingSafeEqualStr(String(msg.sas), expectedSas)) {
        throw new PairingError(403, "sas_mismatch", "配对码校验不一致，疑似中间人攻击");
      }

      const pendingRecord = {
        id: msg?.pendingId || invite.id,
        inviteId: invite.id,
        inviteSecret: invite.s,
        hostName: msg?.hostName || invite.h,
        hostPubKeyHex: invite.pk,
        hostCertPem: msg?.hostCertPem || conn.hostCertPem || "",
        hostFp: msg?.hostFp || fingerprintFromPubKey(invite.pk),
        mode: invite.m,
        ep: invite.ep,
        deviceName: devName,
        sas: expectedSas,
        requestedAt: nowFn(),
      };

      await store.update((draft) => {
        draft.receiverPending = pendingRecord;
      });

      if (msg?.status === "approved") {
        await conn.close?.().catch(() => {});
        const share = await finalizeApprovedShare(pendingRecord, msg);
        return { pending: null, approved: share };
      }

      watchPendingApproval(pendingRecord, invite, conn);
      return { pending: sanitizeStateSnapshot(pendingRecord) };
    } catch (err) {
      await conn?.close?.().catch(() => {});
      if (err instanceof PairingError) throw err;
      throw new PairingError(502, "pair_failed", err?.message || "Pair handshake failed");
    }
  }

  async function withdrawPending(pendingId) {
    stopReceiverWatcher();
    await store.update((draft) => {
      if (!draft.receiverPending) return;
      if (!pendingId || draft.receiverPending.id === pendingId) {
        draft.receiverPending = null;
      }
    });
    return { ok: true };
  }

  async function restoreReceiverWatcher() {
    const rp = store.get().receiverPending;
    if (!rp || !rp.inviteSecret || !rp.hostPubKeyHex) return;
    const inviteObj = {
      v: 1,
      m: rp.mode,
      h: rp.hostName,
      pk: rp.hostPubKeyHex,
      id: rp.inviteId,
      s: rp.inviteSecret,
      exp: Date.now() + 10 * 60_000,
      ep: rp.ep,
    };
    watchPendingApproval(rp, inviteObj, null);
  }

  async function close() {
    closed = true;
    stopReceiverWatcher();
    const pendingEntries = [...waitingPairChannels.values()];
    waitingPairChannels.clear();
    for (const entry of pendingEntries) {
      await entry.channel.close?.().catch(() => {});
    }
  }

  return {
    createInvite,
    revokeInvite,
    handleIncomingPairChannel,
    approvePending,
    rejectPending,
    parseInviteCode,
    applyToInvite,
    withdrawPending,
    restoreReceiverWatcher,
    close,
  };
}
