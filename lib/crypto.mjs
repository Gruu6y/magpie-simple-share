import crypto from "node:crypto";
import { chmod, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const VALID_MODES = new Set(["p2p", "self-relay", "direct"]);
const TIMING_HMAC_KEY = crypto.randomBytes(32);

const identityLocks = new Map();

// --- Minimal DER/ASN.1 encoder for self-signed Ed25519 X.509 v3 certificates ---

function derLen(len) {
  if (len < 0x80) return Buffer.from([len]);
  const bytes = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derTag(tag, content) {
  const buf = Buffer.isBuffer(content) ? content : Buffer.concat(content);
  return Buffer.concat([Buffer.from([tag]), derLen(buf.length), buf]);
}

const derSeq = (items) => derTag(0x30, items);
const derSet = (items) => derTag(0x31, items);

function derInt(buf) {
  let b = Buffer.from(buf);
  while (b.length > 1 && b[0] === 0 && (b[1] & 0x80) === 0) {
    b = b.subarray(1);
  }
  if (b[0] & 0x80) {
    b = Buffer.concat([Buffer.from([0x00]), b]);
  }
  return derTag(0x02, b);
}

const derBitStr = (buf) => derTag(0x03, Buffer.concat([Buffer.from([0x00]), buf]));

function derOid(oid) {
  const parts = oid.split(".").map(Number);
  const out = [parts[0] * 40 + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    const enc = [v & 0x7f];
    while (v >= 0x80) {
      v >>= 7;
      enc.unshift((v & 0x7f) | 0x80);
    }
    out.push(...enc);
  }
  return derTag(0x06, Buffer.from(out));
}

const derUtf8 = (s) => derTag(0x0c, Buffer.from(s, "utf8"));
const derGenTime = (d) =>
  derTag(0x18, Buffer.from(d.toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z", "ascii"));
const derCtx = (n, buf) => derTag(0xa0 | n, buf);

function derToCertPem(certDer) {
  const b64 = Buffer.from(certDer).toString("base64").match(/.{1,64}/g).join("\n");
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}

function normalizePubKeyHex(pubKeyHex) {
  if (typeof pubKeyHex !== "string" || !/^[0-9a-fA-F]{64}$/.test(pubKeyHex)) {
    throw new Error("Invalid Ed25519 public key hex (expected 64 hex chars)");
  }
  return pubKeyHex.toLowerCase();
}

function parseHex32(hex, label) {
  if (typeof hex !== "string" || !/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`Invalid ${label}: expected 64 hex characters`);
  }
  return Buffer.from(hex.toLowerCase(), "hex");
}

function deriveKeyMaterialFromSeed(seed32) {
  if (!(seed32 instanceof Uint8Array) || seed32.byteLength !== 32) {
    throw new Error("Ed25519 seed must be exactly 32 bytes");
  }
  const seedBuf = Buffer.from(seed32);
  const pkcs8Der = Buffer.concat([ED25519_PKCS8_PREFIX, seedBuf]);
  const privateKey = crypto.createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });
  const publicKey = crypto.createPublicKey(privateKey);
  const spki = publicKey.export({ type: "spki", format: "der" });
  if (spki.length !== 44 || !spki.subarray(0, 12).equals(ED25519_SPKI_PREFIX)) {
    throw new Error("Unexpected Ed25519 SPKI structure");
  }
  const pubRaw32 = Buffer.from(spki.subarray(12, 44));
  const pubKeyHex = pubRaw32.toString("hex");
  const keyPem = privateKey.export({ type: "pkcs8", format: "pem" });
  return { seedBuf, privateKey, spki, pubRaw32, pubKeyHex, keyPem };
}

function buildSelfSignedEd25519Cert(privateKey, spki, pubKeyHex) {
  const algId = derSeq([derOid("1.3.101.112")]);
  const cn = `simple-share-${pubKeyHex.slice(0, 16)}`;
  const name = derSeq([derSet([derSeq([derOid("2.5.4.3"), derUtf8(cn)])])]);
  const serialBytes = crypto.randomBytes(16);
  serialBytes[0] = (serialBytes[0] & 0x7f) | 0x01; // positive non-zero serial
  const serial = derInt(serialBytes);
  const now = new Date(Date.now() - 60_000);
  const far = new Date(Date.now() + 10 * 365 * 24 * 3600 * 1000);
  const validity = derSeq([derGenTime(now), derGenTime(far)]);
  // BasicConstraints CA:TRUE so tls ca:[peerCert] pins self-signed peer certs without external CA.
  const bcExt = derSeq([
    derOid("2.5.29.19"),
    Buffer.from([0x01, 0x01, 0xff]),
    derTag(0x04, derSeq([Buffer.from([0x01, 0x01, 0xff])])),
  ]);
  const extensions = derCtx(3, derSeq([bcExt]));

  const tbs = derSeq([
    derCtx(0, derInt(Buffer.from([2]))),
    serial,
    algId,
    name,
    validity,
    name,
    spki,
    extensions,
  ]);
  const sig = crypto.sign(null, tbs, privateKey);
  const certDer = derSeq([tbs, algId, derBitStr(sig)]);
  const certPem = derToCertPem(certDer);
  return { certDer, certPem };
}

/**
 * Compute human-readable Ed25519 fingerprint "ed25519:xxxx·xxxx·xxxx·xxxx"
 * from a 32-byte public key or 64-char hex string.
 */
export function fingerprintFromPubKey(pubRawOrHex) {
  const raw =
    typeof pubRawOrHex === "string"
      ? parseHex32(pubRawOrHex, "public key")
      : Buffer.from(pubRawOrHex);
  if (raw.length !== 32) {
    throw new Error("Public key must be 32 bytes");
  }
  const h = crypto.createHash("sha256").update(raw).digest("hex").slice(0, 16);
  return `ed25519:${h.slice(0, 4)}·${h.slice(4, 8)}·${h.slice(8, 12)}·${h.slice(12, 16)}`;
}

/**
 * Constant-time string comparison safe against different lengths.
 */
export function timingSafeEqualStr(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  const ha = crypto.createHmac("sha256", TIMING_HMAC_KEY).update(ba).digest();
  const hb = crypto.createHmac("sha256", TIMING_HMAC_KEY).update(bb).digest();
  return crypto.timingSafeEqual(ha, hb) && ba.length === bb.length;
}

/**
 * Convert a 64-char Ed25519 pubKeyHex to @number0/iroh EndpointId string.
 * Verified against @number0/iroh@1.2.0 (iroh 1.0.0): EndpointId.toString() is 64-char lowercase hex.
 */
export function irohIdFromPubKeyHex(pubKeyHex) {
  return normalizePubKeyHex(pubKeyHex);
}

/**
 * Convert an @number0/iroh EndpointId string back to normalized 64-char Ed25519 pubKeyHex.
 */
export function pubKeyHexFromIrohId(irohId) {
  if (typeof irohId !== "string" || !/^[0-9a-fA-F]{64}$/.test(irohId.trim())) {
    throw new Error("Invalid iroh EndpointId (expected 64-char hex)");
  }
  return irohId.trim().toLowerCase();
}

/**
 * Extract raw 32-byte Ed25519 public key from a DER-encoded X.509 certificate.
 */
export function extractEd25519PubRawFromCertDer(certDer) {
  if (!(certDer instanceof Uint8Array) || certDer.byteLength === 0) {
    throw new Error("certDer must be a non-empty Buffer or Uint8Array");
  }
  const x509 = new crypto.X509Certificate(Buffer.from(certDer));
  if (x509.publicKey.asymmetricKeyType !== "ed25519") {
    throw new Error(`Expected ed25519 certificate key, got ${x509.publicKey.asymmetricKeyType}`);
  }
  const spki = x509.publicKey.export({ type: "spki", format: "der" });
  if (spki.length !== 44 || !spki.subarray(0, 12).equals(ED25519_SPKI_PREFIX)) {
    throw new Error("Unexpected Ed25519 SPKI DER encoding in certificate");
  }
  return Buffer.from(spki.subarray(12, 44));
}

/**
 * Verify a self-signed Ed25519 X.509 DER certificate and pin its public key
 * against expectedPubKeyHex using timingSafeEqual.
 */
export function verifySelfSignedEd25519Cert(certDer, expectedPubKeyHex) {
  try {
    if (typeof expectedPubKeyHex !== "string" || !/^[0-9a-fA-F]{64}$/.test(expectedPubKeyHex)) {
      return { ok: false, pubKeyHex: null, certPem: null };
    }
    const expectedRaw = Buffer.from(expectedPubKeyHex.toLowerCase(), "hex");
    const derBuf = Buffer.from(certDer);
    const x509 = new crypto.X509Certificate(derBuf);
    if (x509.publicKey.asymmetricKeyType !== "ed25519") {
      return { ok: false, pubKeyHex: null, certPem: null };
    }
    const pubRaw = extractEd25519PubRawFromCertDer(x509.raw);
    const pubKeyHex = pubRaw.toString("hex");
    if (!x509.verify(x509.publicKey)) {
      return { ok: false, pubKeyHex, certPem: null };
    }
    const now = Date.now();
    if (now < x509.validFromDate.getTime() || now > x509.validToDate.getTime()) {
      return { ok: false, pubKeyHex, certPem: null };
    }
    if (!crypto.timingSafeEqual(pubRaw, expectedRaw)) {
      return { ok: false, pubKeyHex, certPem: null };
    }
    return {
      ok: true,
      pubKeyHex,
      certPem: derToCertPem(x509.raw),
    };
  } catch {
    return { ok: false, pubKeyHex: null, certPem: null };
  }
}

async function atomicWriteFile600(filePath, content) {
  const dir = dirname(filePath);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const resolvedDir = resolve(dir);
  if (resolvedDir !== resolve(tmpdir()) && resolvedDir !== "/tmp" && resolvedDir !== "/private/tmp") {
    await chmod(dir, 0o700).catch(() => {});
  }
  const tmpPath = `${filePath}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  try {
    await writeFile(tmpPath, content, { encoding: "utf8", mode: 0o600 });
    await chmod(tmpPath, 0o600).catch(() => {});
    await rename(tmpPath, filePath);
    await chmod(filePath, 0o600).catch(() => {});
  } catch (err) {
    await rm(tmpPath, { force: true }).catch(() => {});
    throw err;
  }
}

async function loadOrCreateIdentityUnlocked(filePath) {
  let parsed = null;
  try {
    const raw = await readFile(filePath, "utf8");
    parsed = JSON.parse(raw);
  } catch (err) {
    if (err?.code !== "ENOENT") {
      throw err;
    }
  }

  if (parsed !== null) {
    if (parsed?.version !== 1 || typeof parsed.seedHex !== "string") {
      throw new Error(`Invalid identity file format at ${filePath}`);
    }
    const seedBuf = parseHex32(parsed.seedHex, "identity seedHex");
    const seedHex = seedBuf.toString("hex");
    const { privateKey, spki, pubRaw32, pubKeyHex, keyPem } = deriveKeyMaterialFromSeed(seedBuf);

    let certPem = typeof parsed.certPem === "string" ? parsed.certPem : "";
    let certDer = null;
    if (certPem) {
      try {
        const x509 = new crypto.X509Certificate(certPem);
        const check = verifySelfSignedEd25519Cert(x509.raw, pubKeyHex);
        if (check.ok) {
          certDer = Buffer.from(x509.raw);
          certPem = check.certPem;
        }
      } catch {
        certDer = null;
      }
    }

    if (!certDer) {
      const rebuilt = buildSelfSignedEd25519Cert(privateKey, spki, pubKeyHex);
      certDer = rebuilt.certDer;
      certPem = rebuilt.certPem;
      await atomicWriteFile600(
        filePath,
        JSON.stringify(
          {
            version: 1,
            seedHex,
            certPem,
            createdAt: parsed.createdAt || new Date().toISOString(),
          },
          null,
          2,
        ) + "\n",
      );
    }

    return {
      seedHex,
      seed32: new Uint8Array(seedBuf),
      pubKeyHex,
      pubRaw32: new Uint8Array(pubRaw32),
      fingerprint: fingerprintFromPubKey(pubRaw32),
      keyPem,
      certPem,
      certDer,
      irohEndpointId: irohIdFromPubKeyHex(pubKeyHex),
    };
  }

  const seedBuf = crypto.randomBytes(32);
  const seedHex = seedBuf.toString("hex");
  const { privateKey, spki, pubRaw32, pubKeyHex, keyPem } = deriveKeyMaterialFromSeed(seedBuf);
  const { certDer, certPem } = buildSelfSignedEd25519Cert(privateKey, spki, pubKeyHex);
  const record = {
    version: 1,
    seedHex,
    certPem,
    createdAt: new Date().toISOString(),
  };
  await atomicWriteFile600(filePath, JSON.stringify(record, null, 2) + "\n");

  return {
    seedHex,
    seed32: new Uint8Array(seedBuf),
    pubKeyHex,
    pubRaw32: new Uint8Array(pubRaw32),
    fingerprint: fingerprintFromPubKey(pubRaw32),
    keyPem,
    certPem,
    certDer,
    irohEndpointId: irohIdFromPubKeyHex(pubKeyHex),
  };
}

/**
 * Load an existing Ed25519 identity from disk or atomically create and persist
 * a new one (0o600 permissions) so restarts reload identically.
 */
export function loadOrCreateIdentity(filePath) {
  if (typeof filePath !== "string" || !filePath) {
    return Promise.reject(new Error("identity filePath is required"));
  }
  const key = resolve(filePath);
  const prev = identityLocks.get(key) ?? Promise.resolve();
  const next = prev.catch(() => {}).then(() => loadOrCreateIdentityUnlocked(filePath));
  identityLocks.set(key, next);
  next.finally(() => {
    if (identityLocks.get(key) === next) {
      identityLocks.delete(key);
    }
  });
  return next;
}

function validateInvitePayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("Invite payload must be an object");
  }
  const v = payload.v === undefined ? 1 : payload.v;
  if (v !== 1) {
    throw new Error(`Unsupported invite version: ${String(v)}`);
  }
  const { m, h, pk, id, s, exp, ep } = payload;
  if (!VALID_MODES.has(m)) {
    throw new Error(`Invalid invite mode: ${String(m)}`);
  }
  if (typeof h !== "string" || h.trim().length === 0) {
    throw new Error("Invite field 'h' (hostName) must be a non-empty string");
  }
  const normalizedPk = normalizePubKeyHex(pk);
  if (typeof id !== "string" || id.trim().length === 0) {
    throw new Error("Invite field 'id' must be a non-empty string");
  }
  if (typeof s !== "string" || s.length === 0) {
    throw new Error("Invite field 's' (secret) must be a non-empty string");
  }
  if (typeof exp !== "number" || !Number.isFinite(exp) || exp <= 0) {
    throw new Error("Invite field 'exp' must be a positive finite timestamp");
  }
  const validEp =
    ep !== null &&
    ep !== undefined &&
    ((typeof ep === "object" && !Array.isArray(ep)) || (typeof ep === "string" && ep.length > 0));
  if (!validEp) {
    throw new Error("Invite field 'ep' (endpoint) is required");
  }
  return {
    v: 1,
    m,
    h,
    pk: normalizedPk,
    id,
    s,
    exp,
    ep,
  };
}

/**
 * Encode an invite object into compact single-line "mshare1:<b64u>" string.
 */
export function encodeInvite(payload) {
  const clean = validateInvitePayload(payload);
  const b64u = Buffer.from(JSON.stringify(clean), "utf8").toString("base64url");
  return `mshare1:${b64u}`;
}

const INVITE_CODE_RE = /^mshare1:[A-Za-z0-9_-]+$/;
const INVITE_SNIPPET_RE = /mshare1(?::|%3[aA])([^\s&"'`<>()[\]{}「」【】（）《》“”‘’、,，。;；]*)/g;

function safeDecodeUriComponent(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new Error("Invalid percent-encoded invite code");
  }
}

/**
 * Extract and strictly validate an "mshare1:<b64u>" invite code from raw code,
 * full share URL (#mshare1:...), local handoff URL (#invite=mshare1:... or %3A),
 * or pasted text snippet.
 */
export function extractInviteCode(input) {
  if (typeof input !== "string") {
    throw new Error("Invite code must be a string");
  }
  const trimmed = input.trim();
  if (!trimmed) {
    throw new Error("Invite code is empty");
  }

  if (trimmed.startsWith("mshare1:") && !/\s/.test(trimmed)) {
    if (!INVITE_CODE_RE.test(trimmed)) {
      throw new Error("Invalid base64url invite encoding");
    }
    return trimmed;
  }

  if (/^mshare1%3a/i.test(trimmed) && !/\s/.test(trimmed)) {
    const decoded = safeDecodeUriComponent(trimmed);
    if (!INVITE_CODE_RE.test(decoded)) {
      throw new Error("Invalid base64url invite encoding");
    }
    return decoded;
  }

  if (/^https?:\/\//i.test(trimmed) && !/\s/.test(trimmed)) {
    let parsed;
    try {
      parsed = new URL(trimmed);
    } catch {
      throw new Error("Invalid invite URL");
    }
    const rawHash = (parsed.hash || "").replace(/^#/, "");
    if (!rawHash) {
      throw new Error("Invite URL is missing #mshare1: fragment");
    }
    let candidate = "";
    for (const part of rawHash.split("&")) {
      if (part.startsWith("invite=")) {
        candidate = safeDecodeUriComponent(part.slice("invite=".length));
        break;
      }
    }
    if (!candidate) {
      candidate = safeDecodeUriComponent(rawHash);
    }
    if (!INVITE_CODE_RE.test(candidate)) {
      throw new Error("Invalid invite code in URL fragment");
    }
    return candidate;
  }

  let sawPrefix = false;
  for (const match of trimmed.matchAll(INVITE_SNIPPET_RE)) {
    sawPrefix = true;
    const rawPayload = match[1] || "";
    if (!rawPayload) continue;
    const decodedPayload = rawPayload.includes("%") ? safeDecodeUriComponent(rawPayload) : rawPayload;
    const candidate = `mshare1:${decodedPayload}`;
    if (INVITE_CODE_RE.test(candidate)) {
      return candidate;
    }
  }

  if (sawPrefix) {
    throw new Error("Invalid base64url invite encoding");
  }
  throw new Error("Invalid invite prefix (expected mshare1:)");
}

/**
 * Decode and validate an "mshare1:<b64u>" invite code or share URL.
 */
export function decodeInvite(code, { checkExpiry = false } = {}) {
  const normalized = extractInviteCode(code);
  const b64u = normalized.slice("mshare1:".length);
  let parsed;
  try {
    const jsonStr = Buffer.from(b64u, "base64url").toString("utf8");
    parsed = JSON.parse(jsonStr);
  } catch (err) {
    throw new Error(`Malformed invite JSON: ${err.message}`);
  }
  if (parsed?.v !== 1) {
    throw new Error(`Unsupported invite version: ${String(parsed?.v)}`);
  }
  const clean = validateInvitePayload(parsed);
  if (checkExpiry && Date.now() > clean.exp) {
    const err = new Error("Invite code has expired");
    err.code = "invite_expired";
    throw err;
  }
  return clean;
}

/**
 * Compute 4-digit zero-padded Short Authentication String (SAS) 0000..9999
 * using HMAC-SHA256 over host and client Ed25519 public keys.
 */
export function computeSas(inviteSecretHex, hostPubKeyHex, clientPubKeyHex) {
  if (typeof inviteSecretHex !== "string" || inviteSecretHex.length === 0) {
    throw new Error("inviteSecretHex must be a non-empty string");
  }
  const hostBuf = parseHex32(hostPubKeyHex, "hostPubKeyHex");
  const clientBuf = parseHex32(clientPubKeyHex, "clientPubKeyHex");
  const keyBuf =
    /^[0-9a-fA-F]+$/.test(inviteSecretHex) && inviteSecretHex.length % 2 === 0
      ? Buffer.from(inviteSecretHex.toLowerCase(), "hex")
      : Buffer.from(inviteSecretHex, "utf8");

  const mac = crypto
    .createHmac("sha256", keyBuf)
    .update("mshare-sas-v1:")
    .update(hostBuf)
    .update(clientBuf)
    .digest();
  const code = mac.readUInt32BE(0) % 10000;
  return String(code).padStart(4, "0");
}

/**
 * Derive blind-relay anonymous slotId from host's Ed25519 public key hex.
 */
export function slotIdForHost(hostPubKeyHex) {
  const normalized = normalizePubKeyHex(hostPubKeyHex);
  return crypto.createHash("sha256").update(`mshare-slot:${normalized}`, "utf8").digest("hex");
}
