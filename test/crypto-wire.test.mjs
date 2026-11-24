import { afterEach, describe, expect, test } from "bun:test";
import crypto from "node:crypto";
import { EventEmitter } from "node:events";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import net from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import tls from "node:tls";

import {
  identityPath,
  irohDir,
  magpieConfigDir,
  pluginDataDir,
  statePath,
} from "../lib/paths.mjs";
import {
  computeSas,
  decodeInvite,
  encodeInvite,
  extractEd25519PubRawFromCertDer,
  fingerprintFromPubKey,
  irohIdFromPubKeyHex,
  loadOrCreateIdentity,
  pubKeyHexFromIrohId,
  slotIdForHost,
  timingSafeEqualStr,
  verifySelfSignedEd25519Cert,
} from "../lib/crypto.mjs";
import { createStore, sanitizeStateSnapshot } from "../lib/store.mjs";
import {
  FRAME,
  MAX_FRAME_PAYLOAD,
  createFrameDecoder,
  createFramedChannel,
  encodeFrame,
  sendHttpRequestOverChannel,
  serveHttpRequestOnChannel,
} from "../lib/wire.mjs";

const tempDirs = [];

async function makeTempDir(prefix = "mshare-test-") {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
});

function createDuplexPair() {
  const aData = new Set();
  const bData = new Set();
  const aClose = new Set();
  const bClose = new Set();
  let closed = false;

  const closeBoth = (err) => {
    if (closed) return;
    closed = true;
    for (const fn of aClose) fn(err);
    for (const fn of bClose) fn(err);
  };

  const a = {
    write(u8) {
      if (closed) throw new Error("closed");
      const copy = new Uint8Array(u8);
      queueMicrotask(() => {
        if (!closed) {
          for (const fn of bData) fn(copy);
        }
      });
    },
    onData(fn) {
      aData.add(fn);
      return () => aData.delete(fn);
    },
    onClose(fn) {
      aClose.add(fn);
      return () => aClose.delete(fn);
    },
    end() {
      closeBoth();
    },
    destroy(err) {
      closeBoth(err);
    },
  };

  const b = {
    write(u8) {
      if (closed) throw new Error("closed");
      const copy = new Uint8Array(u8);
      queueMicrotask(() => {
        if (!closed) {
          for (const fn of aData) fn(copy);
        }
      });
    },
    onData(fn) {
      bData.add(fn);
      return () => bData.delete(fn);
    },
    onClose(fn) {
      bClose.add(fn);
      return () => bClose.delete(fn);
    },
    end() {
      closeBoth();
    },
    destroy(err) {
      closeBoth(err);
    },
  };

  return [a, b];
}

describe("lib/paths.mjs", () => {
  test("resolves precedence MAGPIE_CONFIG_DIR -> XDG_CONFIG_HOME -> ~/.config/magpie", () => {
    const def = magpieConfigDir({});
    expect(def.endsWith(join(".config", "magpie"))).toBe(true);

    const xdg = magpieConfigDir({ XDG_CONFIG_HOME: "/tmp/xdg-root" });
    expect(xdg).toBe(join("/tmp/xdg-root", "magpie"));

    const explicit = magpieConfigDir({
      XDG_CONFIG_HOME: "/tmp/xdg-root",
      MAGPIE_CONFIG_DIR: "/tmp/custom-magpie",
    });
    expect(explicit).toBe("/tmp/custom-magpie");
  });

  test("resolves pluginDataDir and child files cleanly", () => {
    const env1 = { MAGPIE_CONFIG_DIR: "/tmp/cfg" };
    expect(pluginDataDir(env1)).toBe(join("/tmp/cfg", "magpie-simple-share"));
    expect(identityPath(env1)).toBe(join("/tmp/cfg", "magpie-simple-share", "identity.json"));
    expect(statePath(env1)).toBe(join("/tmp/cfg", "magpie-simple-share", "state.json"));
    expect(irohDir(env1)).toBe(join("/tmp/cfg", "magpie-simple-share", "iroh"));

    const env2 = {
      MAGPIE_CONFIG_DIR: "/tmp/cfg",
      MAGPIE_SIMPLE_SHARE_DATA: "/tmp/override-data",
    };
    expect(pluginDataDir(env2)).toBe("/tmp/override-data");
    expect(identityPath(env2)).toBe(join("/tmp/override-data", "identity.json"));
    expect(statePath(env2)).toBe(join("/tmp/override-data", "state.json"));
    expect(irohDir(env2)).toBe(join("/tmp/override-data", "iroh"));

    const env3 = {
      MAGPIE_SIMPLE_SHARE_DATA_DIR: "/tmp/override-data-2",
    };
    expect(pluginDataDir(env3)).toBe("/tmp/override-data-2");

    expect(magpieConfigDir({ HOME: "/Users/alice", USERPROFILE: "C:\\Users\\Alice" }, { platform: "darwin" })).toBe(
      join("/Users/alice", ".config", "magpie"),
    );
    expect(magpieConfigDir({ HOME: "/home/alice", USERPROFILE: "C:\\Users\\Alice" }, { platform: "linux" })).toBe(
      join("/home/alice", ".config", "magpie"),
    );
    expect(magpieConfigDir({ HOME: "/home/alice", USERPROFILE: "C:\\Users\\Alice" }, { platform: "win32" })).toBe(
      join("C:\\Users\\Alice", ".config", "magpie"),
    );
  });
});

describe("lib/crypto.mjs", () => {
  test("loadOrCreateIdentity creates deterministic Ed25519 identity and reloads identically", async () => {
    const dir = await makeTempDir();
    const idFile = join(dir, "nested", "identity.json");

    const id1 = await loadOrCreateIdentity(idFile);
    expect(id1.seedHex).toMatch(/^[0-9a-f]{64}$/);
    expect(id1.seed32).toBeInstanceOf(Uint8Array);
    expect(id1.seed32.length).toBe(32);
    expect(id1.pubKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(id1.pubRaw32).toBeInstanceOf(Uint8Array);
    expect(id1.pubRaw32.length).toBe(32);
    expect(Buffer.isBuffer(id1.certDer)).toBe(true);
    expect(id1.keyPem).toContain("BEGIN PRIVATE KEY");
    expect(id1.certPem).toContain("BEGIN CERTIFICATE");
    expect(id1.fingerprint).toMatch(/^ed25519:[0-9a-f]{4}·[0-9a-f]{4}·[0-9a-f]{4}·[0-9a-f]{4}$/);
    expect(id1.fingerprint).toBe(fingerprintFromPubKey(id1.pubRaw32));
    expect(id1.irohEndpointId).toBe(irohIdFromPubKeyHex(id1.pubKeyHex));
    expect(pubKeyHexFromIrohId(id1.irohEndpointId)).toBe(id1.pubKeyHex);

    const fileStats = await stat(idFile);
    const parentStats = await stat(dirname(idFile));
    if (process.platform !== "win32") {
      expect(fileStats.mode & 0o777).toBe(0o600);
      expect(parentStats.mode & 0o777).toBe(0o700);
    }

    const persisted = JSON.parse(await readFile(idFile, "utf8"));
    expect(persisted.version).toBe(1);
    expect(persisted.seedHex).toBe(id1.seedHex);
    expect(persisted.certPem).toBe(id1.certPem);
    expect(typeof persisted.createdAt).toBe("string");

    const id2 = await loadOrCreateIdentity(idFile);
    expect(id2.seedHex).toBe(id1.seedHex);
    expect(id2.pubKeyHex).toBe(id1.pubKeyHex);
    expect(id2.certPem).toBe(id1.certPem);
    expect(id2.certDer.equals(id1.certDer)).toBe(true);
    expect(id2.keyPem).toBe(id1.keyPem);
    expect(id2.fingerprint).toBe(id1.fingerprint);
    expect(id2.irohEndpointId).toBe(id1.irohEndpointId);
  });

  test("loadOrCreateIdentity handles concurrent first-boot callers without racing", async () => {
    const dir = await makeTempDir();
    const idFile = join(dir, "identity.json");
    const [a, b, c] = await Promise.all([
      loadOrCreateIdentity(idFile),
      loadOrCreateIdentity(idFile),
      loadOrCreateIdentity(idFile),
    ]);
    expect(a.seedHex).toBe(b.seedHex);
    expect(b.seedHex).toBe(c.seedHex);
    expect(a.certPem).toBe(b.certPem);
  });

  test("matches @number0/iroh SecretKey.fromBytes(seed32).public().toString() test vector", async () => {
    const dir = await makeTempDir();
    const idFile = join(dir, "iroh-vector-identity.json");
    // Known seed 0x01..0x20 verified against @number0/iroh@1.2.0 SecretKey.fromBytes(seed32).public().toString()
    const seedHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const expectedIrohId = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";

    await mkdir(dir, { recursive: true });
    await writeFile(
      idFile,
      JSON.stringify({ version: 1, seedHex, createdAt: new Date().toISOString() }),
      "utf8",
    );

    const loaded = await loadOrCreateIdentity(idFile);
    expect(loaded.pubKeyHex).toBe(expectedIrohId);
    expect(loaded.irohEndpointId).toBe(expectedIrohId);
  });

  test("extractEd25519PubRawFromCertDer and verifySelfSignedEd25519Cert pin correctly", async () => {
    const dir = await makeTempDir();
    const host = await loadOrCreateIdentity(join(dir, "host.json"));
    const other = await loadOrCreateIdentity(join(dir, "other.json"));

    const pubRaw = extractEd25519PubRawFromCertDer(host.certDer);
    expect(Buffer.isBuffer(pubRaw)).toBe(true);
    expect(pubRaw.length).toBe(32);
    expect(pubRaw.toString("hex")).toBe(host.pubKeyHex);

    const okRes = verifySelfSignedEd25519Cert(host.certDer, host.pubKeyHex);
    expect(okRes.ok).toBe(true);
    expect(okRes.pubKeyHex).toBe(host.pubKeyHex);
    expect(okRes.certPem).toBe(host.certPem);

    // Uppercase expected hex still matches
    expect(verifySelfSignedEd25519Cert(host.certDer, host.pubKeyHex.toUpperCase()).ok).toBe(true);

    // Wrong expected pubkey fails closed
    expect(verifySelfSignedEd25519Cert(host.certDer, other.pubKeyHex).ok).toBe(false);

    // Tampered signature byte fails verification
    const tampered = Buffer.from(host.certDer);
    tampered[tampered.length - 5] ^= 0xff;
    expect(verifySelfSignedEd25519Cert(tampered, host.pubKeyHex).ok).toBe(false);

    // Garbage DER fails safely
    expect(verifySelfSignedEd25519Cert(Buffer.from("not-der"), host.pubKeyHex).ok).toBe(false);
    expect(verifySelfSignedEd25519Cert(host.certDer, "bad-hex").ok).toBe(false);
  });

  test("generated Ed25519 certs work for real TLS 1.3 mTLS pinning and reject unpinned peers", async () => {
    const dir = await makeTempDir();
    const host = await loadOrCreateIdentity(join(dir, "host.json"));
    const alice = await loadOrCreateIdentity(join(dir, "alice.json"));
    const mallory = await loadOrCreateIdentity(join(dir, "mallory.json"));

    const accepted = [];
    const rejected = [];
    const server = tls.createServer(
      {
        key: host.keyPem,
        cert: host.certPem,
        ca: [alice.certPem],
        requestCert: true,
        rejectUnauthorized: true,
        minVersion: "TLSv1.3",
        ALPNProtocols: ["simple-share-api/1"],
      },
      (sock) => {
        const peer = sock.getPeerCertificate(true);
        const peerPub = extractEd25519PubRawFromCertDer(peer.raw).toString("hex");
        accepted.push(peerPub);
        sock.end(`OK:${peerPub}`);
      },
    );
    server.on("tlsClientError", (err) => rejected.push(err.code || err.message));

    await new Promise((res) => server.listen(0, "127.0.0.1", res));
    const { port } = server.address();

    const tryTls = (client, expectedHostCert) =>
      new Promise((resolve) => {
        const s = tls.connect({
          host: "127.0.0.1",
          port,
          key: client.keyPem,
          cert: client.certPem,
          ca: [expectedHostCert],
          rejectUnauthorized: true,
          checkServerIdentity: () => undefined,
          minVersion: "TLSv1.3",
          ALPNProtocols: ["simple-share-api/1"],
        });
        let text = "";
        let errCode = null;
        s.on("data", (d) => (text += d.toString("utf8")));
        s.on("error", (err) => {
          errCode = err.code || err.message;
        });
        s.on("close", () => resolve({ ok: errCode === null && text.length > 0, text, errCode, alpn: s.alpnProtocol }));
      });

    try {
      const rAlice = await tryTls(alice, host.certPem);
      expect(rAlice.ok).toBe(true);
      expect(rAlice.alpn).toBe("simple-share-api/1");
      expect(rAlice.text).toBe(`OK:${alice.pubKeyHex}`);

      const rMallory = await tryTls(mallory, host.certPem);
      expect(rMallory.ok).toBe(false);
      expect(rMallory.text).toBe("");

      const rWrongHostPin = await tryTls(alice, mallory.certPem);
      expect(rWrongHostPin.ok).toBe(false);
      expect(rWrongHostPin.text).toBe("");
      expect(rWrongHostPin.errCode).toBe("DEPTH_ZERO_SELF_SIGNED_CERT");

      expect(accepted).toEqual([alice.pubKeyHex]);
      expect(rejected).toContain("DEPTH_ZERO_SELF_SIGNED_CERT");
    } finally {
      server.close();
    }
  });

  test("encodeInvite and decodeInvite validate all fields and expiry", () => {
    const pk = "a".repeat(64);
    const futureExp = Date.now() + 300_000;
    const pastExp = Date.now() - 5_000;

    for (const mode of ["p2p", "self-relay", "direct"]) {
      const code = encodeInvite({
        v: 1,
        m: mode,
        h: "Host Machine",
        pk: pk.toUpperCase(),
        id: "inv-1",
        s: "0123456789abcdef0123456789abcdef",
        exp: futureExp,
        ep: { host: "127.0.0.1", port: 3497 },
      });
      expect(code.startsWith("mshare1:")).toBe(true);
      expect(code.includes("\n")).toBe(false);

      const decoded = decodeInvite(code, { checkExpiry: true });
      expect(decoded).toEqual({
        v: 1,
        m: mode,
        h: "Host Machine",
        pk,
        id: "inv-1",
        s: "0123456789abcdef0123456789abcdef",
        exp: futureExp,
        ep: { host: "127.0.0.1", port: 3497 },
      });
    }

    const expiredCode = encodeInvite({
      v: 1,
      m: "p2p",
      h: "Host",
      pk,
      id: "inv-exp",
      s: "abcdef12",
      exp: pastExp,
      ep: { irohId: pk },
    });
    expect(decodeInvite(expiredCode, { checkExpiry: false }).id).toBe("inv-exp");
    expect(() => decodeInvite(expiredCode, { checkExpiry: true })).toThrow(/expired/i);

    expect(() => decodeInvite("badprefix:abc")).toThrow();
    expect(() => decodeInvite("mshare1:!!!")).toThrow();
    expect(() =>
      encodeInvite({ v: 2, m: "p2p", h: "H", pk, id: "1", s: "sec", exp: futureExp, ep: {} }),
    ).toThrow();
    expect(() =>
      encodeInvite({ v: 1, m: "tun", h: "H", pk, id: "1", s: "sec", exp: futureExp, ep: {} }),
    ).toThrow();
    expect(() =>
      encodeInvite({ v: 1, m: "p2p", h: "", pk, id: "1", s: "sec", exp: futureExp, ep: {} }),
    ).toThrow();
    expect(() =>
      encodeInvite({ v: 1, m: "p2p", h: "H", pk: "short", id: "1", s: "sec", exp: futureExp, ep: {} }),
    ).toThrow();
    expect(() =>
      encodeInvite({ v: 1, m: "p2p", h: "H", pk, id: "1", s: "sec", exp: futureExp, ep: null }),
    ).toThrow();
  });

  test("computeSas, slotIdForHost, and timingSafeEqualStr", () => {
    const secret = "00112233445566778899aabbccddeeff";
    const hostPk = "11".repeat(32);
    const clientPk = "22".repeat(32);

    const sas1 = computeSas(secret, hostPk, clientPk);
    const sas2 = computeSas(secret.toUpperCase(), hostPk.toUpperCase(), clientPk.toUpperCase());
    expect(sas1).toMatch(/^\d{4}$/);
    expect(sas1).toBe(sas2);

    expect(computeSas(secret, clientPk, hostPk)).not.toBe(sas1);
    expect(computeSas("ff".repeat(16), hostPk, clientPk)).not.toBe(sas1);

    const slot = slotIdForHost(hostPk.toUpperCase());
    const expectedSlot = crypto
      .createHash("sha256")
      .update(`mshare-slot:${hostPk}`)
      .digest("hex");
    expect(slot).toBe(expectedSlot);
    expect(slot).toMatch(/^[0-9a-f]{64}$/);

    expect(timingSafeEqualStr("token-abc", "token-abc")).toBe(true);
    expect(timingSafeEqualStr("token-abc", "token-abd")).toBe(false);
    expect(timingSafeEqualStr("token-abc", "token-abcd")).toBe(false);
    expect(timingSafeEqualStr("token-abc", null)).toBe(false);
  });
});

describe("lib/store.mjs", () => {
  test("initializes schema defaults, serializes concurrent updates, and survives reload", async () => {
    const dir = await makeTempDir();
    const file = join(dir, "state.json");
    const store = createStore(file);

    const initial = await store.load();
    expect(initial.version).toBe(1);
    expect(initial.sharingEnabled).toBe(false);
    expect(initial.tosAcknowledged).toBe(false);
    expect(initial.mode).toBe("p2p");
    expect(initial.network).toEqual({
      irohRelayUrl: "",
      relayAddr: "",
      relayToken: "",
      directHost: "",
      directPort: 3497,
    });
    expect(initial.visibility).toEqual({ limit: true, quotas: false });
    expect(initial.invites).toEqual([]);
    expect(initial.pending).toEqual([]);
    expect(initial.members).toEqual([]);
    expect(initial.usageEvents).toEqual([]);
    expect(initial.receiverPending).toBeNull();
    expect(initial.received).toEqual([]);

    // 25 concurrent updates must all persist without lost updates
    await Promise.all(
      Array.from({ length: 25 }, (_, i) =>
        store.update((draft) => {
          draft.invites.push({ id: `inv-${i}`, s: `secret-${i}` });
          if (i === 0) draft.sharingEnabled = true;
        }),
      ),
    );

    const snap = store.get();
    expect(snap.invites.length).toBe(25);
    expect(snap.sharingEnabled).toBe(true);
    // Mutating snapshot must not mutate store internal state
    snap.invites.push({ id: "mutated" });
    expect(store.get().invites.length).toBe(25);

    const reloaded = await createStore(file).load();
    expect(reloaded.invites.length).toBe(25);
    expect(reloaded.sharingEnabled).toBe(true);
  });

  test("recordUsage, queryUsage ranges, and sanitizeStateSnapshot", async () => {
    const dir = await makeTempDir();
    const file = join(dir, "state.json");
    const store = createStore(file);
    await store.load();

    await store.update((s) => {
      s.invites.push({ id: "i1", s: "top-secret-invite", secret: "also-secret" });
      s.pending.push({ id: "p1", name: "Cousin", inviteSecret: "sec-pending", s: "sec-s" });
      s.members.push({
        id: "m1",
        name: "Mom",
        magpieKeyName: "ss-mom",
        magpieKeySecret: "sk-magpie-key-secret",
      });
      s.receiverPending = { id: "rp1", inviteSecret: "rp-sec", s: "rp-s" };
      s.received.push({ id: "r1", hostName: "Host", bridgeToken: "br-secret" });
    });

    const now = Date.now();
    const DAY = 24 * 60 * 60 * 1000;
    await store.recordUsage("m1", "deepseek/chat", {
      turns: 2,
      inputTokens: 1000,
      outputTokens: 500,
      costUsd: 0.12,
      ts: now - 1 * DAY,
      prompt: "MUST NOT BE STORED",
      response: "MUST NOT BE STORED",
    });
    await store.recordUsage("m1", "deepseek/reasoner", {
      turns: 1,
      inputTokens: 2000,
      outputTokens: 800,
      costUsd: 0.25,
      ts: now - 15 * DAY,
    });
    await store.recordUsage("m1", "deepseek/chat", {
      turns: 3,
      inputTokens: 3000,
      outputTokens: 900,
      costUsd: 0.3,
      ts: now - 45 * DAY,
    });
    await store.recordUsage("m2", "claude/sonnet", {
      turns: 1,
      inputTokens: 500,
      outputTokens: 200,
      costUsd: 0.1,
      ts: now - 1 * DAY,
    });

    // Verify no prompts/responses stored on disk
    const rawDisk = await readFile(file, "utf8");
    expect(rawDisk).not.toContain("MUST NOT BE STORED");

    const q7d = store.queryUsage("m1", "7d");
    expect(q7d.totals).toEqual({
      turns: 2,
      inputTokens: 1000,
      outputTokens: 500,
      totalTokens: 1500,
      costUsd: 0.12,
    });

    const qMonth = store.queryUsage("m1", "month");
    expect(qMonth.totals.turns).toBe(3);
    expect(qMonth.totals.inputTokens).toBe(3000);
    expect(qMonth.byModel.length).toBe(2);

    const qAll = store.queryUsage("m1", "all");
    expect(qAll.totals.turns).toBe(6);
    expect(qAll.totals.inputTokens).toBe(6000);

    const qEverything = store.queryUsage(null, "7d");
    expect(qEverything.totals.turns).toBe(3);

    const safe = sanitizeStateSnapshot(store.get());
    expect(safe.invites[0].s).toBeUndefined();
    expect(safe.invites[0].secret).toBeUndefined();
    expect(safe.pending[0].inviteSecret).toBeUndefined();
    expect(safe.pending[0].s).toBeUndefined();
    expect(safe.members[0].magpieKeyName).toBe("ss-mom");
    expect(safe.members[0].magpieKeySecret).toBeUndefined();
    expect(safe.receiverPending.inviteSecret).toBeUndefined();
    expect(safe.receiverPending.s).toBeUndefined();
    expect(safe.received[0].bridgeToken).toBeUndefined();
    // Original state still retains secrets in store
    expect(store.get().members[0].magpieKeySecret).toBe("sk-magpie-key-secret");
  });
});

describe("lib/wire.mjs", () => {
  test("FRAME constants and encodeFrame/createFrameDecoder fragmentation & max size", () => {
    expect(FRAME).toEqual({
      REQ_HEAD: 0x01,
      REQ_BODY: 0x02,
      REQ_END: 0x03,
      RES_HEAD: 0x04,
      RES_BODY: 0x05,
      RES_END: 0x06,
      STREAM_ABORT: 0x07,
      PAIR_REQ: 0x10,
      PAIR_STATUS: 0x11,
      PING: 0x20,
      PONG: 0x21,
    });

    const f1 = encodeFrame(FRAME.PING, { ts: 123 });
    const f2 = encodeFrame(FRAME.PONG, Buffer.from("pong"));
    const f3 = encodeFrame(FRAME.REQ_END, null);
    expect(f1[0]).toBe(FRAME.PING);
    expect(f1.readUInt32BE(1)).toBe(f1.length - 5);
    expect(f3.length).toBe(5);

    const combined = Buffer.concat([f1, f2, f3]);
    const decoded = [];
    const errors = [];
    const decode = createFrameDecoder(
      (f) => decoded.push(f),
      (e) => errors.push(e),
    );

    // Feed 1 byte at a time
    for (let i = 0; i < combined.length; i += 1) {
      decode(combined.subarray(i, i + 1));
    }
    expect(errors.length).toBe(0);
    expect(decoded.length).toBe(3);
    expect(decoded[0].type).toBe(FRAME.PING);
    expect(JSON.parse(decoded[0].payload.toString("utf8"))).toEqual({ ts: 123 });
    expect(decoded[1].type).toBe(FRAME.PONG);
    expect(decoded[1].payload.toString("utf8")).toBe("pong");
    expect(decoded[2].type).toBe(FRAME.REQ_END);
    expect(decoded[2].payload.length).toBe(0);

    // Enforce 4 MiB limit
    expect(() => encodeFrame(FRAME.REQ_BODY, Buffer.alloc(MAX_FRAME_PAYLOAD + 1))).toThrow(
      /4 MiB/i,
    );
    const badHeader = Buffer.alloc(5);
    badHeader[0] = FRAME.REQ_BODY;
    badHeader.writeUInt32BE(MAX_FRAME_PAYLOAD + 1, 1);
    const badErrors = [];
    const badDecode = createFrameDecoder(() => {}, (err) => badErrors.push(err));
    badDecode(badHeader);
    expect(badErrors.length).toBe(1);
    expect(badErrors[0].code).toBe("frame_too_large");
  });

  test("createFramedChannel works over net.Socket, tls.TLSSocket, WebSocket, and Iroh BiStream adapters", async () => {
    // 1. net.Socket
    const tcpServer = net.createServer();
    await new Promise((res) => tcpServer.listen(0, "127.0.0.1", res));
    const tcpPort = tcpServer.address().port;
    const serverSockPromise = new Promise((res) => tcpServer.once("connection", res));
    const clientSock = net.connect(tcpPort, "127.0.0.1");
    const serverSock = await serverSockPromise;

    const cNet = createFramedChannel(clientSock);
    const sNet = createFramedChannel(serverSock);
    sNet.onFrame((f) => {
      if (f.type === FRAME.PING) sNet.sendFrame(FRAME.PONG, { echo: true });
    });
    const pongWait = cNet.onceFrame(FRAME.PONG);
    await cNet.sendFrame(FRAME.PING, { hello: "tcp" });
    const pong = await pongWait;
    expect(JSON.parse(pong.payload.toString("utf8"))).toEqual({ echo: true });
    await cNet.close();
    await sNet.close();
    tcpServer.close();

    // 2. tls.TLSSocket
    const dir = await makeTempDir();
    const host = await loadOrCreateIdentity(join(dir, "host.json"));
    const client = await loadOrCreateIdentity(join(dir, "client.json"));
    const tlsServer = tls.createServer({
      key: host.keyPem,
      cert: host.certPem,
      ca: [client.certPem],
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: "TLSv1.3",
    });
    await new Promise((res) => tlsServer.listen(0, "127.0.0.1", res));
    const tlsPort = tlsServer.address().port;
    const serverTlsPromise = new Promise((res) => tlsServer.once("secureConnection", res));
    const clientTls = tls.connect({
      host: "127.0.0.1",
      port: tlsPort,
      key: client.keyPem,
      cert: client.certPem,
      ca: [host.certPem],
      rejectUnauthorized: true,
      checkServerIdentity: () => undefined,
      minVersion: "TLSv1.3",
    });
    const serverTls = await serverTlsPromise;
    const cTls = createFramedChannel(clientTls);
    const sTls = createFramedChannel(serverTls);
    const pairPromise = sTls.onceFrame((f) => f.type === FRAME.PAIR_REQ);
    await cTls.sendFrame(FRAME.PAIR_REQ, { pk: client.pubKeyHex });
    const pairFrame = await pairPromise;
    expect(JSON.parse(pairFrame.payload.toString("utf8")).pk).toBe(client.pubKeyHex);
    await cTls.close();
    await sTls.close();
    tlsServer.close();

    // 3. WebSocket adapter (EventEmitter ws-style pair)
    class MockWs extends EventEmitter {
      constructor() {
        super();
        this.readyState = 1;
        this.peer = null;
      }
      send(data) {
        queueMicrotask(() => this.peer?.emit("message", Buffer.from(data)));
      }
      close() {
        this.readyState = 3;
        this.emit("close");
        this.peer?.emit("close");
      }
    }
    const wsA = new MockWs();
    const wsB = new MockWs();
    wsA.peer = wsB;
    wsB.peer = wsA;
    const cWs = createFramedChannel(wsA);
    const sWs = createFramedChannel(wsB);
    const wsWait = sWs.onceFrame(FRAME.PAIR_STATUS);
    await cWs.sendFrame(FRAME.PAIR_STATUS, { approved: true });
    expect(JSON.parse((await wsWait).payload.toString("utf8"))).toEqual({ approved: true });
    await cWs.close();

    // 4. Real Bun WebSocket (DOM addEventListener API)
    let serverWsChan = null;
    const wsServer = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req, srv) {
        if (srv.upgrade(req)) return undefined;
        return new Response("upgrade required", { status: 400 });
      },
      websocket: {
        open(ws) {
          const dataHandlers = new Set();
          const closeHandlers = new Set();
          ws._handlers = { dataHandlers, closeHandlers };
          serverWsChan = createFramedChannel({
            write: (u8) => ws.send(u8),
            onData: (fn) => {
              dataHandlers.add(fn);
              return () => dataHandlers.delete(fn);
            },
            onClose: (fn) => {
              closeHandlers.add(fn);
              return () => closeHandlers.delete(fn);
            },
            end: () => ws.close(),
            destroy: () => ws.close(),
          });
          serverWsChan.onFrame((f) => {
            if (f.type === FRAME.PING) serverWsChan.sendFrame(FRAME.PONG, { via: "bun-ws" });
          });
        },
        message(ws, message) {
          const u8 =
            typeof message === "string" ? Buffer.from(message, "utf8") : new Uint8Array(message);
          for (const fn of ws._handlers.dataHandlers) fn(u8);
        },
        close(ws) {
          for (const fn of ws._handlers.closeHandlers) fn();
        },
      },
    });
    const rawWs = new WebSocket(`ws://127.0.0.1:${wsServer.port}`);
    await new Promise((res, rej) => {
      rawWs.addEventListener("open", res, { once: true });
      rawWs.addEventListener("error", rej, { once: true });
    });
    const clientRealWs = createFramedChannel(rawWs);
    const realWsPong = clientRealWs.onceFrame(FRAME.PONG);
    await clientRealWs.sendFrame(FRAME.PING, { hello: "ws" });
    expect(JSON.parse((await realWsPong).payload.toString("utf8"))).toEqual({ via: "bun-ws" });
    await clientRealWs.close();
    wsServer.stop(true);

    // 5. Iroh BiStream adapter
    function makeBiPair() {
      const qAtoB = [];
      const qBtoA = [];
      const waitAtoB = [];
      const waitBtoA = [];
      let closedA = false;
      let closedB = false;

      const makeSide = (outQ, outWait, getOutClosed, inQ, inWait, setInClosed, getInClosed) => ({
        send: {
          async writeAll(arr) {
            expect(Array.isArray(arr)).toBe(true);
            outQ.push(arr.slice());
            if (outWait.length > 0) outWait.shift()();
          },
          async finish() {
            setInClosed();
            while (outWait.length > 0) outWait.shift()();
          },
          async reset() {
            setInClosed();
            while (outWait.length > 0) outWait.shift()();
          },
        },
        recv: {
          async read(limit) {
            while (inQ.length === 0 && !getInClosed()) {
              await new Promise((r) => inWait.push(r));
            }
            if (inQ.length === 0) return [];
            const next = inQ.shift();
            return next.slice(0, limit);
          },
          async stop() {
            setInClosed();
          },
        },
      });

      const sideA = makeSide(
        qAtoB,
        waitAtoB,
        () => closedA,
        qBtoA,
        waitBtoA,
        () => {
          closedA = true;
        },
        () => closedB,
      );
      const sideB = makeSide(
        qBtoA,
        waitBtoA,
        () => closedB,
        qAtoB,
        waitAtoB,
        () => {
          closedB = true;
        },
        () => closedA,
      );
      return [sideA, sideB];
    }

    const [biA, biB] = makeBiPair();
    const cIroh = createFramedChannel(biA);
    const sIroh = createFramedChannel(biB);
    const irohWait = sIroh.onceFrame(FRAME.PING);
    await cIroh.sendFrame(FRAME.PING, "iroh-ok");
    expect((await irohWait).payload.toString("utf8")).toBe("iroh-ok");
    await cIroh.close();
  });

  test("unbuffered SSE streaming, concurrent multiplexed streams, large bodies, and AbortSignal", async () => {
    const [dClient, dServer] = createDuplexPair();
    const clientChan = createFramedChannel(dClient);
    const serverChan = createFramedChannel(dServer);

    const serverAborts = new Set();
    let slowRelease;
    const slowGate = new Promise((r) => {
      slowRelease = r;
    });

    let pushSseChunk;
    const sseReady = new Promise((r) => {
      pushSseChunk = r;
    });

    const stopServer = serveHttpRequestOnChannel(serverChan, async (req, { signal }) => {
      if (req.path === "/sse") {
        let ctrl;
        const body = new ReadableStream({
          start(c) {
            ctrl = c;
          },
        });
        pushSseChunk(ctrl);
        return {
          status: 200,
          headers: { "content-type": "text/event-stream" },
          body,
        };
      }

      if (req.path === "/slow-abort") {
        signal.addEventListener(
          "abort",
          () => {
            serverAborts.add(req.id);
          },
          { once: true },
        );
        const body = new ReadableStream({
          async start(c) {
            c.enqueue(Buffer.from("first-chunk\n"));
            await slowGate;
            if (!signal.aborted) {
              c.enqueue(Buffer.from("should-not-arrive\n"));
              c.close();
            }
          },
        });
        return { status: 200, headers: {}, body };
      }

      if (req.path === "/echo-large") {
        const raw = Buffer.from(await new Response(req.body).arrayBuffer());
        return {
          status: 201,
          headers: { "x-len": String(raw.length) },
          body: raw,
        };
      }

      return { status: 404, headers: {}, body: "not found" };
    });

    // 1. Unbuffered SSE: first chunk arrives BEFORE second chunk or stream end is pushed
    const sseRes = await sendHttpRequestOverChannel(clientChan, {
      id: "sse-1",
      method: "POST",
      path: "/sse",
      headers: { accept: "text/event-stream" },
    });
    expect(sseRes.status).toBe(200);
    const sseCtrl = await sseReady;
    const sseReader = sseRes.body.getReader();

    sseCtrl.enqueue(Buffer.from("data: one\n\n"));
    const first = await sseReader.read();
    expect(first.done).toBe(false);
    expect(Buffer.from(first.value).toString("utf8")).toBe("data: one\n\n");

    // 2. While SSE stream AND slow stream are open concurrently, run a multiplexed large request!
    const slowAc = new AbortController();
    const slowRes = await sendHttpRequestOverChannel(clientChan, {
      id: "slow-1",
      method: "GET",
      path: "/slow-abort",
      signal: slowAc.signal,
    });
    const slowReader = slowRes.body.getReader();
    const slowFirst = await slowReader.read();
    expect(Buffer.from(slowFirst.value).toString("utf8")).toBe("first-chunk\n");

    const bigPayload = crypto.randomBytes(1_500_000); // > 1 MiB, tests auto-chunking
    const bigRes = await sendHttpRequestOverChannel(clientChan, {
      id: "big-1",
      method: "POST",
      path: "/echo-large",
      bodyStream: bigPayload,
    });
    expect(bigRes.status).toBe(201);
    expect(bigRes.headers["x-len"]).toBe(String(bigPayload.length));
    const echoedBig = Buffer.from(await new Response(bigRes.body).arrayBuffer());
    expect(echoedBig.equals(bigPayload)).toBe(true);

    // 3. Abort slow stream via AbortSignal and verify server received STREAM_ABORT
    slowAc.abort();
    await expect(slowReader.read()).rejects.toThrow();
    await new Promise((r) => setTimeout(r, 20));
    expect(serverAborts.has("slow-1")).toBe(true);

    // 4. Unrelated concurrent SSE stream continues delivering chunks cleanly
    sseCtrl.enqueue(Buffer.from("data: two\n\n"));
    sseCtrl.close();
    const second = await sseReader.read();
    expect(Buffer.from(second.value).toString("utf8")).toBe("data: two\n\n");
    const done = await sseReader.read();
    expect(done.done).toBe(true);

    // 5. Handler error returns 500 JSON cleanly
    const errRes = await sendHttpRequestOverChannel(clientChan, {
      id: "err-1",
      method: "GET",
      path: "/missing-route",
    });
    expect(errRes.status).toBe(404);
    expect(await new Response(errRes.body).text()).toBe("not found");

    slowRelease();
    stopServer();
    await clientChan.close();
  });

  test("store rejects corrupt JSON instead of wiping state, and handler exceptions return 500", async () => {
    const dir = await makeTempDir();
    const badFile = join(dir, "corrupt-state.json");
    await writeFile(badFile, "{not valid json", "utf8");
    await expect(createStore(badFile).load()).rejects.toThrow();

    const [dClient, dServer] = createDuplexPair();
    const c = createFramedChannel(dClient);
    const s = createFramedChannel(dServer);
    const stop = serveHttpRequestOnChannel(s, async () => {
      throw new Error("boom-before-head");
    });
    const res = await sendHttpRequestOverChannel(c, { method: "GET", path: "/boom" });
    expect(res.status).toBe(500);
    const body = JSON.parse(await new Response(res.body).text());
    expect(body.error).toBe("boom-before-head");
    stop();
    await c.close();
  });
});
