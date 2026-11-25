import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { parseCliArgs, runCli } from "../bin/simple-share.mjs";
import {
  decodeInvite,
  encodeInvite,
  extractInviteCode,
  loadOrCreateIdentity,
} from "../lib/crypto.mjs";
import { createPairingManager, PairingError, parseInviteCode } from "../lib/pairing.mjs";
import { startServer, TOKEN_HEADER } from "../lib/server.mjs";
import { createDefaultState, createStore, normalizeShareBaseUrl, sanitizeStateSnapshot } from "../lib/store.mjs";

const cleanups = [];
const tempDirs = [];

function makeTempDir(prefix = "ss-invcore-") {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  while (cleanups.length > 0) {
    const fn = cleanups.pop();
    try {
      await fn();
    } catch {}
  }
  while (tempDirs.length > 0) {
    try {
      rmSync(tempDirs.pop(), { recursive: true, force: true });
    } catch {}
  }
});

function createMockInviteCardMod() {
  const renderCalls = [];
  const buildUrlCalls = [];
  return {
    renderCalls,
    buildUrlCalls,
    buildShareUrl({ shareBaseUrl = "", mode = "", relayAddr = "", inviteCode = "" } = {}) {
      buildUrlCalls.push({ shareBaseUrl, mode, relayAddr, inviteCode });
      const base = String(shareBaseUrl || "").trim().replace(/\/+$/, "");
      if (base) {
        return inviteCode ? `${base}/#${inviteCode}` : base;
      }
      if (mode === "self-relay" && relayAddr) {
        const clean = String(relayAddr).trim().replace(/^wss?:\/\//i, "").replace(/\/.*$/, "");
        const proto = /^wss:\/\//i.test(String(relayAddr).trim()) ? "https" : "http";
        return inviteCode ? `${proto}://${clean}/join/#${inviteCode}` : `${proto}://${clean}/join`;
      }
      return "";
    },
    makeInviteCardFilename(hostName = "") {
      const safe = String(hostName || "host")
        .replace(/[\r\n\0/\\:*?"<>|]/g, "-")
        .trim() || "host";
      return `simple-share-${safe}.html`;
    },
    renderInviteJoinHtml(opts = {}) {
      renderCalls.push(opts);
      return `<!doctype html><html><head><title>Invite Card</title></head><body><h1>${opts.hostName}</h1><code>${opts.inviteCode}</code><p>${opts.endpointHint}</p><p>port:${opts.port}</p></body></html>`;
    },
  };
}

function runCliCapture(argv, opts = {}) {
  const out = [];
  const err = [];
  return runCli(argv, {
    ...opts,
    stdout: { write: (s) => out.push(s) },
    stderr: { write: (s) => err.push(s) },
  }).then((exitCode) => ({ exitCode, stdout: out.join(""), stderr: err.join("") }));
}

describe("lib/crypto.mjs extractInviteCode & decodeInvite URL support", () => {
  const samplePayload = {
    v: 1,
    m: "p2p",
    h: "Alice Studio",
    pk: "a".repeat(64),
    id: "inv-test01",
    s: "0123456789abcdef0123456789abcdef",
    exp: Date.now() + 600_000,
    ep: { irohEndpointId: "a".repeat(64), relayUrl: "" },
  };
  const rawCode = encodeInvite(samplePayload);

  test("extracts raw code, full share URLs, local handoff URLs, percent-encoded codes, and pasted snippets", () => {
    expect(extractInviteCode(rawCode)).toBe(rawCode);
    expect(extractInviteCode(`  ${rawCode}\n`)).toBe(rawCode);
    expect(extractInviteCode(`https://share.example.com/join/#${rawCode}`)).toBe(rawCode);
    expect(extractInviteCode(`http://1.2.3.4:3499/join/#${rawCode}`)).toBe(rawCode);
    expect(extractInviteCode(`http://[::1]:3499/join/#${rawCode}`)).toBe(rawCode);
    expect(extractInviteCode(`http://127.0.0.1:3494/#invite=${rawCode}`)).toBe(rawCode);
    expect(extractInviteCode(`http://127.0.0.1:3494/#invite=${encodeURIComponent(rawCode)}`)).toBe(rawCode);
    expect(
      extractInviteCode(`http://127.0.0.1:3494/#tab=received&invite=${encodeURIComponent(rawCode)}&src=card`),
    ).toBe(rawCode);
    expect(extractInviteCode(encodeURIComponent(rawCode))).toBe(rawCode);
    expect(
      extractInviteCode(`来用我的模型吧：https://share.example.com/join/#${rawCode}（30分钟有效）`),
    ).toBe(rawCode);
    expect(
      extractInviteCode(`请复制以 mshare1: 开头的邀请码：「${rawCode}」`),
    ).toBe(rawCode);
    expect(
      extractInviteCode(`本地打开 http://127.0.0.1:3494/#invite=${encodeURIComponent(rawCode)} 即可连接`),
    ).toBe(rawCode);
  });

  test("decodeInvite and parseInviteCode seamlessly accept full share and handoff URLs", () => {
    const shareUrl = `https://share.example.com/join/#${rawCode}`;
    const handoffUrl = `http://127.0.0.1:3494/#invite=${encodeURIComponent(rawCode)}`;

    expect(decodeInvite(shareUrl, { checkExpiry: true })).toEqual(samplePayload);
    expect(decodeInvite(handoffUrl, { checkExpiry: true })).toEqual(samplePayload);

    const parsed = parseInviteCode(shareUrl);
    expect(parsed.id).toBe(samplePayload.id);
    expect(parsed.h).toBe(samplePayload.h);
    expect(parsed.m).toBe(samplePayload.m);
    expect(parsed.pk).toBe(samplePayload.pk);
    expect(parsed.expiresAt).toBe(samplePayload.exp);

    const expiredCode = encodeInvite({ ...samplePayload, exp: Date.now() - 1_000 });
    expect(() => decodeInvite(`https://share.example.com/join/#${expiredCode}`, { checkExpiry: true })).toThrow(
      /expired/i,
    );
  });

  test("rejects invalid, empty, or malformed invite strings and URLs strictly", () => {
    for (const bad of [
      null,
      undefined,
      123,
      "",
      "   ",
      "badprefix:abc",
      "MSHARE1:eyJ2IjoxfQ",
      "mshare1:",
      "mshare1:!!!",
      "mshare1:abc+def/==",
      `${rawCode}!`,
      "https://share.example.com/join/",
      "https://share.example.com/join/#notaninvite",
      "https://share.example.com/join/#mshare1:bad!chars",
      "http://127.0.0.1:3494/#invite=badprefix:abc",
      "http://127.0.0.1:3494/#invite=mshare1%3A!!!",
      "mshare1%3A%E0%A4%A",
      "snippet with mshare1:bad!token here",
    ]) {
      expect(() => extractInviteCode(bad)).toThrow();
    }
    expect(() => parseInviteCode("https://share.example.com/join/")).toThrow(PairingError);
  });
});

describe("lib/store.mjs normalizeShareBaseUrl & network.shareBaseUrl schema", () => {
  test("validates, normalizes, and rejects invalid shareBaseUrl values", () => {
    expect(normalizeShareBaseUrl("")).toBe("");
    expect(normalizeShareBaseUrl("   ")).toBe("");
    expect(normalizeShareBaseUrl(null)).toBe("");
    expect(normalizeShareBaseUrl(undefined)).toBe("");

    expect(normalizeShareBaseUrl("https://share.example.com/join")).toBe("https://share.example.com/join");
    expect(normalizeShareBaseUrl("https://share.example.com/join///")).toBe("https://share.example.com/join");
    expect(normalizeShareBaseUrl("https://share.example.com/")).toBe("https://share.example.com");
    expect(normalizeShareBaseUrl("http://1.2.3.4:3499/join/")).toBe("http://1.2.3.4:3499/join");
    expect(normalizeShareBaseUrl("http://[::1]:3499/join/")).toBe("http://[::1]:3499/join");

    const tooLong = `https://example.com/${"a".repeat(250)}`;
    for (const bad of [
      123,
      {},
      "share.example.com/join",
      "javascript:alert(1)",
      "file:///etc/passwd",
      "ws://1.2.3.4:3499/join",
      "https://user:pass@share.example.com/join",
      "https://user@share.example.com/join",
      "https://@share.example.com/join",
      "https://share.example.com/join?foo=1",
      "https://share.example.com/join?",
      "https://share.example.com/join#hash",
      "https://share.example.com/join#",
      "https://share.example.com/join extra",
      "https://share.example.com/join\n",
      "https://share.example.com/join\x00",
      tooLong,
    ]) {
      expect(() => normalizeShareBaseUrl(bad)).toThrow();
    }
  });

  test("createDefaultState and store.load normalize network.shareBaseUrl safely", async () => {
    const def = createDefaultState();
    expect(def.network.shareBaseUrl).toBe("");

    const dir = makeTempDir("ss-store-");
    const stFile = join(dir, "state.json");
    const store = createStore(stFile);
    await store.load();
    await store.update((draft) => {
      draft.network.shareBaseUrl = "https://cn.example.com/join///";
    });
    expect(store.get().network.shareBaseUrl).toBe("https://cn.example.com/join");

    // Corrupted on-disk shareBaseUrl falls back cleanly to "" on reload
    await Bun.write(
      stFile,
      JSON.stringify({
        version: 1,
        network: { shareBaseUrl: "javascript:alert(1)" },
      }),
    );
    const reloaded = await createStore(stFile).load();
    expect(reloaded.network.shareBaseUrl).toBe("");
  });
});

describe("lib/pairing.mjs configurable TTL & getInviteForCard", () => {
  test("supports TTL presets and bounds (60..86400) and rejects invalid TTLs", async () => {
    const dir = makeTempDir("ss-pair-ttl-");
    const identity = await loadOrCreateIdentity(join(dir, "identity.json"));
    const store = createStore(join(dir, "state.json"));
    await store.load();

    let now = 1_700_000_000_000;
    const pairing = createPairingManager({
      store,
      identity,
      nowFn: () => now,
    });

    const defInv = await pairing.createInvite();
    expect(defInv.ttlSec).toBe(300);
    expect(defInv.expiresAt).toBe(now + 300_000);

    for (const ttlSec of [60, 300, 1800, 7200, 86400]) {
      const inv = await pairing.createInvite({ ttlSec });
      expect(inv.ttlSec).toBe(ttlSec);
      expect(inv.expiresAt).toBe(now + ttlSec * 1000);
      const decoded = decodeInvite(inv.code, { checkExpiry: false });
      expect(decoded.exp).toBe(now + ttlSec * 1000);
    }

    for (const badTtl of [59, 86401, 0, -10, 300.5, Number.NaN, Number.POSITIVE_INFINITY, "", "abc", null, true, {}]) {
      let caught = null;
      try {
        await pairing.createInvite({ ttlSec: badTtl });
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(PairingError);
      expect(caught.status).toBe(400);
      expect(caught.code).toBe("invalid_ttl");
    }

    await pairing.close();
  });

  test("getInviteForCard reconstructs active invite without exposing secret in sanitized state, and rejects inactive invites", async () => {
    const dir = makeTempDir("ss-pair-card-");
    const identity = await loadOrCreateIdentity(join(dir, "identity.json"));
    const store = createStore(join(dir, "state.json"));
    await store.load();
    await store.update((d) => {
      d.hostName = "My Studio";
    });

    let now = 1_700_000_000_000;
    const pairing = createPairingManager({
      store,
      identity,
      nowFn: () => now,
    });

    const inv1 = await pairing.createInvite({ ttlSec: 1800 });
    const card = pairing.getInviteForCard(inv1.id);
    expect(card.id).toBe(inv1.id);
    expect(card.code).toBe(inv1.code);
    expect(card.mode).toBe("p2p");
    expect(card.exp).toBe(inv1.expiresAt);
    expect(card.expiresAt).toBe(inv1.expiresAt);
    expect(card.ttlSec).toBe(1800);
    expect(card.hostName).toBe("My Studio");
    expect(card.hostFp).toBe(identity.fingerprint);

    // Verify sanitizeStateSnapshot still strips invite secret `s` and never contains `code`
    const rawInv = store.get().invites.find((i) => i.id === inv1.id);
    expect(typeof rawInv.s).toBe("string");
    expect(rawInv.s.length).toBeGreaterThan(0);
    const sanitized = sanitizeStateSnapshot(store.get());
    const sanitizedText = JSON.stringify(sanitized);
    expect(sanitizedText).not.toContain(rawInv.s);
    expect(sanitizedText).not.toContain(inv1.code);
    expect(sanitized.invites[0].s).toBeUndefined();

    // Missing / empty id
    expect(() => pairing.getInviteForCard("")).toThrow(PairingError);
    try {
      pairing.getInviteForCard("inv-missing");
      throw new Error("should throw");
    } catch (err) {
      expect(err).toBeInstanceOf(PairingError);
      expect(err.status).toBe(404);
      expect(err.code).toBe("invite_not_found");
    }

    // Revoked invite -> 410
    await pairing.revokeInvite(inv1.id);
    try {
      pairing.getInviteForCard(inv1.id);
      throw new Error("should throw");
    } catch (err) {
      expect(err).toBeInstanceOf(PairingError);
      expect(err.status).toBe(410);
      expect(err.code).toBe("invite_revoked");
    }

    // Used invite -> 410
    const inv2 = await pairing.createInvite({ ttlSec: 600 });
    await store.update((d) => {
      const target = d.invites.find((x) => x.id === inv2.id);
      target.used = true;
      target.s = "";
    });
    try {
      pairing.getInviteForCard(inv2.id);
      throw new Error("should throw");
    } catch (err) {
      expect(err).toBeInstanceOf(PairingError);
      expect(err.status).toBe(410);
      expect(err.code).toBe("invite_already_used");
    }

    // Expired invite -> 410
    const inv3 = await pairing.createInvite({ ttlSec: 60 });
    now += 61_000;
    try {
      pairing.getInviteForCard(inv3.id);
      throw new Error("should throw");
    } catch (err) {
      expect(err).toBeInstanceOf(PairingError);
      expect(err.status).toBe(410);
      expect(err.code).toBe("invite_expired");
    }

    await pairing.close();
  });
});

describe("lib/server.mjs invite TTL, shareBaseUrl, and /api/host/invites/:id/card endpoints", () => {
  test("POST /api/host/share-base-url, POST /api/network/mode, POST /api/host/invites, and GET /api/host/invites/:id/card", async () => {
    const dir = makeTempDir("ss-srv-card-");
    const mockCardMod = createMockInviteCardMod();
    const srv = await startServer({
      port: 0,
      dataDir: dir,
      env: { ...process.env, MAGPIE_ADDR: "127.0.0.1:59981" },
      inviteCardMod: mockCardMod,
      transportOptions: { directBindHost: "127.0.0.1" },
      discoverGatewayFn: async () => ({ ok: false, running: false, url: "", addr: "", version: "" }),
      fetchModelsFn: async () => [],
    });
    cleanups.push(() => srv.close());

    const api = (path, init = {}) =>
      fetch(`${srv.url}${path}`, {
        ...init,
        headers: {
          [TOKEN_HEADER]: srv.token,
          ...(init.body ? { "content-type": "application/json" } : {}),
          ...(init.headers || {}),
        },
      });

    // Enable sharing and set Chinese hostName to test RFC 5987 Content-Disposition safety
    await api("/api/host/name", {
      method: "POST",
      body: JSON.stringify({ hostName: "张三的工作站" }),
    });
    await api("/api/host/toggle", {
      method: "POST",
      body: JSON.stringify({ enabled: true, tosAcknowledged: true }),
    });

    // 1. POST /api/host/share-base-url validation & persistence
    const badBase = await api("/api/host/share-base-url", {
      method: "POST",
      body: JSON.stringify({ shareBaseUrl: "https://user:pass@bad.example.com/join?a=1" }),
    });
    expect(badBase.status).toBe(400);
    expect((await badBase.json()).code).toBe("invalid_share_base_url");

    const okBase = await api("/api/host/share-base-url", {
      method: "POST",
      body: JSON.stringify({ shareBaseUrl: "https://cn.example.com/join///" }),
    });
    expect(okBase.status).toBe(200);
    expect(await okBase.json()).toEqual({ ok: true, shareBaseUrl: "https://cn.example.com/join" });

    // 2. POST /api/network/mode validates optional shareBaseUrl too
    const badModeBase = await api("/api/network/mode", {
      method: "POST",
      body: JSON.stringify({
        mode: "self-relay",
        network: {
          relayAddr: "127.0.0.1:3499",
          relayToken: "super-secret-relay-token",
          shareBaseUrl: "javascript:alert(1)",
        },
      }),
    });
    expect(badModeBase.status).toBe(400);
    expect((await badModeBase.json()).code).toBe("invalid_share_base_url");

    const okMode = await api("/api/network/mode", {
      method: "POST",
      body: JSON.stringify({
        mode: "self-relay",
        network: {
          relayAddr: "127.0.0.1:3499",
          relayToken: "super-secret-relay-token",
          shareBaseUrl: "https://share.domestic.cn/join/",
        },
      }),
    });
    expect(okMode.status).toBe(200);
    expect((await okMode.json()).network.shareBaseUrl).toBe("https://share.domestic.cn/join");

    // 3. POST /api/host/invites with custom ttlSec + shareUrl + cardFilename
    const badTtl = await api("/api/host/invites", {
      method: "POST",
      body: JSON.stringify({ ttlSec: 30 }),
    });
    expect(badTtl.status).toBe(400);
    expect((await badTtl.json()).code).toBe("invalid_ttl");

    const invRes = await api("/api/host/invites", {
      method: "POST",
      body: JSON.stringify({ ttlSec: 1800 }),
    });
    expect(invRes.status).toBe(200);
    const inv = await invRes.json();
    expect(inv.ttlSec).toBe(1800);
    expect(inv.shareUrl).toBe(`https://share.domestic.cn/join/#${inv.code}`);
    expect(inv.cardFilename).toBe("simple-share-张三的工作站.html");

    // 4. GET /api/host/invites/:id/card enforces auth & host/origin checks
    expect((await fetch(`${srv.url}/api/host/invites/${encodeURIComponent(inv.id)}/card`)).status).toBe(401);
    expect(
      (
        await fetch(`${srv.url}/api/host/invites/${encodeURIComponent(inv.id)}/card`, {
          headers: { [TOKEN_HEADER]: "wrong-token" },
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await fetch(`${srv.url}/api/host/invites/${encodeURIComponent(inv.id)}/card`, {
          headers: { [TOKEN_HEADER]: srv.token, origin: "https://evil.example.com" },
        })
      ).status,
    ).toBe(403);

    // 5. Default JSON response
    const cardJsonRes = await api(`/api/host/invites/${encodeURIComponent(inv.id)}/card`);
    expect(cardJsonRes.status).toBe(200);
    const cardJson = await cardJsonRes.json();
    expect(cardJson.ok).toBe(true);
    expect(cardJson.id).toBe(inv.id);
    expect(cardJson.filename).toBe("simple-share-张三的工作站.html");
    expect(cardJson.html).toContain(inv.code);
    expect(cardJson.html).toContain(`port:${srv.port}`);
    // endpointHint MUST NOT leak relayToken
    expect(mockCardMod.renderCalls[0].endpointHint).toBe("127.0.0.1:3499");
    expect(cardJson.html).not.toContain("super-secret-relay-token");

    // 6. ?raw=1 returns downloadable HTML with Cache-Control: no-store and strict CSP
    const rawRes = await api(`/api/host/invites/${encodeURIComponent(inv.id)}/card?raw=1`);
    expect(rawRes.status).toBe(200);
    expect(rawRes.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(rawRes.headers.get("cache-control")).toBe("no-store");
    expect(rawRes.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(rawRes.headers.get("content-disposition")).toContain("attachment;");
    expect(rawRes.headers.get("content-disposition")).toContain("filename*=");
    expect(await rawRes.text()).toContain(inv.code);

    // 7. /api/state NEVER leaks invite secret or full invite code
    const stateText = await (await api("/api/state")).text();
    const rawInvite = srv.store.get().invites.find((x) => x.id === inv.id);
    expect(stateText).not.toContain(rawInvite.s);
    expect(stateText).not.toContain(inv.code);

    // 8. Revoked invite card returns 410
    expect((await api(`/api/host/invites/${encodeURIComponent(inv.id)}`, { method: "DELETE" })).status).toBe(200);
    const revokedCard = await api(`/api/host/invites/${encodeURIComponent(inv.id)}/card`);
    expect(revokedCard.status).toBe(410);
    expect((await revokedCard.json()).code).toBe("invite_revoked");

    // 9. Clear shareBaseUrl -> Mode 2 auto-derives relay /join shareUrl
    const clearBase = await api("/api/host/share-base-url", {
      method: "POST",
      body: JSON.stringify({ shareBaseUrl: "" }),
    });
    expect(clearBase.status).toBe(200);
    expect((await clearBase.json()).shareBaseUrl).toBe("");

    const inv2 = await (await api("/api/host/invites", { method: "POST" })).json();
    expect(inv2.ttlSec).toBe(300);
    expect(inv2.shareUrl).toBe(`http://127.0.0.1:3499/join/#${inv2.code}`);
  });
});

describe("bin/simple-share.mjs CLI invite --ttl/--card, apply URL, join & package.json", () => {
  test("parseCliArgs handles --card with and without path, --ttl, and --share-base-url", () => {
    expect(parseCliArgs(["invite", "--ttl", "1800", "--card"])).toEqual({
      positional: ["invite"],
      options: { ttl: "1800", card: true },
    });
    expect(parseCliArgs(["invite", "--card", "out.html", "--json"])).toEqual({
      positional: ["invite"],
      options: { card: "out.html", json: true },
    });
    expect(parseCliArgs(["invite", "--card", "--json"])).toEqual({
      positional: ["invite"],
      options: { card: true, json: true },
    });
    expect(parseCliArgs(["invite", "--card=my-card.html", "--ttl=7200"])).toEqual({
      positional: ["invite"],
      options: { card: "my-card.html", ttl: "7200" },
    });
  });

  test("CLI invite --ttl --card writes HTML card and CLI join/apply work with full share URLs", async () => {
    const hostDir = makeTempDir("ss-cli-host-");
    const recvDir = makeTempDir("ss-cli-recv-");
    const outDir = makeTempDir("ss-cli-out-");
    const mockCardMod = createMockInviteCardMod();

    const probe = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response("") });
    const directPort = probe.port;
    probe.stop(true);

    const hostSrv = await startServer({
      port: 0,
      dataDir: hostDir,
      env: { ...process.env, MAGPIE_ADDR: "127.0.0.1:59982" },
      inviteCardMod: mockCardMod,
      transportOptions: { directBindHost: "127.0.0.1" },
      discoverGatewayFn: async () => ({ ok: false, running: false, url: "", addr: "", version: "" }),
      fetchModelsFn: async () => [],
    });
    cleanups.push(() => hostSrv.close());

    const recvSrv = await startServer({
      port: 0,
      dataDir: recvDir,
      env: { ...process.env, MAGPIE_ADDR: "127.0.0.1:59983" },
      inviteCardMod: mockCardMod,
      transportOptions: { directBindHost: "127.0.0.1" },
      discoverGatewayFn: async () => ({ ok: false, running: false, url: "", addr: "", version: "" }),
      fetchModelsFn: async () => [],
    });
    cleanups.push(() => recvSrv.close());

    // Configure host Mode 3 direct + custom shareBaseUrl via CLI mode
    const modeRes = await runCliCapture(
      [
        "mode",
        "direct",
        "--host",
        "127.0.0.1",
        "--direct-port",
        String(directPort),
        "--share-base-url",
        "https://join.example.cn/join",
        "--url",
        hostSrv.url,
        "--json",
      ],
    );
    expect(modeRes.exitCode).toBe(0);
    expect(JSON.parse(modeRes.stdout).network.shareBaseUrl).toBe("https://join.example.cn/join");

    await runCliCapture(["toggle", "on", "--tos", "--url", hostSrv.url]);

    // 1. CLI invite --ttl 1800 --card (default filename in cwd)
    const invDefault = await runCliCapture(["invite", "--ttl", "1800", "--card", "--url", hostSrv.url], {
      cwd: outDir,
    });
    expect(invDefault.exitCode).toBe(0);
    expect(invDefault.stdout).toContain("Share URL: https://join.example.cn/join/#mshare1:");
    expect(invDefault.stdout).toContain("Card: ");

    // 2. CLI invite --ttl 7200 --card nested/family.html --json
    const invCustom = await runCliCapture(
      ["invite", "--ttl", "7200", "--card", "nested/family.html", "--url", hostSrv.url, "--json"],
      { cwd: outDir },
    );
    expect(invCustom.exitCode).toBe(0);
    const invData = JSON.parse(invCustom.stdout);
    expect(invData.ttlSec).toBe(7200);
    expect(invData.shareUrl).toBe(`https://join.example.cn/join/#${invData.code}`);
    expect(invData.cardPath).toBe(join(outDir, "nested", "family.html"));
    const cardHtml = readFileSync(invData.cardPath, "utf8");
    expect(cardHtml).toContain(invData.code);

    // 3. CLI join with FULL share URL -> parses, applies over real mTLS direct mode, prints 4-digit SAS
    const joinRes = await runCliCapture(
      ["join", invData.shareUrl, "--name", "Mom-Laptop", "--url", recvSrv.url],
    );
    expect(joinRes.exitCode).toBe(0);
    expect(joinRes.stdout).toMatch(/SAS:\s+\d{4}/);
    expect(joinRes.stdout).toContain("Mode: direct");

    const hostPending = JSON.parse(
      (await runCliCapture(["pending", "--json", "--url", hostSrv.url])).stdout,
    ).pending;
    expect(hostPending.length).toBe(1);
    expect(hostPending[0].name).toBe("Mom-Laptop");
    expect(joinRes.stdout).toContain(hostPending[0].sas);

    // 4. CLI apply with local handoff URL (#invite=mshare1%3A...)
    const invForApply = JSON.parse(
      (await runCliCapture(["invite", "--url", hostSrv.url, "--json"])).stdout,
    );
    const handoffUrl = `http://127.0.0.1:${recvSrv.port}/#invite=${encodeURIComponent(invForApply.code)}`;
    const applyRes = await runCliCapture(
      ["apply", handoffUrl, "--name", "Dad-PC", "--url", recvSrv.url, "--json"],
    );
    expect(applyRes.exitCode).toBe(0);
    const applyJson = JSON.parse(applyRes.stdout);
    expect(applyJson.pending.sas).toMatch(/^\d{4}$/);
  });

  test("CLI join auto-installs Iroh for Mode 1 P2P invites when not yet installed, and skips when ready", async () => {
    const p2pCode = encodeInvite({
      v: 1,
      m: "p2p",
      h: "P2P-Host",
      pk: "b".repeat(64),
      id: "inv-p2p1",
      s: "fedcba9876543210fedcba9876543210",
      exp: Date.now() + 600_000,
      ep: { irohEndpointId: "b".repeat(64), relayUrl: "" },
    });
    const shareUrl = `https://join.example.cn/#${p2pCode}`;

    let irohInstalled = false;
    let installCallCount = 0;
    const calls = [];

    const mockFetch = async (url, init = {}) => {
      const u = new URL(url);
      const path = u.pathname;
      calls.push(`${init.method || "GET"} ${path}`);

      if (path === "/api/health") {
        return Response.json({ ok: true, version: "0.1.2" });
      }
      if (path === "/") {
        return new Response('<meta name="simple-share-token" content="tok-123">', { status: 200 });
      }
      if (path === "/api/receiver/parse") {
        const body = JSON.parse(init.body);
        const decoded = decodeInvite(body.code, { checkExpiry: true });
        return Response.json({
          v: decoded.v,
          h: decoded.h,
          fp: "ed25519:1111·2222·3333·4444",
          pk: decoded.pk,
          m: decoded.m,
          id: decoded.id,
          ep: decoded.ep,
          expiresAt: decoded.exp,
        });
      }
      if (path === "/api/state") {
        return Response.json({
          irohStatus: {
            supported: true,
            installed: irohInstalled,
            integrityOk: irohInstalled,
          },
        });
      }
      if (path === "/api/network/iroh/install") {
        installCallCount += 1;
        irohInstalled = true;
        return Response.json({
          ok: true,
          irohStatus: { supported: true, installed: true, integrityOk: true },
        });
      }
      if (path === "/api/receiver/apply") {
        return Response.json({
          pending: { id: "pend-p2p1", sas: "4829", hostName: "P2P-Host", mode: "p2p" },
        });
      }
      return new Response("not found", { status: 404 });
    };

    // First run: Iroh not installed -> auto-installs via /api/network/iroh/install
    const first = await runCliCapture(["join", shareUrl, "--name", "Linux-Box", "--json"], {
      fetchImpl: mockFetch,
    });
    expect(first.exitCode).toBe(0);
    const firstJson = JSON.parse(first.stdout);
    expect(firstJson.ok).toBe(true);
    expect(firstJson.irohAutoInstalled).toBe(true);
    expect(firstJson.pending.sas).toBe("4829");
    expect(installCallCount).toBe(1);
    expect(calls).toContain("POST /api/network/iroh/install");

    // Second run: Iroh already installed -> skips install endpoint
    const second = await runCliCapture(["join", shareUrl, "--json"], {
      fetchImpl: mockFetch,
    });
    expect(second.exitCode).toBe(0);
    const secondJson = JSON.parse(second.stdout);
    expect(secondJson.irohAutoInstalled).toBe(false);
    expect(secondJson.pending.sas).toBe("4829");
    expect(installCallCount).toBe(1);
  });

  test("package.json files list includes bootstrap scripts and static /join landing page", () => {
    const pkg = JSON.parse(readFileSync(join(import.meta.dir, "..", "package.json"), "utf8"));
    expect(pkg.files).toContain("scripts/bootstrap.ps1");
    expect(pkg.files).toContain("scripts/bootstrap.sh");
    expect(pkg.files).toContain("docs/join/index.html");
  });
});
