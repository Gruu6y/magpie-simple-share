import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  addRemoteMagpieProvider,
  classifyProviderKind,
  createMemberGatewayKey,
  discoverMagpieGateway,
  ensureGatewayLoadedProviderModels,
  fetchLocalModels,
  isLoopbackUrl,
  removeMemberGatewayKey,
  removeRemoteMagpieProvider,
  resolveMagpieBinary,
  updateMemberGatewayKey,
} from "../lib/magpie-cli.mjs";
import { makeProviderId } from "../lib/pairing.mjs";
import {
  createHostGatewayHandler,
  isAllowedGatewayPath,
} from "../lib/host-gateway.mjs";

const servers = [];
const tempDirs = [];

function trackServer(srv) {
  servers.push(srv);
  return srv;
}

function makeTempDir() {
  const dir = mkdtempSync(join(tmpdir(), "simple-share-gw-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (servers.length > 0) {
    try {
      servers.pop().stop(true);
    } catch {}
  }
  while (tempDirs.length > 0) {
    try {
      rmSync(tempDirs.pop(), { recursive: true, force: true });
    } catch {}
  }
});

describe("magpie-cli", () => {
  test("isLoopbackUrl strictly validates loopback http URLs", () => {
    expect(isLoopbackUrl("http://127.0.0.1:3425")).toBe(true);
    expect(isLoopbackUrl("http://127.0.0.1")).toBe(true);
    expect(isLoopbackUrl("http://[::1]:3425")).toBe(true);
    expect(isLoopbackUrl("http://localhost:3425")).toBe(true);
    expect(isLoopbackUrl("http://127.0.0.1:3496/prefix")).toBe(true);

    expect(isLoopbackUrl("https://127.0.0.1:3425")).toBe(false);
    expect(isLoopbackUrl("http://0.0.0.0:3425")).toBe(false);
    expect(isLoopbackUrl("http://192.168.1.20:3425")).toBe(false);
    expect(isLoopbackUrl("http://example.com:3425")).toBe(false);
    expect(isLoopbackUrl("http://localhost.evil.com:3425")).toBe(false);
    expect(isLoopbackUrl("http://user:pass@127.0.0.1:3425")).toBe(false);
    expect(isLoopbackUrl("http://127.0.0.1:3425#frag")).toBe(false);
    expect(isLoopbackUrl("ftp://127.0.0.1:3425")).toBe(false);
    expect(isLoopbackUrl("http://127.0.0.1:0")).toBe(false);
    expect(isLoopbackUrl("")).toBe(false);
    expect(isLoopbackUrl(null)).toBe(false);
  });

  test("discoverMagpieGateway discovers via MAGPIE_ADDR, gateway.json, and status --json", async () => {
    const srv = trackServer(
      Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch(req) {
          const path = new URL(req.url).pathname;
          if (path === "/api/hello") {
            return Response.json({ name: "magpie", version: "0.1.4572" });
          }
          return new Response("not found", { status: 404 });
        },
      }),
    );
    const addr = `127.0.0.1:${srv.port}`;

    // 1. env.MAGPIE_ADDR
    const viaEnv = await discoverMagpieGateway({
      env: { MAGPIE_ADDR: addr },
      configDir: makeTempDir(),
    });
    expect(viaEnv).toEqual({
      ok: true,
      running: true,
      url: `http://${addr}`,
      addr,
      version: "0.1.4572",
    });

    // 2. Non-loopback MAGPIE_ADDR rejected without probing
    let probedEvil = false;
    const nonLoopback = await discoverMagpieGateway({
      env: { MAGPIE_ADDR: "http://192.168.1.10:3425" },
      fetchImpl: async () => {
        probedEvil = true;
        return new Response("ok");
      },
    });
    expect(nonLoopback.ok).toBe(false);
    expect(nonLoopback.error).toBe("non_loopback_gateway_addr");
    expect(probedEvil).toBe(false);

    // 3. <configDir>/gateway.json
    const cfgDir = makeTempDir();
    writeFileSync(join(cfgDir, "gateway.json"), JSON.stringify({ addr, version: "0.1.4572" }));
    const viaFile = await discoverMagpieGateway({ env: {}, configDir: cfgDir });
    expect(viaFile.ok).toBe(true);
    expect(viaFile.url).toBe(`http://${addr}`);

    // 4. Fallback to `magpie status --json`
    const emptyCfg = makeTempDir();
    const viaCli = await discoverMagpieGateway({
      env: {},
      configDir: emptyCfg,
      execMagpie: async (args) => {
        expect(args).toEqual(["status", "--json"]);
        return {
          code: 0,
          stdout: JSON.stringify({ running: true, url: `http://${addr}`, addr, version: "0.1.4572" }),
          stderr: "",
        };
      },
    });
    expect(viaCli.ok).toBe(true);
    expect(viaCli.running).toBe(true);

    // 5. Offline returns graceful ok: false
    const offline = await discoverMagpieGateway({
      env: { MAGPIE_ADDR: "127.0.0.1:59997" },
      timeoutMs: 200,
    });
    expect(offline.ok).toBe(false);
    expect(offline.running).toBe(false);
  });

  test("fetchLocalModels classifies sub vs api providers and degrades gracefully", async () => {
    const srv = trackServer(
      Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch(req) {
          if (new URL(req.url).pathname === "/v1/models") {
            return Response.json({
              object: "list",
              data: [
                { id: "deepseek/deepseek-chat", display_name: "DeepSeek Chat", owned_by: "deepseek" },
                { id: "openrouter/gpt-4o-mini", owned_by: "openrouter" },
                { id: "group/daily-fast", owned_by: "group" },
                { id: "clinepass/sonnet", owned_by: "clinepass" },
                { id: "claude/claude-sonnet-4-6", display_name: "claude-sonnet-4-6", owned_by: "claude" },
                { id: "codex/gpt-5.4", owned_by: "codex" },
                { id: "agy/gemini-3-pro", owned_by: "agy" },
                { id: "workbuddy/wb-1", owned_by: "workbuddy" },
                { id: "kimi-work/k2", owned_by: "kimi-work" },
              ],
            });
          }
          return new Response("not found", { status: 404 });
        },
      }),
    );

    const models = await fetchLocalModels(`http://127.0.0.1:${srv.port}`);
    const byId = new Map(models.map((m) => [m.id, m]));
    expect(byId.get("deepseek/deepseek-chat")).toEqual({
      id: "deepseek/deepseek-chat",
      label: "DeepSeek Chat",
      provider: "deepseek",
      kind: "api",
    });
    expect(byId.get("openrouter/gpt-4o-mini")?.kind).toBe("api");
    expect(byId.get("group/daily-fast")?.kind).toBe("api");
    expect(byId.get("clinepass/sonnet")?.kind).toBe("api");
    expect(byId.get("claude/claude-sonnet-4-6")?.kind).toBe("sub");
    expect(byId.get("codex/gpt-5.4")?.kind).toBe("sub");
    expect(byId.get("agy/gemini-3-pro")?.kind).toBe("sub");
    expect(byId.get("workbuddy/wb-1")?.kind).toBe("sub");
    expect(byId.get("kimi-work/k2")?.kind).toBe("sub");

    for (const sub of [
      "claude", "codex", "copilot", "kiro", "cursor", "workbuddy", "qoder",
      "gemini-web", "doubao", "kimi-work", "devin", "zed", "warp", "cline",
      "trae", "loomy", "catpaw", "orcaterm", "codearts", "agy",
    ]) {
      expect(classifyProviderKind(sub)).toBe("sub");
    }

    // Offline or non-loopback returns []
    expect(await fetchLocalModels("http://127.0.0.1:59996", { timeoutMs: 150 })).toEqual([]);
    expect(await fetchLocalModels("http://evil.example.com:3425")).toEqual([]);
  });

  test("createMemberGatewayKey hardens key and rolls back if any hardening step fails", async () => {
    const calls = [];
    const created = await createMemberGatewayKey({
      name: "Mom Laptop",
      models: ["deepseek/deepseek-chat", "group/daily-fast"],
      period: "day",
      tokenLimitWan: 100,
      costLimit: 3.5,
      concurrency: 2,
      quotas: false,
      execMagpie: async (args) => {
        calls.push(args);
        if (args[1] === "add") {
          return { code: 0, stdout: "sk-magpie-key-aaaa1111bbbb2222cccc333399aaff", stderr: "" };
        }
        if (args[1] === "list") {
          return {
            code: 0,
            stdout: [
              "ID                        NAME        STATE    GATEWAY KEY            LIMIT  MODELS  ACCOUNTS  ACCESS",
              "111111111111111111111111  Mom Laptop  enabled  sk-magpie-key-…001122  -      all     all       full",
              "222222222222222222222222  Mom Laptop  enabled  sk-magpie-key-…99aaff  -      all     all       full",
            ].join("\n"),
            stderr: "",
          };
        }
        return { code: 0, stdout: "ok", stderr: "" };
      },
    });

    expect(created).toEqual({
      keyId: "222222222222222222222222",
      keyName: "Mom Laptop",
      keySecret: "sk-magpie-key-aaaa1111bbbb2222cccc333399aaff",
    });
    expect(calls).toEqual([
      ["gateway-key", "add", "Mom Laptop"],
      ["gateway-key", "list"],
      ["gateway-key", "models", "222222222222222222222222", "deepseek/deepseek-chat", "group/daily-fast"],
      ["gateway-key", "limit", "222222222222222222222222", "day", "--tokens", "1000000", "--cost", "3.5"],
      ["gateway-key", "concurrency", "222222222222222222222222", "2"],
      ["gateway-key", "mcp", "222222222222222222222222", "none"],
      ["gateway-key", "memory", "222222222222222222222222", "off"],
      ["gateway-key", "admin", "222222222222222222222222", "off"],
      ["gateway-key", "quotas", "222222222222222222222222", "off"],
    ]);

    // Rollback on failure during `admin off`
    const rollbackCalls = [];
    await expect(
      createMemberGatewayKey({
        name: "bad-key",
        models: ["all"],
        execMagpie: async (args) => {
          rollbackCalls.push(args);
          if (args[1] === "add") return { code: 0, stdout: "sk-magpie-key-deadbeef123456", stderr: "" };
          if (args[1] === "list") return { code: 0, stdout: "deadbeefid  bad-key  enabled  sk-magpie-key-…123456", stderr: "" };
          if (args[1] === "admin") return { code: 1, stdout: "", stderr: "admin lock failed" };
          return { code: 0, stdout: "ok", stderr: "" };
        },
      }),
    ).rejects.toThrow(/admin lock failed/);
    expect(rollbackCalls.at(-1)).toEqual(["gateway-key", "remove", "deadbeefid"]);
  });

  test("update, remove, and remote-magpie provider CLI wrappers enforce validation", async () => {
    const cmds = [];
    const execMagpie = async (args) => {
      cmds.push(args);
      return { code: 0, stdout: "ok", stderr: "" };
    };

    await updateMemberGatewayKey({
      keyId: "k123",
      models: ["openai/gpt-4o"],
      period: "week",
      tokenLimitWan: 50,
      costLimit: 0,
      concurrency: 0,
      quotas: true,
      execMagpie,
    });
    await removeMemberGatewayKey({ keyId: "k123", execMagpie });
    await addRemoteMagpieProvider({
      id: "share-home",
      bridgeUrl: "http://127.0.0.1:3496",
      bridgeToken: "tok-abc",
      execMagpie,
    });
    await removeRemoteMagpieProvider({ id: "share-home", execMagpie });

    expect(cmds).toEqual([
      ["gateway-key", "models", "k123", "openai/gpt-4o"],
      ["gateway-key", "limit", "k123", "week", "--tokens", "500000"],
      ["gateway-key", "concurrency", "k123", "off"],
      ["gateway-key", "quotas", "k123", "on"],
      ["gateway-key", "remove", "k123"],
      ["provider", "add", "remote-magpie", "tok-abc", "url=http://127.0.0.1:3496", "id=share-home"],
      ["provider", "rm", "share-home"],
    ]);

    await expect(
      addRemoteMagpieProvider({
        id: "share-bad",
        bridgeUrl: "http://evil.example.com:3496",
        bridgeToken: "tok",
        execMagpie,
      }),
    ).rejects.toThrow(/loopback/);
  });

  test("resolveMagpieBinary handles env overrides, boolean MAGPIE_CLI=1, PATH, and macOS/Linux paths", () => {
    expect(resolveMagpieBinary({ MAGPIE_BIN: "/custom/magpie", MAGPIE_CLI: "1" }, { platform: "linux" })).toBe(
      "/custom/magpie",
    );
    expect(
      resolveMagpieBinary(
        { MAGPIE_CLI: "1", HOME: "/home/alice", PATH: "" },
        {
          platform: "linux",
          existsSync: (p) => p === join("/home/alice", ".local", "bin", "magpie"),
          accessSync: () => {},
        },
      ),
    ).toBe(join("/home/alice", ".local", "bin", "magpie"));
    expect(
      resolveMagpieBinary(
        { HOME: "/Users/alice", PATH: "" },
        {
          platform: "darwin",
          existsSync: (p) => p === "/Applications/Magpie.app/Contents/MacOS/magpie",
          accessSync: () => {},
        },
      ),
    ).toBe("/Applications/Magpie.app/Contents/MacOS/magpie");
    expect(
      resolveMagpieBinary(
        { HOME: "/Users/alice", PATH: "" },
        {
          platform: "darwin",
          existsSync: (p) => p === "/opt/homebrew/bin/magpie",
          accessSync: () => {},
        },
      ),
    ).toBe("/opt/homebrew/bin/magpie");
    expect(
      resolveMagpieBinary(
        { PATH: "/usr/bin:/opt/bin" },
        {
          platform: "linux",
          existsSync: (p) => p === join("/opt/bin", "magpie"),
          accessSync: () => {},
        },
      ),
    ).toBe(join("/opt/bin", "magpie"));
    expect(resolveMagpieBinary({ PATH: "" }, { platform: "darwin", existsSync: () => false })).toBe("magpie");
    expect(resolveMagpieBinary({ PATH: "" }, { platform: "win32", existsSync: () => false })).toBe("magpie.exe");
  });

  test("makeProviderId produces strictly Magpie-valid lowercase alphanumeric-dash IDs for FQDN/unicode hosts", async () => {
    for (const host of [
      "ip-172-16-5-2.us-west-2.compute.internal",
      "Alice's_MacBook-Pro.local",
      "测试主机-01.corp",
      "---...___",
    ]) {
      const id = makeProviderId(host, "m-ab12CD34dfd5eada");
      expect(id).toMatch(/^[a-z0-9][a-z0-9-]{0,63}$/);
      expect(id.includes(".")).toBe(false);
      expect(id.includes("_")).toBe(false);
      expect(id.includes("--")).toBe(false);
    }
    expect(makeProviderId("ip-172-16-5-2.us-west-2.compute.internal", "m-0011dfd5eada")).toBe(
      "mshare-ip-172-16-5-2-us-wes-dfd5eada",
    );

    const execMock = async () => ({ code: 0, stdout: "ok" });
    await expect(
      addRemoteMagpieProvider({
        id: "mshare-bad.dot-1234",
        bridgeUrl: "http://127.0.0.1:3496",
        bridgeToken: "tok",
        execMagpie: execMock,
      }),
    ).rejects.toThrow(/Invalid remote-magpie provider id/i);
  });

  test("ensureGatewayLoadedProviderModels waits before syncing and falls back cleanly on cold start", async () => {
    // 1. Appears on poll #8 within initialWaitMs -> no magpie sync triggered
    let polls1 = 0;
    let syncs1 = 0;
    let sleeps1 = 0;
    const res1 = await ensureGatewayLoadedProviderModels("mshare-mac-1", {
      discoverGatewayFn: async () => ({ ok: true, url: "http://127.0.0.1:3425" }),
      hasProviderModelsFn: async () => {
        polls1 += 1;
        return polls1 >= 8;
      },
      runSyncFn: async () => {
        syncs1 += 1;
        return { code: 0, stdout: "", stderr: "" };
      },
      sleepFn: async () => {
        sleeps1 += 1;
      },
      pollIntervalMs: 100,
      initialWaitMs: 2000,
      postSyncWaitMs: 1500,
      maxSyncRetries: 2,
    });
    expect(res1).toEqual({ loaded: true, synced: 0 });
    expect(polls1).toBe(8);
    expect(sleeps1).toBe(7);
    expect(syncs1).toBe(0);

    // 2. Absent across initialWaitMs -> runs magpie sync once and detects after sync
    let polls2 = 0;
    let syncs2 = 0;
    const res2 = await ensureGatewayLoadedProviderModels("mshare-mac-2", {
      discoverGatewayFn: async () => ({ ok: true, url: "http://127.0.0.1:3425" }),
      hasProviderModelsFn: async () => {
        polls2 += 1;
        return syncs2 >= 1 && polls2 >= 5;
      },
      runSyncFn: async () => {
        syncs2 += 1;
        return { code: 0, stdout: "", stderr: "" };
      },
      sleepFn: async () => {},
      pollIntervalMs: 100,
      initialWaitMs: 300,
      postSyncWaitMs: 400,
      maxSyncRetries: 2,
    });
    expect(res2).toEqual({ loaded: true, synced: 1 });
    expect(syncs2).toBe(1);
    expect(polls2).toBe(5);

    // 3. Absent after 1st sync -> triggers 2nd magpie sync retry and succeeds
    let polls3 = 0;
    let syncs3 = 0;
    const res3 = await ensureGatewayLoadedProviderModels("mshare-mac-3", {
      discoverGatewayFn: async () => ({ ok: true, url: "http://127.0.0.1:3425" }),
      hasProviderModelsFn: async () => {
        polls3 += 1;
        return syncs3 >= 2;
      },
      runSyncFn: async () => {
        syncs3 += 1;
        return { code: 0, stdout: "", stderr: "" };
      },
      sleepFn: async () => {},
      pollIntervalMs: 100,
      initialWaitMs: 200,
      postSyncWaitMs: 200,
      maxSyncRetries: 2,
    });
    expect(res3).toEqual({ loaded: true, synced: 2 });
    expect(syncs3).toBe(2);

    // 4. Unreachable gateway returns immediately without polling or syncing
    let polls4 = 0;
    let syncs4 = 0;
    let sleeps4 = 0;
    const res4 = await ensureGatewayLoadedProviderModels("mshare-offline", {
      discoverGatewayFn: async () => ({ ok: false, url: "" }),
      hasProviderModelsFn: async () => {
        polls4 += 1;
        return true;
      },
      runSyncFn: async () => {
        syncs4 += 1;
      },
      sleepFn: async () => {
        sleeps4 += 1;
      },
    });
    expect(res4).toEqual({ loaded: false, synced: 0 });
    expect(polls4).toBe(0);
    expect(sleeps4).toBe(0);
    expect(syncs4).toBe(0);
  });
});

describe("host-gateway path allowlist & proxy handler", () => {
  test("isAllowedGatewayPath enforces strict allowlist and blocks traversal/admin/mcp", () => {
    expect(isAllowedGatewayPath("GET", "/v1/models").allowed).toBe(true);
    expect(isAllowedGatewayPath("GET", "/models").allowed).toBe(true);
    expect(isAllowedGatewayPath("GET", "/v1/magpie/limit").allowed).toBe(true);
    expect(isAllowedGatewayPath("GET", "/v1/magpie/quotas", { allowQuotas: false })).toEqual({
      allowed: false,
      code: "forbidden_path",
      reason: "not_in_get_allowlist",
    });
    expect(isAllowedGatewayPath("GET", "/v1/magpie/quotas", { allowQuotas: true }).allowed).toBe(true);

    expect(isAllowedGatewayPath("POST", "/v1/chat/completions").allowed).toBe(true);
    expect(isAllowedGatewayPath("POST", "/v1/responses").allowed).toBe(true);
    expect(isAllowedGatewayPath("POST", "/v1/messages").allowed).toBe(true);
    expect(isAllowedGatewayPath("POST", "/v1/messages/count_tokens").allowed).toBe(true);
    expect(isAllowedGatewayPath("POST", "/v1beta/models/gemini-2.5-flash:generateContent").allowed).toBe(true);
    expect(
      isAllowedGatewayPath("POST", "/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse").allowed,
    ).toBe(true);

    const blocked = [
      ["GET", "/v1/models/../magpie/admin/providers"],
      ["GET", "/v1/%2e%2e/magpie/admin/providers"],
      ["GET", "/v1/%2E%2E/magpie/keys"],
      ["GET", "/v1/%252e%252e/magpie/admin"],
      ["GET", "/v1\\..\\magpie\\admin"],
      ["GET", "/v1/%5c../magpie/admin"],
      ["GET", "//v1/models"],
      ["GET", "/v1//models"],
      ["GET", "/v1/%2fmodels"],
      ["GET", "/v1/models#admin"],
      ["GET", "/v1/models%23admin"],
      ["GET", "/v1/magpie/admin/providers"],
      ["POST", "/v1/magpie/admin/keys"],
      ["GET", "/v1/magpie/native/status"],
      ["POST", "/v1/magpie/keys"],
      ["GET", "/v1/magpie/usage"],
      ["GET", "/v1/magpie/memory"],
      ["POST", "/mcp"],
      ["GET", "/mcp/sse"],
      ["GET", "/"],
      ["GET", "/v1/chat/completions"],
      ["DELETE", "/v1/models"],
      ["POST", "/v1beta/models/google/gemini-2.5-flash:generateContent"],
      ["POST", "/v1beta/models/..:generateContent"],
    ];

    for (const [method, path] of blocked) {
      const res = isAllowedGatewayPath(method, path, { allowQuotas: true });
      expect(res.allowed).toBe(false);
      expect(res.code).toBe("forbidden_path");
    }
  });

  test("Fail-Closed /v1/magpie/limit oracle blocks empty/mismatched keys and NEVER forwards", async () => {
    let forwardCalled = 0;
    let oracleResponse = { key: "" };
    let oracleStatus = 200;

    const upstream = trackServer(
      Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch(req) {
          const path = new URL(req.url).pathname;
          if (path === "/v1/magpie/limit") {
            return Response.json(oracleResponse, { status: oracleStatus });
          }
          forwardCalled++;
          return Response.json({ ok: true });
        },
      }),
    );

    const state = {
      sharingEnabled: true,
      visibility: { limit: true, quotas: false },
      members: [
        {
          id: "m-alice",
          status: "active",
          magpieKeyName: "ss-alice",
          magpieKeySecret: "sk-magpie-key-alice123",
        },
      ],
    };
    const handler = createHostGatewayHandler({
      store: { get: () => state },
      getGatewayUrl: () => `http://127.0.0.1:${upstream.port}`,
    });

    // Empty key -> Fail-Closed! (magpie loopback privilege escalation blocked)
    oracleResponse = { key: "", limited: false };
    const r1 = await handler.handleHttpRequest("m-alice", {
      method: "POST",
      path: "/v1/chat/completions",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "deepseek/deepseek-chat", messages: [] }),
    });
    expect(r1.status).toBe(403);
    expect(JSON.parse(new TextDecoder().decode(r1.body)).code).toBe("key_revoked_or_invalid");
    expect(forwardCalled).toBe(0);

    // Mismatched key name -> Fail-Closed!
    oracleResponse = { key: "other-key" };
    const r2 = await handler.handleHttpRequest("m-alice", {
      method: "GET",
      path: "/v1/models",
      headers: {},
    });
    expect(r2.status).toBe(403);
    expect(JSON.parse(new TextDecoder().decode(r2.body)).code).toBe("key_revoked_or_invalid");
    expect(forwardCalled).toBe(0);

    // Non-200 oracle -> Fail-Closed!
    oracleStatus = 401;
    oracleResponse = { key: "ss-alice" };
    const r3 = await handler.handleHttpRequest("m-alice", {
      method: "GET",
      path: "/v1/models",
      headers: {},
    });
    expect(r3.status).toBe(403);
    expect(forwardCalled).toBe(0);

    // Valid oracle -> forwards!
    oracleStatus = 200;
    oracleResponse = { key: "ss-alice" };
    const r4 = await handler.handleHttpRequest("m-alice", {
      method: "GET",
      path: "/v1/models",
      headers: {},
    });
    expect(r4.status).toBe(200);
    expect(forwardCalled).toBe(1);
    await new Response(r4.body).arrayBuffer();
  });

  test("enforces sharingEnabled, pause 403, revoke 403, header stripping, and usage extraction", async () => {
    const receivedHeaders = [];
    const upstream = trackServer(
      Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        async fetch(req) {
          const path = new URL(req.url).pathname;
          if (path === "/v1/magpie/limit") {
            return Response.json({ key: "ss-alice" });
          }
          receivedHeaders.push(Object.fromEntries(req.headers.entries()));
          if (path === "/v1/chat/completions") {
            return Response.json({
              id: "chat-1",
              model: "deepseek-chat",
              choices: [{ message: { role: "assistant", content: "secret-answer-never-stored" } }],
              usage: { prompt_tokens: 123, completion_tokens: 45 },
            });
          }
          if (path === "/v1/messages") {
            const encoder = new TextEncoder();
            const body = new ReadableStream({
              start(ctrl) {
                ctrl.enqueue(
                  encoder.encode(
                    'event: message_start\ndata: {"type":"message_start","message":{"model":"claude-sonnet-4-6","usage":{"input_tokens":77,"output_tokens":1}}}\n\n',
                  ),
                );
                ctrl.enqueue(
                  encoder.encode(
                    'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"text":"hello"}}\n\n',
                  ),
                );
                ctrl.enqueue(
                  encoder.encode(
                    'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":33}}\n\n',
                  ),
                );
                ctrl.close();
              },
            });
            return new Response(body, {
              status: 200,
              headers: { "content-type": "text/event-stream; charset=utf-8" },
            });
          }
          return new Response("not found", { status: 404 });
        },
      }),
    );

    const state = {
      sharingEnabled: false,
      visibility: { limit: true, quotas: false },
      members: [
        {
          id: "m-alice",
          status: "active",
          magpieKeyName: "ss-alice",
          magpieKeySecret: "sk-magpie-key-host-only-secret",
        },
      ],
    };
    const usageEvents = [];
    const handler = createHostGatewayHandler({
      store: { get: () => state },
      getGatewayUrl: () => `http://127.0.0.1:${upstream.port}`,
      onUsage: (u) => usageEvents.push(u),
    });

    // sharingEnabled false -> 503 share_offline
    const offRes = await handler.handleHttpRequest("m-alice", {
      method: "GET",
      path: "/v1/models",
      headers: {},
    });
    expect(offRes.status).toBe(503);
    expect(JSON.parse(new TextDecoder().decode(offRes.body)).code).toBe("share_offline");

    // paused -> 403 share_paused
    state.sharingEnabled = true;
    state.members[0].status = "paused";
    const pausedRes = await handler.handleHttpRequest("m-alice", {
      method: "GET",
      path: "/v1/models",
      headers: {},
    });
    expect(pausedRes.status).toBe(403);
    expect(JSON.parse(new TextDecoder().decode(pausedRes.body)).code).toBe("share_paused");

    // unknown member -> 403 share_revoked
    const unknownRes = await handler.handleHttpRequest("m-nobody", {
      method: "GET",
      path: "/v1/models",
      headers: {},
    });
    expect(unknownRes.status).toBe(403);
    expect(JSON.parse(new TextDecoder().decode(unknownRes.body)).code).toBe("share_revoked");

    // active -> strips dangerous headers, injects member secret, extracts JSON usage
    state.members[0].status = "active";
    const chatRes = await handler.handleHttpRequest("m-alice", {
      method: "POST",
      path: "/v1/chat/completions",
      headers: {
        authorization: "Bearer attacker-fake",
        "x-api-key": "attacker-key",
        "x-forwarded-for": "1.2.3.4",
        host: "evil.internal",
        cookie: "session=hijack",
        "x-custom-safe": "yes",
        "content-type": "application/json",
      },
      body: JSON.stringify({ model: "deepseek/deepseek-chat", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(chatRes.status).toBe(200);
    await new Response(chatRes.body).text();

    expect(receivedHeaders.length).toBe(1);
    expect(receivedHeaders[0].authorization).toBe("Bearer sk-magpie-key-host-only-secret");
    expect(receivedHeaders[0]["x-api-key"]).toBeUndefined();
    expect(receivedHeaders[0]["x-forwarded-for"]).toBeUndefined();
    expect(receivedHeaders[0].cookie).toBeUndefined();
    expect(receivedHeaders[0].host).toBe(`127.0.0.1:${upstream.port}`);
    expect(receivedHeaders[0]["x-custom-safe"]).toBe("yes");

    expect(usageEvents).toEqual([
      {
        memberId: "m-alice",
        model: "deepseek/deepseek-chat",
        inputTokens: 123,
        outputTokens: 45,
      },
    ]);
    // Verify no prompt/response text stored on usage event
    expect(Object.keys(usageEvents[0]).sort()).toEqual([
      "inputTokens",
      "memberId",
      "model",
      "outputTokens",
    ]);

    // Anthropic SSE multi-event usage accumulation
    const msgRes = await handler.handleHttpRequest("m-alice", {
      method: "POST",
      path: "/v1/messages",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "claude/claude-sonnet-4-6", stream: true }),
    });
    expect(msgRes.status).toBe(200);
    await new Response(msgRes.body).text();
    expect(usageEvents[1]).toEqual({
      memberId: "m-alice",
      model: "claude/claude-sonnet-4-6",
      inputTokens: 77,
      outputTokens: 33,
    });
  });

  test("abortMemberStreams immediately aborts Member A SSE without affecting Member B", async () => {
    const encoder = new TextEncoder();
    const controllers = new Map();
    const abortedMembers = [];

    const upstream = trackServer(
      Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch(req) {
          const url = new URL(req.url);
          if (url.pathname === "/v1/magpie/limit") {
            const auth = req.headers.get("authorization") || "";
            if (auth.includes("secret-a")) return Response.json({ key: "ss-a" });
            if (auth.includes("secret-b")) return Response.json({ key: "ss-b" });
            return Response.json({ key: "" });
          }
          if (url.pathname === "/v1/chat/completions") {
            const tag = req.headers.get("x-member-tag");
            const stream = new ReadableStream({
              start(ctrl) {
                controllers.set(tag, ctrl);
                ctrl.enqueue(encoder.encode(`data: {"tag":"${tag}","chunk":1}\n\n`));
                req.signal.addEventListener("abort", () => {
                  abortedMembers.push(tag);
                  try {
                    ctrl.close();
                  } catch {}
                });
              },
            });
            return new Response(stream, {
              status: 200,
              headers: { "content-type": "text/event-stream" },
            });
          }
          return new Response("not found", { status: 404 });
        },
      }),
    );

    const state = {
      sharingEnabled: true,
      visibility: { limit: true, quotas: false },
      members: [
        { id: "member-a", status: "active", magpieKeyName: "ss-a", magpieKeySecret: "secret-a" },
        { id: "member-b", status: "active", magpieKeyName: "ss-b", magpieKeySecret: "secret-b" },
      ],
    };
    const usageEvents = [];
    const handler = createHostGatewayHandler({
      store: { get: () => state },
      getGatewayUrl: () => `http://127.0.0.1:${upstream.port}`,
      onUsage: (u) => usageEvents.push(u),
    });

    const resA = await handler.handleHttpRequest("member-a", {
      method: "POST",
      path: "/v1/chat/completions",
      headers: { "x-member-tag": "A", "content-type": "application/json" },
      body: JSON.stringify({ model: "deepseek/deepseek-chat", stream: true }),
    });
    const resB = await handler.handleHttpRequest("member-b", {
      method: "POST",
      path: "/v1/chat/completions",
      headers: { "x-member-tag": "B", "content-type": "application/json" },
      body: JSON.stringify({ model: "deepseek/deepseek-chat", stream: true }),
    });

    expect(handler.activeCount("member-a")).toBe(1);
    expect(handler.activeCount("member-b")).toBe(1);

    const readerA = resA.body.getReader();
    const readerB = resB.body.getReader();

    // Unbuffered: first chunk arrives immediately while stream stays open
    const firstA = await readerA.read();
    expect(new TextDecoder().decode(firstA.value)).toContain('"tag":"A"');
    const firstB = await readerB.read();
    expect(new TextDecoder().decode(firstB.value)).toContain('"tag":"B"');

    // Start awaiting second read on A, then abort Member A
    const pendingReadA = readerA.read();
    const abortedCount = handler.abortMemberStreams("member-a");
    expect(abortedCount).toBe(1);
    expect(handler.activeCount("member-a")).toBe(0);
    expect(handler.activeCount("member-b")).toBe(1);

    await expect(pendingReadA).rejects.toThrow();

    // Member B finishes normally with usage chunk
    const ctrlB = controllers.get("B");
    ctrlB.enqueue(
      encoder.encode(
        'data: {"model":"deepseek/deepseek-chat","usage":{"prompt_tokens":40,"completion_tokens":15}}\n\ndata: [DONE]\n\n',
      ),
    );
    ctrlB.close();

    let tailB = "";
    while (true) {
      const { done, value } = await readerB.read();
      if (done) break;
      tailB += new TextDecoder().decode(value);
    }
    expect(tailB).toContain("[DONE]");
    expect(handler.activeCount("member-b")).toBe(0);
    // Allow TCP FIN propagation on loopback for upstream req.signal abort callback
    for (let i = 0; i < 20 && abortedMembers.length === 0; i++) {
      await Bun.sleep(10);
    }
    expect(abortedMembers).toEqual(["A"]);
    expect(usageEvents).toEqual([
      {
        memberId: "member-b",
        model: "deepseek/deepseek-chat",
        inputTokens: 40,
        outputTokens: 15,
      },
    ]);
  });

  test("extracts usage across split SSE chunks, OpenAI Responses, and Gemini usageMetadata", async () => {
    const encoder = new TextEncoder();
    const upstream = trackServer(
      Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch(req) {
          const url = new URL(req.url);
          if (url.pathname === "/v1/magpie/limit") {
            return Response.json({ key: "ss-alice" });
          }
          if (url.pathname === "/v1/responses") {
            const full =
              'event: response.created\ndata: {"type":"response.created","response":{"id":"r1"}}\n\n' +
              'event: response.completed\ndata: {"type":"response.completed","response":{"model":"gpt-5.4","usage":{"input_tokens":88,"output_tokens":21}}}\n\n';
            const mid = Math.floor(full.length / 2) + 12; // Split right in middle of JSON line
            const body = new ReadableStream({
              start(ctrl) {
                ctrl.enqueue(encoder.encode(full.slice(0, mid)));
                ctrl.enqueue(encoder.encode(full.slice(mid)));
                ctrl.close();
              },
            });
            return new Response(body, {
              status: 200,
              headers: { "content-type": "text/event-stream" },
            });
          }
          if (url.pathname === "/v1beta/models/gemini-2.5-flash:streamGenerateContent") {
            const body = new ReadableStream({
              start(ctrl) {
                ctrl.enqueue(
                  encoder.encode(
                    'data: {"candidates":[{"content":{"parts":[{"text":"hi"}]}}],"usageMetadata":{"promptTokenCount":55,"candidatesTokenCount":12},"modelVersion":"gemini-2.5-flash"}\n\n',
                  ),
                );
                ctrl.close();
              },
            });
            return new Response(body, {
              status: 200,
              headers: { "content-type": "text/event-stream" },
            });
          }
          return new Response("not found", { status: 404 });
        },
      }),
    );

    const state = {
      sharingEnabled: true,
      visibility: { limit: true, quotas: false },
      members: [
        { id: "m-alice", status: "active", magpieKeyName: "ss-alice", magpieKeySecret: "sk-magpie-key-alice" },
      ],
    };
    const usageEvents = [];
    const handler = createHostGatewayHandler({
      store: { get: () => state },
      getGatewayUrl: () => `http://127.0.0.1:${upstream.port}`,
      onUsage: (u) => usageEvents.push(u),
    });

    const r1 = await handler.handleHttpRequest("m-alice", {
      method: "POST",
      path: "/v1/responses",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "codex/gpt-5.4", input: "hi" }),
    });
    expect(r1.status).toBe(200);
    await new Response(r1.body).text();

    const r2 = await handler.handleHttpRequest("m-alice", {
      method: "POST",
      path: "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ contents: [] }),
    });
    expect(r2.status).toBe(200);
    await new Response(r2.body).text();

    expect(usageEvents).toEqual([
      {
        memberId: "m-alice",
        model: "codex/gpt-5.4",
        inputTokens: 88,
        outputTokens: 21,
      },
      {
        memberId: "m-alice",
        model: "gemini-2.5-flash",
        inputTokens: 55,
        outputTokens: 12,
      },
    ]);
  });
});
