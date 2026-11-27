import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";

import { parseTokenFromHtml, runCli } from "../bin/simple-share.mjs";
import {
  buildGitHubIssueUrl,
  GITHUB_ISSUES_NEW_URL,
  startServer,
  TOKEN_HEADER,
} from "../lib/server.mjs";

const cleanups = [];
const tempDirs = [];

function makeTempDir(prefix = "ss-sec-") {
  const d = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(d);
  return d;
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

describe("Wave 2 control-plane, pairing, bridge & host-gateway security", () => {
  test("control-plane enforces session token, Origin, Host, traversal block, and zero secret leakage", async () => {
    const dir = makeTempDir("ss-cp-");
    const srv = await startServer({
      port: 0,
      dataDir: dir,
      env: { ...process.env, MAGPIE_ADDR: "127.0.0.1:59991" },
      transportOptions: { directBindHost: "127.0.0.1" },
      discoverGatewayFn: async () => ({ ok: false, running: false, url: "", addr: "", version: "" }),
      fetchModelsFn: async () => [],
    });
    cleanups.push(() => srv.close());

    // 1. /api/health works without token
    const healthRes = await fetch(`${srv.url}/api/health`);
    expect(healthRes.status).toBe(200);
    expect((await healthRes.json()).ok).toBe(true);

    // 2. GET / injects token meta and omits CORS
    const htmlRes = await fetch(`${srv.url}/`);
    expect(htmlRes.status).toBe(200);
    expect(htmlRes.headers.get("access-control-allow-origin")).toBeNull();
    const html = await htmlRes.text();
    const extractedToken = parseTokenFromHtml(html);
    expect(extractedToken).toBe(srv.token);
    expect(extractedToken.length).toBe(64);

    // 3. /api/state rejects missing or wrong token
    expect((await fetch(`${srv.url}/api/state`)).status).toBe(401);
    expect(
      (await fetch(`${srv.url}/api/state`, { headers: { [TOKEN_HEADER]: "wrong" } })).status,
    ).toBe(401);

    // 4. Rejects foreign Origin without CORS headers, allows Origin: null (Magpie iframe sandbox)
    const evilOrigin = await fetch(`${srv.url}/api/state`, {
      headers: { [TOKEN_HEADER]: srv.token, origin: "https://evil.example.com" },
    });
    expect(evilOrigin.status).toBe(403);
    expect(evilOrigin.headers.get("access-control-allow-origin")).toBeNull();

    const sandboxOrigin = await fetch(`${srv.url}/api/state`, {
      headers: { [TOKEN_HEADER]: srv.token, origin: "null" },
    });
    expect(sandboxOrigin.status).toBe(200);
    expect(sandboxOrigin.headers.get("access-control-allow-origin")).toBe("null");

    // 5. Rejects DNS rebinding Host header
    const badHost = await fetch(`${srv.url}/api/state`, {
      headers: { [TOKEN_HEADER]: srv.token, host: "evil.example.com" },
    });
    expect(badHost.status).toBe(403);

    // 6. Rejects path traversal on static files
    const trav = await fetch(`${srv.url}/../package.json`);
    expect(trav.status).toBe(404);
    const encTrav = await fetch(`${srv.url}/%2e%2e/package.json`);
    expect(encTrav.status).toBe(404);

    // 7. Never leaks private key material
    const stateText = await sandboxOrigin.text();
    expect(stateText).not.toContain(srv.identity.seedHex);
    expect(stateText).not.toContain("PRIVATE KEY");
    expect(stateText).not.toContain(srv.token);
  });

  test("full red-team E2E: pairing, bridge auth, path block, Fail-Closed oracle, pause, and isolated live SSE abort", async () => {
    const encoder = new TextEncoder();
    const validMagpieKeys = new Map(); // secret -> keyName
    const activeSlowStreams = new Map(); // keyName -> ctrl
    const abortedUpstream = [];
    let dangerHitCount = 0;
    let chatForwardCount = 0;

    // Mock local Magpie gateway for Host
    const upstreamMagpie = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(req) {
        const path = new URL(req.url).pathname;
        if (path === "/api/hello") {
          return Response.json({ name: "magpie", version: "0.1.4572" });
        }
        if (path === "/v1/models") {
          return Response.json({
            object: "list",
            data: [
              { id: "deepseek/deepseek-chat", display_name: "DeepSeek Chat", owned_by: "deepseek" },
              { id: "claude/claude-sonnet-4-6", display_name: "claude-sonnet-4-6", owned_by: "claude" },
            ],
          });
        }
        if (path === "/v1/magpie/limit") {
          const auth = req.headers.get("authorization") || "";
          const secret = auth.replace(/^Bearer\s+/i, "");
          const keyName = validMagpieKeys.get(secret) || "";
          // Reproduces real Magpie behavior: empty key returns 200 {"key":""}!
          return Response.json({ key: keyName, limited: Boolean(keyName) });
        }
        if (
          path.startsWith("/v1/magpie/admin") ||
          path.startsWith("/v1/magpie/native") ||
          path.startsWith("/mcp")
        ) {
          dangerHitCount += 1;
          return Response.json({ pwned: true }, { status: 200 });
        }
        if (path === "/v1/chat/completions") {
          chatForwardCount += 1;
          const auth = req.headers.get("authorization") || "";
          const secret = auth.replace(/^Bearer\s+/i, "");
          const keyName = validMagpieKeys.get(secret) || "unrestricted";
          const mode = req.headers.get("x-test-mode") || "fast";

          if (mode === "slow-sse") {
            const stream = new ReadableStream({
              start(ctrl) {
                activeSlowStreams.set(keyName, ctrl);
                ctrl.enqueue(encoder.encode(`data: {"key":"${keyName}","chunk":1}\n\n`));
                req.signal.addEventListener("abort", () => {
                  abortedUpstream.push(keyName);
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

          return Response.json({
            id: "chat-ok",
            model: "deepseek-chat",
            choices: [{ message: { role: "assistant", content: "SECRET_PROMPT_REPLY_OK" } }],
            usage: { prompt_tokens: 25, completion_tokens: 10 },
          });
        }
        return new Response("not found", { status: 404 });
      },
    });
    cleanups.push(() => upstreamMagpie.stop(true));

    const gwAddr = `127.0.0.1:${upstreamMagpie.port}`;
    const hostDir = makeTempDir("ss-host-");
    const aliceDir = makeTempDir("ss-alice-");
    const bobDir = makeTempDir("ss-bob-");

    let keySeq = 0;
    const mockCreateKey = async ({ name }) => {
      keySeq += 1;
      const keyId = `kid-${keySeq}`;
      const keySecret = `sk-magpie-key-hostonly-${keySeq}-${name}`;
      validMagpieKeys.set(keySecret, name);
      return { keyId, keyName: name, keySecret };
    };
    const mockRemoveKey = async ({ keyId }) => {
      for (const [secret] of validMagpieKeys.entries()) {
        if (secret.includes(`-${keyId.replace("kid-", "")}-`)) {
          validMagpieKeys.delete(secret);
        }
      }
      return { ok: true, keyId };
    };
    const providerRegistrations = [];

    const hostSrv = await startServer({
      port: 0,
      dataDir: hostDir,
      env: { ...process.env, MAGPIE_ADDR: gwAddr },
      transportOptions: { directBindHost: "127.0.0.1" },
      createKeyFn: mockCreateKey,
      updateKeyFn: async ({ keyId }) => ({ ok: true, keyId }),
      removeKeyFn: mockRemoveKey,
    });
    cleanups.push(() => hostSrv.close());

    const aliceSrv = await startServer({
      port: 0,
      dataDir: aliceDir,
      env: { ...process.env, MAGPIE_ADDR: "127.0.0.1:59992" },
      transportOptions: { directBindHost: "127.0.0.1" },
      discoverGatewayFn: async () => ({ ok: false, running: false, url: "", addr: "", version: "" }),
      fetchModelsFn: async () => [],
      addProviderFn: async (p) => {
        providerRegistrations.push(p);
        return { ok: true, ...p };
      },
      removeProviderFn: async ({ id }) => ({ ok: true, id }),
    });
    cleanups.push(() => aliceSrv.close());

    const bobSrv = await startServer({
      port: 0,
      dataDir: bobDir,
      env: { ...process.env, MAGPIE_ADDR: "127.0.0.1:59993" },
      transportOptions: { directBindHost: "127.0.0.1" },
      discoverGatewayFn: async () => ({ ok: false, running: false, url: "", addr: "", version: "" }),
      fetchModelsFn: async () => [],
      addProviderFn: async (p) => ({ ok: true, ...p }),
      removeProviderFn: async ({ id }) => ({ ok: true, id }),
    });
    cleanups.push(() => bobSrv.close());

    const hostApi = (path, init = {}) =>
      fetch(`${hostSrv.url}${path}`, {
        ...init,
        headers: {
          [TOKEN_HEADER]: hostSrv.token,
          ...(init.body ? { "content-type": "application/json" } : {}),
          ...(init.headers || {}),
        },
      });
    const recvApi = (srv, path, init = {}) =>
      fetch(`${srv.url}${path}`, {
        ...init,
        headers: {
          [TOKEN_HEADER]: srv.token,
          ...(init.body ? { "content-type": "application/json" } : {}),
          ...(init.headers || {}),
        },
      });

    // 1. Configure Mode 3 on 127.0.0.1 with ephemeral direct port; test ToS gate
    const tosFail = await hostApi("/api/host/toggle", {
      method: "POST",
      body: JSON.stringify({ enabled: true }),
    });
    expect(tosFail.status).toBe(400);

    // Pick free ephemeral port by reserving briefly or binding directPort 0? Let's find a free port first:
    const probeSrv = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response("") });
    const directPort = probeSrv.port;
    probeSrv.stop(true);

    const modeRes = await hostApi("/api/network/mode", {
      method: "POST",
      body: JSON.stringify({
        mode: "direct",
        network: { directHost: "127.0.0.1", directPort },
      }),
    });
    expect(modeRes.status).toBe(200);

    const toggleOk = await hostApi("/api/host/toggle", {
      method: "POST",
      body: JSON.stringify({ enabled: true, tosAcknowledged: true }),
    });
    expect(toggleOk.status).toBe(200);

    // 2. Pair Alice and Bob via full mTLS PAIR_ALPN + 4-digit SAS
    async function pairDevice(recvSrv, deviceName) {
      const invRes = await hostApi("/api/host/invites", { method: "POST" });
      expect(invRes.status).toBe(200);
      const inv = await invRes.json();
      expect(inv.code.startsWith("mshare1:")).toBe(true);

      const parseRes = await recvApi(recvSrv, "/api/receiver/parse", {
        method: "POST",
        body: JSON.stringify({ code: inv.code }),
      });
      expect(parseRes.status).toBe(200);

      const applyRes = await recvApi(recvSrv, "/api/receiver/apply", {
        method: "POST",
        body: JSON.stringify({ code: inv.code, deviceName }),
      });
      expect(applyRes.status).toBe(200);
      const applied = await applyRes.json();
      const recvSas = applied.pending.sas;

      const hostState = await (await hostApi("/api/state")).json();
      const hostPend = hostState.pending.find((p) => p.name === deviceName);
      expect(hostPend).toBeDefined();
      expect(hostPend.sas).toBe(recvSas);

      const appRes = await hostApi(`/api/host/pending/${encodeURIComponent(hostPend.id)}/approve`, {
        method: "POST",
        body: JSON.stringify({
          models: ["deepseek/deepseek-chat"],
          period: "day",
          costLimit: 5,
          tokenLimitWan: 100,
          concurrency: 2,
        }),
      });
      expect(appRes.status).toBe(200);
      const appData = await appRes.json();

      // Wait for receiver background watcher to finalize share & start local bridge
      let share = null;
      for (let i = 0; i < 40; i++) {
        const rs = await (await recvApi(recvSrv, "/api/state")).json();
        if (rs.received.length > 0 && !rs.receiverPending) {
          share = rs.received[0];
          break;
        }
        await Bun.sleep(25);
      }
      expect(share).not.toBeNull();
      return { member: appData.member, share };
    }

    const alice = await pairDevice(aliceSrv, "Alice-PC");
    const bob = await pairDevice(bobSrv, "Bob-PC");

    // Verify zero secrets in /api/state on both host and receiver
    const hostStateRaw = await (await hostApi("/api/state")).text();
    const aliceStateRaw = await (await recvApi(aliceSrv, "/api/state")).text();
    for (const secret of validMagpieKeys.keys()) {
      expect(hostStateRaw).not.toContain(secret);
      expect(aliceStateRaw).not.toContain(secret);
    }
    expect(aliceStateRaw).not.toContain("bridgeToken");
    expect(providerRegistrations.length).toBe(1);
    expect(providerRegistrations[0].bridgeUrl).toBe(`http://127.0.0.1:${alice.share.bridgePort}`);

    const aliceBridgeUrl = `http://127.0.0.1:${alice.share.bridgePort}`;
    const aliceBridgeToken = aliceSrv.store.get().received[0].bridgeToken;
    const bobBridgeUrl = `http://127.0.0.1:${bob.share.bridgePort}`;
    const bobBridgeToken = bobSrv.store.get().received[0].bridgeToken;

    // 3. Bridge rejects missing/bad token
    expect((await fetch(`${aliceBridgeUrl}/v1/models`)).status).toBe(401);
    expect(
      (await fetch(`${aliceBridgeUrl}/v1/models`, { headers: { authorization: "Bearer bad" } })).status,
    ).toBe(401);

    // 4. End-to-end test button works
    const testRes = await recvApi(aliceSrv, `/api/receiver/shares/${encodeURIComponent(alice.share.id)}/test`, {
      method: "POST",
      body: JSON.stringify({ model: "deepseek/deepseek-chat" }),
    });
    expect(testRes.status).toBe(200);
    const testJson = await testRes.json();
    expect(testJson.ok).toBe(true);
    expect(testJson.usage.totalTokens).toBe(35);

    // 5. Path allowlist & traversal blocked over full bridge->mTLS->gateway pipeline
    for (const blockedPath of [
      "/v1/magpie/admin/providers",
      "/v1/%2e%2e/magpie/admin/providers",
      "/v1/magpie/native/status",
      "/mcp",
    ]) {
      const r = await fetch(`${aliceBridgeUrl}${blockedPath}`, {
        headers: { authorization: `Bearer ${aliceBridgeToken}` },
      });
      expect(r.status).toBe(403);
      expect((await r.json()).code).toBe("forbidden_path");
    }
    expect(dangerHitCount).toBe(0);

    // 6. Fail-Closed oracle: delete Alice key on upstream Magpie -> 403 key_revoked_or_invalid, NEVER forwards
    const aliceMemberRaw = hostSrv.store.get().members.find((m) => m.id === alice.member.id);
    validMagpieKeys.delete(aliceMemberRaw.magpieKeySecret);
    const beforeForwardCount = chatForwardCount;
    const revokedOracleRes = await fetch(`${aliceBridgeUrl}/v1/chat/completions`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${aliceBridgeToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ model: "deepseek/deepseek-chat", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(revokedOracleRes.status).toBe(403);
    expect((await revokedOracleRes.json()).code).toBe("key_revoked_or_invalid");
    expect(chatForwardCount).toBe(beforeForwardCount);
    // Restore key for remaining tests
    validMagpieKeys.set(aliceMemberRaw.magpieKeySecret, aliceMemberRaw.magpieKeyName);

    // 7. Pause returns 403 share_paused, resume restores access
    const pauseRes = await hostApi(`/api/host/members/${encodeURIComponent(alice.member.id)}/pause`, {
      method: "POST",
      body: JSON.stringify({ paused: true }),
    });
    expect(pauseRes.status).toBe(200);
    const pausedCall = await fetch(`${aliceBridgeUrl}/v1/models`, {
      headers: { authorization: `Bearer ${aliceBridgeToken}` },
    });
    expect(pausedCall.status).toBe(403);
    expect((await pausedCall.json()).code).toBe("share_paused");

    await hostApi(`/api/host/members/${encodeURIComponent(alice.member.id)}/pause`, {
      method: "POST",
      body: JSON.stringify({ paused: false }),
    });
    expect(
      (await fetch(`${aliceBridgeUrl}/v1/models`, { headers: { authorization: `Bearer ${aliceBridgeToken}` } })).status,
    ).toBe(200);

    // 8. Revoke Alice while BOTH Alice and Bob hold live slow SSE streams:
    // Alice aborts immediately; Bob completes cleanly!
    const bobMemberRaw = hostSrv.store.get().members.find((m) => m.id === bob.member.id);
    const sseAliceRes = await fetch(`${aliceBridgeUrl}/v1/chat/completions`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${aliceBridgeToken}`,
        "content-type": "application/json",
        "x-test-mode": "slow-sse",
      },
      body: JSON.stringify({ model: "deepseek/deepseek-chat", stream: true }),
    });
    const sseBobRes = await fetch(`${bobBridgeUrl}/v1/chat/completions`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${bobBridgeToken}`,
        "content-type": "application/json",
        "x-test-mode": "slow-sse",
      },
      body: JSON.stringify({ model: "deepseek/deepseek-chat", stream: true }),
    });
    expect(sseAliceRes.status).toBe(200);
    expect(sseBobRes.status).toBe(200);

    const readerA = sseAliceRes.body.getReader();
    const readerB = sseBobRes.body.getReader();
    const chunkA1 = await readerA.read();
    expect(new TextDecoder().decode(chunkA1.value)).toContain(aliceMemberRaw.magpieKeyName);
    const chunkB1 = await readerB.read();
    expect(new TextDecoder().decode(chunkB1.value)).toContain(bobMemberRaw.magpieKeyName);

    const pendingReadA = readerA.read();
    const delRes = await hostApi(`/api/host/members/${encodeURIComponent(alice.member.id)}`, {
      method: "DELETE",
    });
    expect(delRes.status).toBe(200);

    // Alice's stream must abort or end with error immediately (never hang!)
    let aliceEndedOrErrored = false;
    try {
      const nextA = await pendingReadA;
      aliceEndedOrErrored = Boolean(nextA.done);
    } catch {
      aliceEndedOrErrored = true;
    }
    expect(aliceEndedOrErrored).toBe(true);

    // Bob's stream completes normally with usage recorded
    const bobCtrl = activeSlowStreams.get(bobMemberRaw.magpieKeyName);
    bobCtrl.enqueue(
      encoder.encode(
        'data: {"model":"deepseek/deepseek-chat","usage":{"prompt_tokens":60,"completion_tokens":20}}\n\ndata: [DONE]\n\n',
      ),
    );
    bobCtrl.close();

    let bobTail = "";
    while (true) {
      const { done, value } = await readerB.read();
      if (done) break;
      bobTail += new TextDecoder().decode(value);
    }
    expect(bobTail).toContain("[DONE]");

    // Verify usage recorded for Bob (async disk write completes cleanly) and prompt/response text NEVER persisted on disk
    let usageJson = null;
    for (let i = 0; i < 30; i++) {
      const usageRes = await hostApi("/api/host/usage?range=7d");
      expect(usageRes.status).toBe(200);
      usageJson = await usageRes.json();
      if (usageJson.usageByMember?.[bob.member.id]?.["7d"]?.length > 0) break;
      await Bun.sleep(20);
    }
    expect(usageJson.usageByMember[bob.member.id]["7d"][0].inputTokens).toBe(60);
    expect(usageJson.usageByMember[bob.member.id]["7d"][0].outputTokens).toBe(20);

    const hostStateDisk = readFileSync(join(hostDir, "state.json"), "utf8");
    expect(hostStateDisk).not.toContain("SECRET_PROMPT_REPLY_OK");
  });

  test("CLI --help and doctor --json work in isolated env and reject non-loopback --url", async () => {
    const dir = makeTempDir("ss-cli-");
    const env = {
      ...process.env,
      MAGPIE_SIMPLE_SHARE_DATA: dir,
      MAGPIE_ADDR: "127.0.0.1:59994",
    };

    const helpBuf = [];
    const helpCode = await runCli(["--help"], {
      env,
      stdout: { write: (s) => helpBuf.push(s) },
      stderr: { write: () => {} },
    });
    expect(helpCode).toBe(0);
    expect(helpBuf.join("")).toContain("magpie-simple-share");

    const docBuf = [];
    const docCode = await runCli(["doctor", "--json", "--port", "59995"], {
      env,
      stdout: { write: (s) => docBuf.push(s) },
      stderr: { write: () => {} },
    });
    expect(docCode).toBe(0);
    const doc = JSON.parse(docBuf.join(""));
    expect(doc.ok).toBe(true);
    expect(doc.controlPlane.running).toBe(false);
    expect(doc.security.noTun).toBe(true);
    expect(doc.security.controlPlaneLoopbackOnly).toBe(true);
    expect(doc.identity.fingerprint.startsWith("ed25519:")).toBe(true);

    await expect(
      runCli(["status", "--url", "http://evil.example.com:3494"], {
        env,
        stdout: new PassThrough(),
        stderr: new PassThrough(),
      }),
    ).rejects.toThrow(/loopback/);
  });

  test("invite brute-force burn (5 attempts), restart recovery, visibility/edit/leave, and live CLI", async () => {
    const { startBlindRelay } = await import("../relay/simple-share-relay.mjs");
    const { createFramedChannel, FRAME } = await import("../lib/wire.mjs");

    const relay = await startBlindRelay({ host: "127.0.0.1", port: 0, token: "r-tok-1" });
    cleanups.push(() => relay.close());

    const upstreamMagpie = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(req) {
        const path = new URL(req.url).pathname;
        if (path === "/api/hello") return Response.json({ name: "magpie", version: "0.1.4572" });
        if (path === "/v1/models") {
          return Response.json({ object: "list", data: [{ id: "deepseek/deepseek-chat", owned_by: "deepseek" }] });
        }
        if (path === "/v1/magpie/limit") {
          const auth = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
          return Response.json({ key: auth ? "ss-persist" : "" });
        }
        return Response.json({ ok: true });
      },
    });
    cleanups.push(() => upstreamMagpie.stop(true));

    const hostDir = makeTempDir("ss-persist-h-");
    const recvDir = makeTempDir("ss-persist-r-");
    const gwAddr = `127.0.0.1:${upstreamMagpie.port}`;

    const startHost = () =>
      startServer({
        port: 0,
        dataDir: hostDir,
        env: { ...process.env, MAGPIE_ADDR: gwAddr },
        transportOptions: { directBindHost: "127.0.0.1" },
        createKeyFn: async () => ({
          keyId: "kid-p1",
          keyName: "ss-persist",
          keySecret: "sk-magpie-key-persist",
        }),
        updateKeyFn: async ({ keyId }) => ({ ok: true, keyId }),
        removeKeyFn: async ({ keyId }) => ({ ok: true, keyId }),
      });

    const startRecv = () =>
      startServer({
        port: 0,
        dataDir: recvDir,
        env: { ...process.env, MAGPIE_ADDR: "127.0.0.1:59996" },
        transportOptions: { directBindHost: "127.0.0.1" },
        discoverGatewayFn: async () => ({ ok: false, running: false, url: "", addr: "", version: "" }),
        fetchModelsFn: async () => [],
        addProviderFn: async (p) => ({ ok: true, ...p }),
        removeProviderFn: async ({ id }) => ({ ok: true, id }),
      });

    let hostSrv = await startHost();
    let recvSrv = await startRecv();
    let hostClosed = false;
    let recvClosed = false;
    cleanups.push(async () => {
      if (!hostClosed) await hostSrv.close();
      if (!recvClosed) await recvSrv.close();
    });

    const api = (srv, path, init = {}) =>
      fetch(`${srv.url}${path}`, {
        ...init,
        headers: {
          [TOKEN_HEADER]: srv.token,
          ...(init.body ? { "content-type": "application/json" } : {}),
        },
      });

    // Switch host to Mode 2 self-relay, test relay probe, enable sharing
    await api(hostSrv, "/api/network/mode", {
      method: "POST",
      body: JSON.stringify({
        mode: "self-relay",
        network: { relayAddr: `127.0.0.1:${relay.port}`, relayToken: "r-tok-1" },
      }),
    });
    const relayCheck = await (
      await api(hostSrv, "/api/network/test-relay", {
        method: "POST",
        body: JSON.stringify({ relayAddr: `127.0.0.1:${relay.port}`, relayToken: "r-tok-1" }),
      })
    ).json();
    expect(relayCheck.ok).toBe(true);
    expect(relayCheck.blindVerified).toBe(true);

    await api(hostSrv, "/api/host/toggle", {
      method: "POST",
      body: JSON.stringify({ enabled: true, tosAcknowledged: true }),
    });
    await api(hostSrv, "/api/host/name", {
      method: "POST",
      body: JSON.stringify({ hostName: "Studio-PC" }),
    });

    // Test invite brute-force auto-burn after 5 bad secret attempts
    const inv1 = await (await api(hostSrv, "/api/host/invites", { method: "POST" })).json();
    const parsed1 = await (
      await api(recvSrv, "/api/receiver/parse", {
        method: "POST",
        body: JSON.stringify({ code: inv1.code }),
      })
    ).json();

    for (let attempt = 0; attempt < 5; attempt++) {
      const conn = await recvSrv.transportManager.dialPair({
        m: "self-relay",
        pk: hostSrv.identity.pubKeyHex,
        ep: parsed1.ep,
      });
      await conn.channel.sendFrame(FRAME.PAIR_REQ, {
        action: "apply",
        inviteId: parsed1.id,
        inviteSecret: `wrong-secret-${attempt}`,
        deviceName: "Attacker",
        clientPubKeyHex: recvSrv.identity.pubKeyHex,
        clientCertPem: recvSrv.identity.certPem,
      });
      const resp = JSON.parse(Buffer.from((await conn.channel.onceFrame(FRAME.PAIR_STATUS, 5000)).payload).toString("utf8"));
      expect(resp.status).toBe("error");
      await conn.close();
    }

    // 1) With no other active invites, PAIR_ALPN refuses the burned invite at TLS layer (502)
    const burnedRes1 = await api(recvSrv, "/api/receiver/apply", {
      method: "POST",
      body: JSON.stringify({ code: inv1.code, deviceName: "Real-Client" }),
    });
    expect(burnedRes1.status).toBe(502);

    // 2) Even if another active invite keeps PAIR_ALPN open, burned inv1 is rejected at pairing layer (400)
    const invTmp = await (await api(hostSrv, "/api/host/invites", { method: "POST" })).json();
    const burnedRes2 = await api(recvSrv, "/api/receiver/apply", {
      method: "POST",
      body: JSON.stringify({ code: inv1.code, deviceName: "Real-Client" }),
    });
    expect(burnedRes2.status).toBe(400);

    // Also test invite revoke
    expect(
      (await api(hostSrv, `/api/host/invites/${encodeURIComponent(invTmp.id)}`, { method: "DELETE" })).status,
    ).toBe(200);

    // Now pair cleanly via Mode 2 Blind Relay and live CLI commands
    const inv2 = await (await api(hostSrv, "/api/host/invites", { method: "POST" })).json();
    await api(recvSrv, "/api/receiver/apply", {
      method: "POST",
      body: JSON.stringify({ code: inv2.code, deviceName: "Mom-Mac" }),
    });

    // Live CLI pending & approve
    const pendOut = [];
    expect(
      await runCli(["pending", "--json", "--url", hostSrv.url], {
        stdout: { write: (s) => pendOut.push(s) },
        stderr: { write: () => {} },
      }),
    ).toBe(0);
    const pendList = JSON.parse(pendOut.join("")).pending;
    expect(pendList.length).toBe(1);

    const appOut = [];
    expect(
      await runCli(
        ["approve", pendList[0].id, "--models", "deepseek/deepseek-chat", "--url", hostSrv.url, "--json"],
        {
          stdout: { write: (s) => appOut.push(s) },
          stderr: { write: () => {} },
        },
      ),
    ).toBe(0);
    const approved = JSON.parse(appOut.join(""));
    expect(approved.ok).toBe(true);

    // Wait for receiver Mode 2 approval finalization
    let share = null;
    for (let i = 0; i < 40; i++) {
      const rs = await (await api(recvSrv, "/api/state")).json();
      if (rs.received.length > 0 && !rs.receiverPending) {
        share = rs.received[0];
        break;
      }
      await Bun.sleep(25);
    }
    expect(share).not.toBeNull();
    expect(share.mode).toBe("self-relay");

    // Host member PATCH & visibility update
    expect(
      (
        await api(hostSrv, `/api/host/members/${encodeURIComponent(approved.member.id)}`, {
          method: "PATCH",
          body: JSON.stringify({ name: "Mom-Updated", costLimit: 10 }),
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await api(hostSrv, "/api/host/visibility", {
          method: "POST",
          body: JSON.stringify({ quotas: true }),
        })
      ).status,
    ).toBe(200);

    // Restart BOTH host and receiver on same dataDirs -> auto-restores Mode 2 relay + local bridge!
    await hostSrv.close();
    hostClosed = true;
    await recvSrv.close();
    recvClosed = true;

    hostSrv = await startHost();
    hostClosed = false;
    recvSrv = await startRecv();
    recvClosed = false;

    const restoredHostState = await (await api(hostSrv, "/api/state")).json();
    expect(restoredHostState.sharingEnabled).toBe(true);
    expect(restoredHostState.identity.hostName).toBe("Studio-PC");
    expect(restoredHostState.members[0].name).toBe("Mom-Updated");

    const restoredRecvState = await (await api(recvSrv, "/api/state")).json();
    expect(restoredRecvState.received.length).toBe(1);
    const restoredBridgeToken = recvSrv.store.get().received[0].bridgeToken;
    const restoredBridgePort = restoredRecvState.received[0].bridgePort;

    // Poll briefly for host-ctl reconnect to blind relay then verify bridge works after restart
    let modelsOk = false;
    for (let i = 0; i < 20; i++) {
      const r = await fetch(`http://127.0.0.1:${restoredBridgePort}/v1/models`, {
        headers: { authorization: `Bearer ${restoredBridgeToken}` },
      });
      if (r.status === 200) {
        modelsOk = true;
        break;
      }
      await Bun.sleep(50);
    }
    expect(modelsOk).toBe(true);

    // Leave share via DELETE /api/receiver/shares/:id
    expect(
      (await api(recvSrv, `/api/receiver/shares/${encodeURIComponent(share.id)}`, { method: "DELETE" })).status,
    ).toBe(200);
    expect((await (await api(recvSrv, "/api/state")).json()).received.length).toBe(0);
  });

  test("UI client api() strips leading slashes so requests resolve relative to magpie web service proxy path", () => {
    const appSource = readFileSync(join(import.meta.dir, "..", "ui", "app.js"), "utf8");
    expect(appSource).toContain('const reqPath = path.startsWith("/") ? path.slice(1) : path;');
    expect(appSource).toContain("await fetch(reqPath,");
  });

  test("buildGitHubIssueUrl and POST /api/feedback/open enforce GitHub origin, label allowlist, auth, and safe length cap", async () => {
    const basic = buildGitHubIssueUrl({
      title: "Line1\nLine2",
      body: "Body\0text",
      labels: ["bug", "arbitrary-label", "enhancement", "bug"],
    });
    expect(basic.truncated).toBe(false);
    expect(basic.url.startsWith(`${GITHUB_ISSUES_NEW_URL}?`)).toBe(true);
    const parsedBasic = new URL(basic.url);
    expect(parsedBasic.searchParams.get("title")).toBe("Line1 Line2");
    expect(parsedBasic.searchParams.get("labels")).toBe("bug,enhancement");
    expect(parsedBasic.searchParams.get("body")).toBe("Bodytext");

    const longBody = "排查日志：".repeat(600);
    const capped = buildGitHubIssueUrl({
      title: "长报告测试",
      body: longBody,
      labels: "bug",
    });
    expect(capped.truncated).toBe(true);
    expect(capped.url.length).toBeLessThanOrEqual(1900);
    expect(new URL(capped.url).searchParams.get("body")).toContain("内容较长已截断");

    const dir = makeTempDir("ss-fb-");
    const openedUrls = [];
    let shouldFailOpen = false;
    const srv = await startServer({
      port: 0,
      dataDir: dir,
      env: { ...process.env, MAGPIE_ADDR: "127.0.0.1:59991" },
      transportOptions: { directBindHost: "127.0.0.1" },
      discoverGatewayFn: async () => ({ ok: false, running: false, url: "", addr: "", version: "" }),
      fetchModelsFn: async () => [],
      openIssueUrlFn: async (url) => {
        openedUrls.push(url);
        if (shouldFailOpen) throw new Error("headless display unavailable");
      },
    });
    cleanups.push(() => srv.close());

    // /api/state exposes safe runtime environment only
    const stateRes = await fetch(`${srv.url}/api/state`, {
      headers: { [TOKEN_HEADER]: srv.token },
    });
    expect(stateRes.status).toBe(200);
    const stateJson = await stateRes.json();
    expect(stateJson.environment).toEqual({
      platform: process.platform,
      arch: process.arch,
      bunVersion: process.versions?.bun || "",
    });

    // Rejects missing/bad token, foreign origin, and non-POST method
    expect((await fetch(`${srv.url}/api/feedback/open`, { method: "POST" })).status).toBe(401);
    expect(
      (
        await fetch(`${srv.url}/api/feedback/open`, {
          method: "POST",
          headers: { [TOKEN_HEADER]: srv.token, origin: "https://evil.example.com" },
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await fetch(`${srv.url}/api/feedback/open`, {
          method: "GET",
          headers: { [TOKEN_HEADER]: srv.token },
        })
      ).status,
    ).toBe(405);

    // Ignores client-supplied url and strictly builds GitHub Issues URL
    const okRes = await fetch(`${srv.url}/api/feedback/open`, {
      method: "POST",
      headers: {
        [TOKEN_HEADER]: srv.token,
        origin: "null",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        url: "https://evil.example.com/phish",
        title: "[Bug] 配对失败",
        body: "详情描述",
        labels: ["bug", "pwned"],
      }),
    });
    expect(okRes.status).toBe(200);
    const okBody = await okRes.json();
    expect(okBody.ok).toBe(true);
    expect(okBody.url.startsWith(`${GITHUB_ISSUES_NEW_URL}?`)).toBe(true);
    expect(okBody.url).not.toContain("evil.example.com");
    expect(new URL(okBody.url).searchParams.get("labels")).toBe("bug");
    expect(openedUrls).toEqual([okBody.url]);

    // When OS browser launch fails, still returns HTTP 200 with ok: false + copyable URL
    shouldFailOpen = true;
    const failRes = await fetch(`${srv.url}/api/feedback/open`, {
      method: "POST",
      headers: {
        [TOKEN_HEADER]: srv.token,
        origin: "null",
        "content-type": "application/json",
      },
      body: JSON.stringify({ title: "Test fail fallback", body: "desc", labels: "enhancement" }),
    });
    expect(failRes.status).toBe(200);
    const failBody = await failRes.json();
    expect(failBody.ok).toBe(false);
    expect(failBody.url.startsWith(`${GITHUB_ISSUES_NEW_URL}?`)).toBe(true);
    expect(failBody.message).toContain("headless display unavailable");
  });
});
