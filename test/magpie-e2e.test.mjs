import { afterEach, describe, expect, test } from "bun:test";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";

import { getIrohStatus, installIroh, platformPackageName } from "../lib/iroh-installer.mjs";
import { startServer, TOKEN_HEADER } from "../lib/server.mjs";
import { sendHttpRequestOverChannel } from "../lib/wire.mjs";
import { startBlindRelay } from "../relay/simple-share-relay.mjs";
import { hasTestMagpieBin, resolveTestMagpieBin, stageLocalIrohDir } from "./helpers/platform.mjs";

const REPO_ROOT = path.resolve(import.meta.dir, "..");
const CLI_PATH = path.join(REPO_ROOT, "bin", "simple-share.mjs");
const MAGPIE_BIN = resolveTestMagpieBin(process.env);
const HAS_MAGPIE = hasTestMagpieBin(process.env);
const magpieTest = HAS_MAGPIE || process.env.REQUIRE_MAGPIE_E2E === "1" ? test : test.skip;

const activeCleanups = [];
const tempDirs = [];

function makeTempDir(prefix = "ss-e2e-") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function makeIsolatedEnv(baseDir, magpiePort) {
  const dataDir = path.join(baseDir, "ss-data");
  return {
    ...process.env,
    HOME: baseDir,
    USERPROFILE: baseDir,
    XDG_CONFIG_HOME: path.join(baseDir, "cfg"),
    XDG_CACHE_HOME: path.join(baseDir, "cache"),
    LOCALAPPDATA: path.join(baseDir, "local"),
    APPDATA: path.join(baseDir, "roam"),
    MAGPIE_CONFIG_DIR: path.join(baseDir, "cfg", "magpie"),
    MAGPIE_SIMPLE_SHARE_DATA: dataDir,
    MAGPIE_SIMPLE_SHARE_DATA_DIR: dataDir,
    MAGPIE_ADDR: `127.0.0.1:${magpiePort}`,
    MAGPIE_NO_ACCOUNTS: "1",
  };
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const port = srv.address().port;
      srv.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

function runMagpieAsync(args, env) {
  return runCmdAsync(MAGPIE_BIN, args, env);
}

async function runCmdAsync(cmd, args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      stdout += d.toString("utf8");
    });
    child.stderr.on("data", (d) => {
      stderr += d.toString("utf8");
    });
    child.once("error", reject);
    child.once("close", (code) => {
      resolve({ code: code ?? 1, stdout: stdout.trim(), stderr: stderr.trim() });
    });
  });
}

async function startIsolatedMagpieServe(env, port) {
  const proc = spawn(MAGPIE_BIN, ["serve"], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let logs = "";
  proc.stdout.on("data", (d) => {
    logs += d.toString("utf8");
  });
  proc.stderr.on("data", (d) => {
    logs += d.toString("utf8");
  });

  const exitedEarly = new Promise((_, reject) => {
    proc.once("exit", (code) => {
      reject(new Error(`magpie serve on ${port} exited early (${code}): ${logs}`));
    });
  });

  const readyCheck = (async () => {
    for (let i = 0; i < 80; i++) {
      try {
        const res = await fetch(`http://127.0.0.1:${port}/api/hello`);
        if (res.ok) {
          const hello = await res.json();
          if (hello?.name === "magpie" || hello?.version) return hello;
        }
      } catch {}
      await Bun.sleep(100);
    }
    throw new Error(`Timed out waiting for magpie serve on 127.0.0.1:${port}: ${logs}`);
  })();

  await Promise.race([readyCheck, exitedEarly]);

  const close = async () => {
    if (proc.exitCode === null && proc.signalCode === null) {
      await new Promise((resolve) => {
        const timer = setTimeout(resolve, 2000);
        proc.once("exit", () => {
          clearTimeout(timer);
          resolve();
        });
        try {
          proc.kill();
        } catch {
          clearTimeout(timer);
          resolve();
        }
      });
    }
  };

  activeCleanups.push(close);
  return { proc, port, env, url: `http://127.0.0.1:${port}`, getLogs: () => logs, close };
}

function startMockUpstream() {
  const encoder = new TextEncoder();
  const requests = [];
  const slowControllers = new Map();
  let slowAbortedCount = 0;

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(req) {
      const url = new URL(req.url);
      const bodyText = req.method !== "GET" && req.method !== "HEAD" ? await req.text() : "";
      requests.push({
        method: req.method,
        path: url.pathname,
        auth: req.headers.get("authorization") || "",
        bodyText,
      });

      if (url.pathname === "/v1/models") {
        return Response.json({
          object: "list",
          data: [
            { id: "gpt-4o-mini", object: "model", owned_by: "openai" },
            { id: "gpt-4o", object: "model", owned_by: "openai" },
          ],
        });
      }

      if (url.pathname === "/v1/chat/completions") {
        if (bodyText.includes("__SLOW_SSE_STREAM__")) {
          const streamId = `slow-${slowControllers.size + 1}`;
          const stream = new ReadableStream({
            start(ctrl) {
              slowControllers.set(streamId, ctrl);
              ctrl.enqueue(
                encoder.encode(
                  `data: {"id":"${streamId}","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"SLOW_CHUNK_1"}}]}\n\n`,
                ),
              );
              req.signal.addEventListener("abort", () => {
                slowAbortedCount += 1;
                slowControllers.delete(streamId);
                try {
                  ctrl.close();
                } catch {}
              });
            },
          });
          return new Response(stream, {
            status: 200,
            headers: { "content-type": "text/event-stream", "cache-control": "no-cache" },
          });
        }

        let wantStream = true;
        try {
          const parsed = JSON.parse(bodyText || "{}");
          wantStream = parsed.stream !== false;
        } catch {}

        if (wantStream) {
          const stream = new ReadableStream({
            start(ctrl) {
              ctrl.enqueue(
                encoder.encode(
                  'data: {"id":"cmpl-e2e","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"UPSTREAM_REPLY_OK"}}]}\n\n',
                ),
              );
              ctrl.enqueue(
                encoder.encode(
                  'data: {"id":"cmpl-e2e","model":"gpt-4o-mini","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":15,"completion_tokens":7,"total_tokens":22}}\n\n',
                ),
              );
              ctrl.enqueue(encoder.encode("data: [DONE]\n\n"));
              ctrl.close();
            },
          });
          return new Response(stream, {
            status: 200,
            headers: { "content-type": "text/event-stream", "cache-control": "no-cache" },
          });
        }

        return Response.json({
          id: "cmpl-e2e-json",
          model: "gpt-4o-mini",
          choices: [{ index: 0, message: { role: "assistant", content: "UPSTREAM_REPLY_OK" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 15, completion_tokens: 7, total_tokens: 22 },
        });
      }

      return new Response("Not Found", { status: 404 });
    },
  });

  const stop = async () => {
    for (const ctrl of slowControllers.values()) {
      try {
        ctrl.close();
      } catch {}
    }
    slowControllers.clear();
    server.stop(true);
  };
  activeCleanups.push(stop);

  return {
    url: `http://127.0.0.1:${server.port}/v1`,
    port: server.port,
    requests,
    getSlowAbortedCount: () => slowAbortedCount,
    finishSlowStreams() {
      for (const [id, ctrl] of slowControllers.entries()) {
        try {
          ctrl.enqueue(
            encoder.encode(
              'data: {"id":"' + id + '","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"_TAIL"}}],"usage":{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30}}\n\n',
            ),
          );
          ctrl.enqueue(encoder.encode("data: [DONE]\n\n"));
          ctrl.close();
        } catch {}
        slowControllers.delete(id);
      }
    },
    stop,
  };
}

function createTcpByteSpy(targetPort) {
  const captured = [];
  const sockets = new Set();
  const server = net.createServer((clientSock) => {
    sockets.add(clientSock);
    const upstream = net.createConnection({ host: "127.0.0.1", port: targetPort });
    sockets.add(upstream);
    clientSock.on("data", (chunk) => {
      captured.push(Buffer.from(chunk));
      upstream.write(chunk);
    });
    upstream.on("data", (chunk) => {
      captured.push(Buffer.from(chunk));
      clientSock.write(chunk);
    });
    const destroyBoth = () => {
      clientSock.destroy();
      upstream.destroy();
    };
    clientSock.on("error", destroyBoth);
    upstream.on("error", destroyBoth);
    clientSock.on("close", () => {
      sockets.delete(clientSock);
      upstream.destroy();
    });
    upstream.on("close", () => {
      sockets.delete(upstream);
      clientSock.destroy();
    });
  });

  const close = async () => {
    for (const s of sockets) s.destroy();
    await new Promise((r) => server.close(r));
  };
  activeCleanups.push(close);

  return {
    async start() {
      await new Promise((r) => server.listen(0, "127.0.0.1", r));
      return server.address().port;
    },
    dump() {
      const all = Buffer.concat(captured);
      return { all, text: all.toString("utf8") };
    },
    close,
  };
}

function buildUstarTgz(entries) {
  const blocks = [];
  for (const [entryPath, contentInput] of Object.entries(entries)) {
    const data = Buffer.isBuffer(contentInput) ? contentInput : Buffer.from(contentInput, "utf8");
    const hdr = Buffer.alloc(512, 0);
    Buffer.from(entryPath, "utf8").copy(hdr, 0);
    hdr.write("0000644\0", 100, "ascii");
    hdr.write("0000000\0", 108, "ascii");
    hdr.write("0000000\0", 116, "ascii");
    hdr.write(data.length.toString(8).padStart(11, "0") + "\0", 124, "ascii");
    hdr.write("00000000000\0", 136, "ascii");
    hdr.fill(0x20, 148, 156);
    hdr.write("0", 156, "ascii");
    hdr.write("ustar\0", 257, "ascii");
    hdr.write("00", 263, "ascii");
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += hdr[i];
    hdr.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, "ascii");
    blocks.push(hdr);
    if (data.length > 0) {
      blocks.push(data);
      const rem = data.length % 512;
      if (rem !== 0) blocks.push(Buffer.alloc(512 - rem, 0));
    }
  }
  blocks.push(Buffer.alloc(1024, 0));
  return zlib.gzipSync(Buffer.concat(blocks));
}

function apiClient(srv) {
  return (p, init = {}) =>
    fetch(`${srv.url}${p}`, {
      ...init,
      headers: {
        [TOKEN_HEADER]: srv.token,
        ...(init.body ? { "content-type": "application/json" } : {}),
        ...(init.headers || {}),
      },
    });
}

async function pairThroughServers(hostSrv, recvSrv, { deviceName, models = ["mock-up/gpt-4o-mini"] }) {
  const hApi = apiClient(hostSrv);
  const rApi = apiClient(recvSrv);

  const invRes = await hApi("/api/host/invites", { method: "POST" });
  expect(invRes.status).toBe(200);
  const inv = await invRes.json();
  expect(inv.code.startsWith("mshare1:")).toBe(true);

  const parseRes = await rApi("/api/receiver/parse", {
    method: "POST",
    body: JSON.stringify({ code: inv.code }),
  });
  expect(parseRes.status).toBe(200);

  const applyRes = await rApi("/api/receiver/apply", {
    method: "POST",
    body: JSON.stringify({ code: inv.code, deviceName }),
  });
  expect(applyRes.status).toBe(200);
  const applied = await applyRes.json();
  const recvSas = applied.pending.sas;
  expect(recvSas).toMatch(/^\d{4}$/);

  const hState = await (await hApi("/api/state")).json();
  const pending = hState.pending.find((p) => p.name === deviceName);
  expect(pending).toBeDefined();
  expect(pending.sas).toBe(recvSas);

  const approveRes = await hApi(`/api/host/pending/${encodeURIComponent(pending.id)}/approve`, {
    method: "POST",
    body: JSON.stringify({
      models,
      period: "day",
      costLimit: 5,
      tokenLimitWan: 50,
      concurrency: 2,
    }),
  });
  expect(approveRes.status).toBe(200);
  const { member } = await approveRes.json();

  let share = null;
  for (let i = 0; i < 240; i++) {
    const rState = await (await rApi("/api/state")).json();
    if (rState.received.length > 0 && !rState.receiverPending) {
      share = rState.received.find((r) => r.id === member.id) || rState.received[rState.received.length - 1];
      break;
    }
    await Bun.sleep(50);
  }
  expect(share).not.toBeNull();
  return { member, share, invite: inv };
}

async function waitForReceiverMagpieModel(recvMagpieUrl, providerId, modelTail = "mock-up/gpt-4o-mini") {
  const expectedPrefix = `${providerId}/${modelTail}`;
  let lastText = "";
  for (let i = 0; i < 50; i++) {
    try {
      const res = await fetch(`${recvMagpieUrl}/v1/models`);
      if (res.ok) {
        lastText = await res.text();
        const json = JSON.parse(lastText);
        const found = (json?.data || []).find((m) => m?.id === expectedPrefix);
        if (found) return found.id;
      }
    } catch {}
    await Bun.sleep(100);
  }
  throw new Error(`Receiver magpie did not expose ${expectedPrefix} in /v1/models (last=${lastText})`);
}

afterEach(async () => {
  while (activeCleanups.length > 0) {
    const fn = activeCleanups.pop();
    try {
      await fn();
    } catch {}
  }
  while (tempDirs.length > 0) {
    const d = tempDirs.pop();
    try {
      fs.rmSync(d, { recursive: true, force: true });
    } catch {}
  }
});

describe("Magpie dual-daemon E2E & red-team verification", () => {
  magpieTest(
    "CLI help flags & dual isolated magpie serve: Mode 2 blind relay (TCP byte-spy + WS /ws) full E2E",
    async () => {
      const root = makeTempDir("ss-e2e-m2-");
      const hEnvProbe = makeIsolatedEnv(path.join(root, "probe"), await getFreePort());

      const helpMain = await runCmdAsync(MAGPIE_BIN, ["--help"], hEnvProbe);
      expect(helpMain.code).toBe(0);
      expect(helpMain.stdout).toContain("magpie serve");

      const helpServe = await runCmdAsync(MAGPIE_BIN, ["serve", "--help"], hEnvProbe);
      expect(helpServe.code).toBe(0);
      expect(helpServe.stdout).toContain("magpie serve");

      const upstream = startMockUpstream();
      const hostMagpiePort = await getFreePort();
      const recvMagpiePort = await getFreePort();
      const hEnv = makeIsolatedEnv(path.join(root, "host"), hostMagpiePort);
      const rEnv = makeIsolatedEnv(path.join(root, "recv"), recvMagpiePort);

      const addUp = await runMagpieAsync(
        ["provider", "add", "mock-up", `url=${upstream.url}`, "key=sk-upstream-secret-999", "models=gpt-4o-mini,gpt-4o"],
        hEnv,
      );
      expect(addUp.code).toBe(0);

      const hostMagpie = await startIsolatedMagpieServe(hEnv, hostMagpiePort);
      const recvMagpie = await startIsolatedMagpieServe(rEnv, recvMagpiePort);

      const relay = await startBlindRelay({ host: "127.0.0.1", port: 0, token: "e2e-relay-tok" });
      activeCleanups.push(() => relay.close());
      const spy = createTcpByteSpy(relay.port);
      const spyPort = await spy.start();

      const hostSrv = await startServer({ port: 0, env: hEnv, transportOptions: { directBindHost: "127.0.0.1" } });
      activeCleanups.push(() => hostSrv.close());
      const recvSrv = await startServer({ port: 0, env: rEnv, transportOptions: { directBindHost: "127.0.0.1" } });
      activeCleanups.push(() => recvSrv.close());

      const hApi = apiClient(hostSrv);
      const rApi = apiClient(recvSrv);

      const initialHostState = await (await hApi("/api/state")).json();
      expect(initialHostState.magpieGateway.ok).toBe(true);
      expect(initialHostState.magpieGateway.url).toBe(`http://127.0.0.1:${hostMagpiePort}`);
      expect(initialHostState.availableModels.some((m) => m.id === "mock-up/gpt-4o-mini")).toBe(true);

      // 1. Configure Mode 2 TCP over byte-spy and enable sharing
      expect(
        (
          await hApi("/api/network/mode", {
            method: "POST",
            body: JSON.stringify({
              mode: "self-relay",
              network: { relayAddr: `127.0.0.1:${spyPort}`, relayToken: "e2e-relay-tok" },
            }),
          })
        ).status,
      ).toBe(200);
      expect(
        (
          await hApi("/api/host/toggle", {
            method: "POST",
            body: JSON.stringify({ enabled: true, tosAcknowledged: true }),
          })
        ).status,
      ).toBe(200);

      // 2. Pair via invite -> SAS -> approve (provisions real gateway-key in Host magpie, registers remote-magpie in Receiver magpie)
      const { member, share } = await pairThroughServers(hostSrv, recvSrv, {
        deviceName: "Recv-Mode2-TCP",
        models: ["mock-up/gpt-4o-mini"],
      });

      const hostKeysList = await runMagpieAsync(["gateway-key", "list"], hEnv);
      expect(hostKeysList.code).toBe(0);
      expect(hostKeysList.stdout).toContain(member.magpieKeyName);

      const recvProviders = await runMagpieAsync(["providers"], rEnv);
      expect(recvProviders.code).toBe(0);
      expect(recvProviders.stdout).toContain(share.providerId);

      // 3. Stream through REAL Receiver magpie -> Bridge -> Mode 2 Blind Relay -> HostGateway -> Host magpie -> Mock upstream
      const modelIdOnRecv = await waitForReceiverMagpieModel(recvMagpie.url, share.providerId);
      const chatRes = await fetch(`${recvMagpie.url}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model: modelIdOnRecv,
          stream: true,
          messages: [{ role: "user", content: "SECRET_E2E_PROMPT_MODE2" }],
        }),
      });
      expect(chatRes.status).toBe(200);
      const sseText = await chatRes.text();
      expect(sseText).toContain("UPSTREAM_REPLY_OK");
      expect(sseText).toContain("[DONE]");

      // 4. Verify Host usage incremented & secrets NEVER leaked over wire or control-plane/disk
      let hostUsage = null;
      for (let i = 0; i < 30; i++) {
        hostUsage = await (await hApi("/api/host/usage?range=7d")).json();
        if ((hostUsage.usageByMember?.[member.id]?.["7d"] || []).length > 0) break;
        await Bun.sleep(25);
      }
      const usageRows = hostUsage.usageByMember[member.id]["7d"];
      expect(usageRows.length).toBeGreaterThan(0);
      expect(usageRows.reduce((s, r) => s + r.inputTokens, 0)).toBeGreaterThanOrEqual(15);
      expect(usageRows.reduce((s, r) => s + r.outputTokens, 0)).toBeGreaterThanOrEqual(7);

      const spyDump = spy.dump();
      expect(spyDump.all.includes(Buffer.from([0x16, 0x03]))).toBe(true);
      expect(spyDump.text).not.toContain("SECRET_E2E_PROMPT_MODE2");
      expect(spyDump.text).not.toContain("UPSTREAM_REPLY_OK");
      expect(spyDump.text).not.toContain("/v1/chat/completions");
      expect(spyDump.text).not.toContain("sk-magpie-key-");
      expect(spyDump.text).not.toContain("sk-upstream-secret-999");

      const hostStateRaw = await (await hApi("/api/state")).text();
      const recvStateRaw = await (await rApi("/api/state")).text();
      const recvDiskRaw = fs.readFileSync(path.join(rEnv.MAGPIE_SIMPLE_SHARE_DATA, "state.json"), "utf8");
      const hostKeySecret = hostSrv.store.get().members.find((m) => m.id === member.id).magpieKeySecret;
      expect(hostKeySecret).toMatch(/^sk-magpie-key-/);
      for (const blob of [hostStateRaw, recvStateRaw, recvDiskRaw]) {
        expect(blob).not.toContain(hostKeySecret);
        expect(blob).not.toContain("sk-upstream-secret-999");
        expect(blob).not.toContain("SECRET_E2E_PROMPT_MODE2");
      }
      expect(recvStateRaw).not.toContain("bridgeToken");

      // 5. Switch to Mode 2 WebSocket (/ws), leave old share, re-pair & stream via Receiver magpie!
      expect((await rApi(`/api/receiver/shares/${encodeURIComponent(share.id)}`, { method: "DELETE" })).status).toBe(200);
      expect((await hApi(`/api/host/members/${encodeURIComponent(member.id)}`, { method: "DELETE" })).status).toBe(200);

      const wsAddr = `ws://127.0.0.1:${relay.port}/ws`;
      const relayProbe = await (
        await hApi("/api/network/test-relay", {
          method: "POST",
          body: JSON.stringify({ relayAddr: wsAddr, relayToken: "e2e-relay-tok" }),
        })
      ).json();
      expect(relayProbe.ok).toBe(true);
      expect(relayProbe.blindVerified).toBe(true);

      await hApi("/api/network/mode", {
        method: "POST",
        body: JSON.stringify({
          mode: "self-relay",
          network: { relayAddr: wsAddr, relayToken: "e2e-relay-tok" },
        }),
      });
      const wsPaired = await pairThroughServers(hostSrv, recvSrv, {
        deviceName: "Recv-Mode2-WS",
        models: ["mock-up/gpt-4o-mini"],
      });
      const wsModelId = await waitForReceiverMagpieModel(recvMagpie.url, wsPaired.share.providerId);
      const wsChat = await fetch(`${recvMagpie.url}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model: wsModelId,
          stream: true,
          messages: [{ role: "user", content: "WS_PING" }],
        }),
      });
      expect(wsChat.status).toBe(200);
      expect(await wsChat.text()).toContain("UPSTREAM_REPLY_OK");

      await recvSrv.close();
      await hostSrv.close();
      await hostMagpie.close();
      await recvMagpie.close();
    },
    45_000,
  );

  magpieTest(
    "Mode 3 (direct TLS 1.3 mTLS) & Mode 1 (Iroh QUIC P2P) full dual-Magpie E2E",
    async () => {
      const root = makeTempDir("ss-e2e-m31-");
      const upstream = startMockUpstream();
      const hostMagpiePort = await getFreePort();
      const recvMagpiePort = await getFreePort();
      const hEnv = makeIsolatedEnv(path.join(root, "host"), hostMagpiePort);
      const rEnv = makeIsolatedEnv(path.join(root, "recv"), recvMagpiePort);

      await stageLocalIrohDir(path.join(hEnv.MAGPIE_SIMPLE_SHARE_DATA, "iroh"));
      await stageLocalIrohDir(path.join(rEnv.MAGPIE_SIMPLE_SHARE_DATA, "iroh"));

      expect(
        (
          await runMagpieAsync(
            ["provider", "add", "mock-up", `url=${upstream.url}`, "key=sk-upstream-m31", "models=gpt-4o-mini"],
            hEnv,
          )
        ).code,
      ).toBe(0);

      const hostMagpie = await startIsolatedMagpieServe(hEnv, hostMagpiePort);
      const recvMagpie = await startIsolatedMagpieServe(rEnv, recvMagpiePort);

      const directPort = await getFreePort();
      const hostSrv = await startServer({
        port: 0,
        env: hEnv,
        transportOptions: {
          directBindHost: "127.0.0.1",
          irohOptions: { relayMode: "minimal", bindAddr: "127.0.0.1:0" },
        },
      });
      activeCleanups.push(() => hostSrv.close());
      const recvSrv = await startServer({
        port: 0,
        env: rEnv,
        transportOptions: {
          directBindHost: "127.0.0.1",
          irohOptions: { relayMode: "minimal", bindAddr: "127.0.0.1:0" },
        },
      });
      activeCleanups.push(() => recvSrv.close());

      const hApi = apiClient(hostSrv);
      const rApi = apiClient(recvSrv);

      // 1. Mode 3 Direct TLS 1.3 mTLS
      await hApi("/api/network/mode", {
        method: "POST",
        body: JSON.stringify({ mode: "direct", network: { directHost: "127.0.0.1", directPort } }),
      });
      await hApi("/api/host/toggle", {
        method: "POST",
        body: JSON.stringify({ enabled: true, tosAcknowledged: true }),
      });

      const m3 = await pairThroughServers(hostSrv, recvSrv, {
        deviceName: "Recv-Mode3-Direct",
        models: ["mock-up/gpt-4o-mini"],
      });
      expect(m3.share.mode).toBe("direct");
      const m3ModelId = await waitForReceiverMagpieModel(recvMagpie.url, m3.share.providerId);
      const m3Chat = await fetch(`${recvMagpie.url}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: m3ModelId, stream: true, messages: [{ role: "user", content: "direct" }] }),
      });
      expect(m3Chat.status).toBe(200);
      expect(await m3Chat.text()).toContain("UPSTREAM_REPLY_OK");

      // Clean up Mode 3 share before Mode 1
      await rApi(`/api/receiver/shares/${encodeURIComponent(m3.share.id)}`, { method: "DELETE" });
      await hApi(`/api/host/members/${encodeURIComponent(m3.member.id)}`, { method: "DELETE" });

      // 2. Mode 1 Iroh QUIC P2P
      const m1Switch = await hApi("/api/network/mode", {
        method: "POST",
        body: JSON.stringify({ mode: "p2p", network: { irohRelayUrl: "" } }),
      });
      expect(m1Switch.status).toBe(200);
      const m1SwitchJson = await m1Switch.json();
      expect(m1SwitchJson.transportStatus.listening).toBe(true);
      expect(m1SwitchJson.transportStatus.activeMode).toBe("p2p");

      const m1 = await pairThroughServers(hostSrv, recvSrv, {
        deviceName: "Recv-Mode1-Iroh",
        models: ["mock-up/gpt-4o-mini"],
      });
      expect(m1.share.mode).toBe("p2p");
      const m1ModelId = await waitForReceiverMagpieModel(recvMagpie.url, m1.share.providerId);
      const m1Chat = await fetch(`${recvMagpie.url}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: m1ModelId, stream: true, messages: [{ role: "user", content: "p2p" }] }),
      });
      expect(m1Chat.status).toBe(200);
      expect(await m1Chat.text()).toContain("UPSTREAM_REPLY_OK");

      // Confirm Host usage recorded for Mode 1 member
      let m1Usage = null;
      for (let i = 0; i < 30; i++) {
        m1Usage = await (await hApi("/api/host/usage?range=7d")).json();
        if ((m1Usage.usageByMember?.[m1.member.id]?.["7d"] || []).length > 0) break;
        await Bun.sleep(25);
      }
      expect(m1Usage.usageByMember[m1.member.id]["7d"][0].totalTokens).toBe(22);

      // Verify Mode 1 EndpointId eviction via DELETE /api/host/members/:id -> reconfigure()
      const m1HostStatus = hostSrv.transportManager.getHostStatus();
      const upstreamHitsBeforeEvict = upstream.requests.length;
      await hApi(`/api/host/members/${encodeURIComponent(m1.member.id)}`, { method: "DELETE" });
      const evictedDial = await recvSrv.transportManager
        .dialApi({
          mode: "p2p",
          ep: {
            irohEndpointId: hostSrv.identity.irohEndpointId,
            directAddrs: hostSrv.transportManager.getHostEndpointPayload("p2p").directAddrs,
            relayUrl: "",
          },
          hostPubKeyHex: hostSrv.identity.pubKeyHex,
          hostCertPem: hostSrv.identity.certPem,
        })
        .catch((err) => ({ err }));
      if (!evictedDial?.err) {
        await expect(
          sendHttpRequestOverChannel(evictedDial.channel, { method: "GET", path: "/v1/models" }),
        ).rejects.toThrow();
        await evictedDial.close().catch(() => {});
      }
      expect(upstream.requests.length).toBe(upstreamHitsBeforeEvict);
      expect(m1HostStatus.activeMode).toBe("p2p");

      await recvSrv.close();
      await hostSrv.close();
      await hostMagpie.close();
      await recvMagpie.close();
    },
    45_000,
  );

  test(
    "Live installIroh against https://registry.npmmirror.com & tampered sha512 rejection",
    async () => {
      const root = makeTempDir("ss-iroh-live-");
      const liveDir = path.join(root, "live-iroh");
      const status = await installIroh(liveDir, {
        registries: ["https://registry.npmmirror.com", "https://registry.npmjs.org"],
        timeoutMs: 60_000,
      });
      expect(status.ok).toBe(true);
      expect(status.installed).toBe(true);
      expect(status.integrityOk).toBe(true);
      expect(status.version).toBe("1.2.0");

      const checked = getIrohStatus(liveDir);
      expect(checked.installed).toBe(true);
      expect(checked.integrityOk).toBe(true);
      expect(fs.existsSync(path.join(liveDir, "node_modules", "@number0", "iroh", "index.js"))).toBe(true);

      // Tampered tarball test against local mock registry server (1-byte flip fails sha512)
      const platPkg = platformPackageName();
      const badDir = path.join(root, "tampered-iroh");
      const validTgz = buildUstarTgz({
        "package/package.json": JSON.stringify({ name: "@number0/iroh", version: "1.2.0", main: "index.js" }),
        "package/index.js": "module.exports = {};\n",
      });
      const tamperedTgz = Buffer.from(validTgz);
      tamperedTgz[tamperedTgz.length - 5] ^= 0xff;

      const badReg = http.createServer((req, res) => {
        if (req.url?.includes("iroh-1.2.0.tgz")) {
          res.writeHead(200, { "content-type": "application/octet-stream" });
          res.end(tamperedTgz);
          return;
        }
        res.writeHead(404);
        res.end();
      });
      await new Promise((r) => badReg.listen(0, "127.0.0.1", r));
      const badRegUrl = `http://127.0.0.1:${badReg.address().port}`;
      activeCleanups.push(() => new Promise((r) => badReg.close(r)));

      await expect(
        installIroh(badDir, { registries: [badRegUrl], timeoutMs: 5000 }),
      ).rejects.toThrow(/sha512 mismatch/i);
      expect(getIrohStatus(badDir).installed).toBe(false);
      expect(fs.existsSync(badDir)).toBe(false);
    },
    90_000,
  );

  magpieTest(
    "Red-team security: path block, Fail-Closed /v1/magpie/limit, pause/resume, mid-stream revoke, no-fallback, restart & live CLI",
    async () => {
      const root = makeTempDir("ss-e2e-red-");
      const upstream = startMockUpstream();
      const hostMagpiePort = await getFreePort();
      const recvMagpiePort = await getFreePort();
      const hEnv = makeIsolatedEnv(path.join(root, "host"), hostMagpiePort);
      const rEnv = makeIsolatedEnv(path.join(root, "recv"), recvMagpiePort);
      const bEnv = makeIsolatedEnv(path.join(root, "bob"), await getFreePort());

      expect(
        (
          await runMagpieAsync(
            ["provider", "add", "mock-up", `url=${upstream.url}`, "key=sk-upstream-red", "models=gpt-4o-mini"],
            hEnv,
          )
        ).code,
      ).toBe(0);

      const hostMagpie = await startIsolatedMagpieServe(hEnv, hostMagpiePort);
      const recvMagpie = await startIsolatedMagpieServe(rEnv, recvMagpiePort);

      let relay = await startBlindRelay({ host: "127.0.0.1", port: 0, token: "red-tok" });
      const relayPort = relay.port;
      let relayClosed = false;
      activeCleanups.push(async () => {
        if (!relayClosed) await relay.close();
      });

      let hostSrv = await startServer({ port: 0, env: hEnv, transportOptions: { directBindHost: "127.0.0.1" } });
      let recvSrv = await startServer({ port: 0, env: rEnv, transportOptions: { directBindHost: "127.0.0.1" } });
      const bobSrv = await startServer({
        port: 0,
        env: bEnv,
        transportOptions: { directBindHost: "127.0.0.1" },
        discoverGatewayFn: async () => ({ ok: false, running: false, url: "", addr: "", version: "" }),
        fetchModelsFn: async () => [],
        addProviderFn: async (p) => ({ ok: true, ...p }),
        removeProviderFn: async ({ id }) => ({ ok: true, id }),
      });

      let hostClosed = false;
      let recvClosed = false;
      activeCleanups.push(async () => {
        if (!hostClosed) await hostSrv.close();
        if (!recvClosed) await recvSrv.close();
        await bobSrv.close();
      });

      let hApi = apiClient(hostSrv);
      let rApi = apiClient(recvSrv);

      await hApi("/api/network/mode", {
        method: "POST",
        body: JSON.stringify({
          mode: "self-relay",
          network: { relayAddr: `127.0.0.1:${relayPort}`, relayToken: "red-tok" },
        }),
      });
      await hApi("/api/host/toggle", {
        method: "POST",
        body: JSON.stringify({ enabled: true, tosAcknowledged: true }),
      });

      const alice = await pairThroughServers(hostSrv, recvSrv, { deviceName: "Alice-RealMagpie" });
      const bob = await pairThroughServers(hostSrv, bobSrv, { deviceName: "Bob-Stream" });

      const aliceBridgeUrl = `http://127.0.0.1:${alice.share.bridgePort}`;
      const aliceBridgeToken = recvSrv.store.get().received.find((r) => r.id === alice.share.id).bridgeToken;
      const bobBridgeUrl = `http://127.0.0.1:${bob.share.bridgePort}`;
      const bobBridgeToken = bobSrv.store.get().received.find((r) => r.id === bob.share.id).bridgeToken;

      // 1. Path allowlist returns 403 on admin/native/mcp/quotas/traversal
      for (const badPath of [
        "/v1/magpie/admin/providers",
        "/v1/magpie/native/status",
        "/mcp",
        "/v1/%2e%2e/magpie/admin/providers",
        "/../package.json",
        "/v1/magpie/quotas",
      ]) {
        const res = await fetch(`${aliceBridgeUrl}${badPath}`, {
          method: badPath === "/mcp" ? "POST" : "GET",
          headers: { authorization: `Bearer ${aliceBridgeToken}` },
        });
        expect(res.status).toBe(403);
        expect((await res.json()).code).toBe("forbidden_path");
      }

      // 2. Pause -> 403 share_paused (preserving quota/key in Host magpie), Resume -> 200
      expect(
        (
          await hApi(`/api/host/members/${encodeURIComponent(alice.member.id)}/pause`, {
            method: "POST",
            body: JSON.stringify({ paused: true }),
          })
        ).status,
      ).toBe(200);
      const pausedRes = await fetch(`${aliceBridgeUrl}/v1/models`, {
        headers: { authorization: `Bearer ${aliceBridgeToken}` },
      });
      expect(pausedRes.status).toBe(403);
      expect((await pausedRes.json()).code).toBe("share_paused");
      expect((await runMagpieAsync(["gateway-key", "list"], hEnv)).stdout).toContain(alice.member.magpieKeyName);

      expect(
        (
          await hApi(`/api/host/members/${encodeURIComponent(alice.member.id)}/pause`, {
            method: "POST",
            body: JSON.stringify({ paused: false }),
          })
        ).status,
      ).toBe(200);
      expect(
        (await fetch(`${aliceBridgeUrl}/v1/models`, { headers: { authorization: `Bearer ${aliceBridgeToken}` } })).status,
      ).toBe(200);

      // 3. Fail-Closed /v1/magpie/limit: remove Alice's gateway-key directly via isolated `magpie gateway-key remove`
      const aliceMemberRaw = hostSrv.store.get().members.find((m) => m.id === alice.member.id);
      const rmAliceKey = await runMagpieAsync(["gateway-key", "remove", aliceMemberRaw.magpieKeyId], hEnv);
      expect(rmAliceKey.code).toBe(0);

      // Prove raw Host magpie returns {"key":"","limited":false} for removed key (loopback trap)
      const rawTrapRes = await fetch(`${hostMagpie.url}/v1/magpie/limit`, {
        headers: { authorization: `Bearer ${aliceMemberRaw.magpieKeySecret}` },
      });
      expect(rawTrapRes.status).toBe(200);
      expect((await rawTrapRes.json()).key).toBe("");

      const reqCountBefore = upstream.requests.length;
      const failClosedRes = await fetch(`${aliceBridgeUrl}/v1/chat/completions`, {
        method: "POST",
        headers: { authorization: `Bearer ${aliceBridgeToken}`, "content-type": "application/json" },
        body: JSON.stringify({ model: "mock-up/gpt-4o-mini", stream: true, messages: [{ role: "user", content: "blocked" }] }),
      });
      expect(failClosedRes.status).toBe(403);
      expect((await failClosedRes.json()).code).toBe("key_revoked_or_invalid");
      expect(upstream.requests.length).toBe(reqCountBefore);

      // Clean up Alice before next steps
      await rApi(`/api/receiver/shares/${encodeURIComponent(alice.share.id)}`, { method: "DELETE" });
      await hApi(`/api/host/members/${encodeURIComponent(alice.member.id)}`, { method: "DELETE" });

      // 4. Mid-stream Revoke on Bob: open slow SSE through Host magpie -> delete member -> abort + key removed + cert evicted
      const bobMemberRaw = hostSrv.store.get().members.find((m) => m.id === bob.member.id);
      const slowRes = await fetch(`${bobBridgeUrl}/v1/chat/completions`, {
        method: "POST",
        headers: { authorization: `Bearer ${bobBridgeToken}`, "content-type": "application/json" },
        body: JSON.stringify({
          model: "mock-up/gpt-4o-mini",
          stream: true,
          messages: [{ role: "user", content: "__SLOW_SSE_STREAM__" }],
        }),
      });
      expect(slowRes.status).toBe(200);
      const slowReader = slowRes.body.getReader();
      const firstChunk = await slowReader.read();
      expect(new TextDecoder().decode(firstChunk.value)).toContain("SLOW_CHUNK_1");

      const nextReadOutcome = slowReader
        .read()
        .then((tail) => ({ aborted: Boolean(tail.done) }))
        .catch(() => ({ aborted: true }));
      const revokeBobRes = await hApi(`/api/host/members/${encodeURIComponent(bob.member.id)}`, { method: "DELETE" });
      expect(revokeBobRes.status).toBe(200);

      const { aborted: streamAborted } = await nextReadOutcome;
      expect(streamAborted).toBe(true);
      await Bun.sleep(150);
      expect(upstream.getSlowAbortedCount()).toBeGreaterThanOrEqual(1);
      expect((await runMagpieAsync(["gateway-key", "list"], hEnv)).stdout).not.toContain(bob.member.magpieKeyName);

      // Evicted peer cert must be rejected on dialApi (no fallback)
      await expect(
        bobSrv.transportManager.dialApi({
          mode: "self-relay",
          ep: { relayAddr: `127.0.0.1:${relayPort}`, relayToken: "red-tok" },
          hostPubKeyHex: hostSrv.identity.pubKeyHex,
          hostCertPem: hostSrv.identity.certPem,
        }),
      ).rejects.toThrow();

      // 5. Pair Charlie for Restart Recovery & Strict No-Fallback & Live CLI
      const charlie = await pairThroughServers(hostSrv, recvSrv, { deviceName: "Charlie-Persist" });
      const charlieModelId = await waitForReceiverMagpieModel(recvMagpie.url, charlie.share.providerId);

      // Strict no-fallback when Mode 2 relay shuts down
      await relay.close();
      relayClosed = true;
      const charlieBridgeUrl = `http://127.0.0.1:${charlie.share.bridgePort}`;
      const charlieBridgeToken = recvSrv.store.get().received.find((r) => r.id === charlie.share.id).bridgeToken;
      const offlineBridgeRes = await fetch(`${charlieBridgeUrl}/v1/models`, {
        headers: { authorization: `Bearer ${charlieBridgeToken}` },
      });
      expect(offlineBridgeRes.status).toBe(502);

      // Bring relay back on SAME port and restart BOTH hostSrv and recvSrv from disk!
      relay = await startBlindRelay({ host: "127.0.0.1", port: relayPort, token: "red-tok" });
      relayClosed = false;

      await hostSrv.close();
      hostClosed = true;
      await recvSrv.close();
      recvClosed = true;

      hostSrv = await startServer({ port: 0, env: hEnv, transportOptions: { directBindHost: "127.0.0.1" } });
      hostClosed = false;
      recvSrv = await startServer({ port: 0, env: rEnv, transportOptions: { directBindHost: "127.0.0.1" } });
      recvClosed = false;
      hApi = apiClient(hostSrv);
      rApi = apiClient(recvSrv);

      // Wait briefly for host-ctl reconnect and verify already-paired Receiver magpie streams without re-pairing!
      let postRestartChat = null;
      for (let i = 0; i < 30; i++) {
        const res = await fetch(`${recvMagpie.url}/v1/chat/completions`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            model: charlieModelId,
            stream: true,
            messages: [{ role: "user", content: "POST_RESTART_NO_REPAIR" }],
          }),
        });
        if (res.status === 200) {
          postRestartChat = await res.text();
          break;
        }
        await Bun.sleep(100);
      }
      expect(postRestartChat).toContain("UPSTREAM_REPLY_OK");

      // Mode 3 strict no-fallback when direct port closed
      const closedPort = await getFreePort();
      await expect(
        recvSrv.transportManager.dialApi({
          mode: "direct",
          ep: { directHost: "127.0.0.1", directPort: closedPort },
          hostPubKeyHex: hostSrv.identity.pubKeyHex,
          hostCertPem: hostSrv.identity.certPem,
        }),
      ).rejects.toThrow();

      // 6. Live CLI subprocess E2E smoke (`bun bin/simple-share.mjs`) against isolated startServer --port
      const cliStatus = await runCmdAsync(
        process.execPath,
        [CLI_PATH, "status", "--json", "--port", String(hostSrv.port)],
        hEnv,
      );
      expect(cliStatus.code).toBe(0);
      const statusJson = JSON.parse(cliStatus.stdout);
      expect(statusJson.sharingEnabled).toBe(true);
      expect(statusJson.membersCount).toBe(1);

      const cliMembers = await runCmdAsync(
        process.execPath,
        [CLI_PATH, "members", "--json", "--port", String(hostSrv.port)],
        hEnv,
      );
      expect(cliMembers.code).toBe(0);
      expect(JSON.parse(cliMembers.stdout).members[0].id).toBe(charlie.member.id);

      const cliInvite = await runCmdAsync(
        process.execPath,
        [CLI_PATH, "invite", "--json", "--port", String(hostSrv.port)],
        hEnv,
      );
      expect(cliInvite.code).toBe(0);
      expect(JSON.parse(cliInvite.stdout).code.startsWith("mshare1:")).toBe(true);

      const cliDoctor = await runCmdAsync(
        process.execPath,
        [CLI_PATH, "doctor", "--json", "--port", String(hostSrv.port)],
        hEnv,
      );
      expect(cliDoctor.code).toBe(0);
      const docJson = JSON.parse(cliDoctor.stdout);
      expect(docJson.controlPlane.running).toBe(true);
      expect(docJson.magpieGateway.ok).toBe(true);
    },
    60_000,
  );
});
