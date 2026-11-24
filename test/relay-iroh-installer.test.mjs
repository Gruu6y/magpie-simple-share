import { describe, expect, test } from "bun:test";
import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";

import { startBlindRelay } from "../relay/simple-share-relay.mjs";
import {
  detectLinuxLibc,
  getIrohStatus,
  installIroh,
  loadIrohModule,
  platformPackageName,
} from "../lib/iroh-installer.mjs";

function createByteStream() {
  let buf = Buffer.alloc(0);
  let ended = false;
  let error = null;
  const waiters = [];

  function notify() {
    while (waiters.length > 0) {
      const w = waiters[0];
      if (error) {
        waiters.shift();
        w.reject(error);
        continue;
      }
      if (w.kind === "line") {
        const idx = buf.indexOf(0x0a);
        if (idx !== -1) {
          const line = buf.subarray(0, idx).toString("utf8").replace(/\r$/, "");
          buf = buf.subarray(idx + 1);
          waiters.shift();
          w.resolve(line);
          continue;
        }
        if (ended) {
          waiters.shift();
          w.reject(new Error("Stream ended before newline"));
          continue;
        }
        break;
      }
      if (w.kind === "exact") {
        if (buf.length >= w.n) {
          const out = Buffer.from(buf.subarray(0, w.n));
          buf = buf.subarray(w.n);
          waiters.shift();
          w.resolve(out);
          continue;
        }
        if (ended) {
          waiters.shift();
          w.reject(new Error(`Stream ended early (wanted ${w.n}, got ${buf.length})`));
          continue;
        }
        break;
      }
      if (w.kind === "end") {
        if (ended) {
          waiters.shift();
          w.resolve(true);
          continue;
        }
        break;
      }
    }
  }

  return {
    push(chunk) {
      if (chunk?.length) {
        buf = buf.length ? Buffer.concat([buf, chunk]) : Buffer.from(chunk);
        notify();
      }
    },
    end() {
      ended = true;
      notify();
    },
    fail(err) {
      error = err;
      ended = true;
      notify();
    },
    readJsonLine() {
      return new Promise((resolve, reject) => {
        waiters.push({ kind: "line", resolve, reject });
        notify();
      }).then((s) => JSON.parse(s));
    },
    readExact(n) {
      return new Promise((resolve, reject) => {
        waiters.push({ kind: "exact", n, resolve, reject });
        notify();
      });
    },
    waitEnd() {
      return new Promise((resolve, reject) => {
        waiters.push({ kind: "end", resolve, reject });
        notify();
      });
    },
  };
}

async function openTcpPeer(port) {
  const stream = createByteStream();
  const socket = net.createConnection({ host: "127.0.0.1", port });
  socket.on("data", (d) => stream.push(d));
  socket.on("close", () => stream.end());
  socket.on("error", (e) => stream.fail(e));
  await new Promise((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  });
  return {
    sendJson(obj) {
      socket.write(JSON.stringify(obj) + "\n");
    },
    sendBytes(buf) {
      socket.write(buf);
    },
    readJsonLine: () => stream.readJsonLine(),
    readExact: (n) => stream.readExact(n),
    waitEnd: () => stream.waitEnd(),
    close() {
      if (!socket.destroyed) socket.destroy();
    },
  };
}

async function openWsPeer(port) {
  const stream = createByteStream();
  const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`);
  ws.binaryType = "arraybuffer";
  ws.addEventListener("message", (ev) => {
    const chunk = typeof ev.data === "string" ? Buffer.from(ev.data, "utf8") : Buffer.from(ev.data);
    stream.push(chunk);
  });
  ws.addEventListener("close", () => stream.end());
  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve, { once: true });
    ws.addEventListener("error", () => reject(new Error("WebSocket connect failed")), { once: true });
  });
  return {
    sendJson(obj) {
      ws.send(JSON.stringify(obj) + "\n");
    },
    sendBytes(buf) {
      ws.send(buf);
    },
    readJsonLine: () => stream.readJsonLine(),
    readExact: (n) => stream.readExact(n),
    waitEnd: () => stream.waitEnd(),
    close() {
      try {
        ws.close();
      } catch {}
    },
  };
}

function buildUstarTgz(entries) {
  const blocks = [];
  for (const [entryPath, contentInput] of Object.entries(entries)) {
    const data = Buffer.isBuffer(contentInput) ? contentInput : Buffer.from(contentInput, "utf8");
    const hdr = Buffer.alloc(512, 0);
    const nameBytes = Buffer.from(entryPath, "utf8");
    if (nameBytes.length > 100) throw new Error(`Mock tar name too long: ${entryPath}`);
    nameBytes.copy(hdr, 0);
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
  const tgz = zlib.gzipSync(Buffer.concat(blocks));
  const sha512 = "sha512-" + crypto.createHash("sha512").update(tgz).digest("base64");
  return { tgz, sha512 };
}

async function runBridgeScenario(relayPort, openCtl, openClient, openData, token = "") {
  const slotId = "slot-" + crypto.randomBytes(6).toString("hex");
  const hostCtl = await openCtl(relayPort);
  let client = null;
  let hostData = null;
  try {
    hostCtl.sendJson({ role: "host-ctl", slotId, token });
    expect(await hostCtl.readJsonLine()).toEqual({ ok: true });

    client = await openClient(relayPort);
    client.sendJson({ role: "client", slotId, token });

    const pairMsg = await hostCtl.readJsonLine();
    expect(pairMsg.type).toBe("pair");
    expect(typeof pairMsg.connId).toBe("string");

    hostData = await openData(relayPort);
    hostData.sendJson({ role: "host-data", slotId, connId: pairMsg.connId, token });

    expect(await client.readJsonLine()).toEqual({ ok: true, connId: pairMsg.connId });
    expect(await hostData.readJsonLine()).toEqual({ ok: true, connId: pairMsg.connId });

    // Arbitrary non-UTF8 opaque binary payloads (e.g. TLS 1.3 ciphertext)
    const c2h = Buffer.concat([
      Buffer.from([0x16, 0x03, 0x03, 0xff, 0xfe, 0x00, 0x0a, 0x0d]),
      crypto.randomBytes(32768),
    ]);
    const h2c = Buffer.concat([
      Buffer.from([0x17, 0x03, 0x03, 0x80, 0xc0, 0x00, 0x00, 0x0a]),
      crypto.randomBytes(32768),
    ]);

    client.sendBytes(c2h);
    hostData.sendBytes(h2c);

    const gotAtHost = await hostData.readExact(c2h.length);
    const gotAtClient = await client.readExact(h2c.length);
    expect(Buffer.compare(gotAtHost, c2h)).toBe(0);
    expect(Buffer.compare(gotAtClient, h2c)).toBe(0);
  } finally {
    client?.close();
    hostData?.close();
    hostCtl.close();
  }
}

describe("simple-share-relay blind forwarder", () => {
  test("GET /health returns 200 blind-relay status and unknown HTTP returns 404", async () => {
    const relay = await startBlindRelay({ host: "127.0.0.1", port: 0 });
    try {
      const health = await fetch(`http://127.0.0.1:${relay.port}/health`);
      expect(health.status).toBe(200);
      expect(await health.json()).toEqual({ ok: true, mode: "blind-relay" });

      const missing = await fetch(`http://127.0.0.1:${relay.port}/nope`);
      expect(missing.status).toBe(404);
    } finally {
      await relay.close();
    }
  });

  test("rejects unauthorized tokens timing-safely and reports host_offline when absent", async () => {
    const relay = await startBlindRelay({ host: "127.0.0.1", port: 0, token: "top-secret-relay-key" });
    try {
      const badCtl = await openTcpPeer(relay.port);
      badCtl.sendJson({ role: "host-ctl", slotId: "s1", token: "top-secret-relay-keX" });
      expect(await badCtl.readJsonLine()).toEqual({ ok: false, error: "unauthorized" });
      await badCtl.waitEnd();

      const badClient = await openWsPeer(relay.port);
      badClient.sendJson({ role: "client", slotId: "s1", token: "wrong" });
      expect(await badClient.readJsonLine()).toEqual({ ok: false, error: "unauthorized" });
      await badClient.waitEnd();

      const offlineTcp = await openTcpPeer(relay.port);
      offlineTcp.sendJson({ role: "client", slotId: "missing-slot", token: "top-secret-relay-key" });
      expect(await offlineTcp.readJsonLine()).toEqual({ ok: false, error: "host_offline" });
      await offlineTcp.waitEnd();

      const offlineWs = await openWsPeer(relay.port);
      offlineWs.sendJson({ role: "client", slotId: "missing-slot", token: "top-secret-relay-key" });
      expect(await offlineWs.readJsonLine()).toEqual({ ok: false, error: "host_offline" });
      await offlineWs.waitEnd();
    } finally {
      await relay.close();
    }
  });

  test("bridges TCP<->TCP, WS<->WS, TCP<->WS and WS<->TCP with zero byte mutation", async () => {
    const token = "relay-bridge-secret";
    const relay = await startBlindRelay({ host: "127.0.0.1", port: 0, token });
    try {
      await runBridgeScenario(relay.port, openTcpPeer, openTcpPeer, openTcpPeer, token);
      await runBridgeScenario(relay.port, openWsPeer, openWsPeer, openWsPeer, token);
      await runBridgeScenario(relay.port, openWsPeer, openTcpPeer, openWsPeer, token);
      await runBridgeScenario(relay.port, openTcpPeer, openWsPeer, openTcpPeer, token);

      // Wait briefly for socket close handlers to settle stats
      await new Promise((r) => setTimeout(r, 30));
      const st = relay.stats();
      expect(st.activeTunnels).toBe(0);
      expect(st.pending).toBe(0);
    } finally {
      await relay.close();
    }
  });

  test("preserves pipelined bytes sent immediately after newline preamble", async () => {
    const relay = await startBlindRelay({ host: "127.0.0.1", port: 0 });
    const hostCtl = await openTcpPeer(relay.port);
    let client = null;
    let hostData = null;
    try {
      hostCtl.sendJson({ role: "host-ctl", slotId: "pipe-slot" });
      expect(await hostCtl.readJsonLine()).toEqual({ ok: true });

      client = await openTcpPeer(relay.port);
      const earlyPayload = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
      client.sendBytes(
        Buffer.concat([Buffer.from('{"role":"client","slotId":"pipe-slot"}\n'), earlyPayload]),
      );

      const pair = await hostCtl.readJsonLine();
      hostData = await openTcpPeer(relay.port);
      hostData.sendJson({ role: "host-data", slotId: "pipe-slot", connId: pair.connId });

      expect(await client.readJsonLine()).toEqual({ ok: true, connId: pair.connId });
      expect(await hostData.readJsonLine()).toEqual({ ok: true, connId: pair.connId });

      const received = await hostData.readExact(earlyPayload.length);
      expect(Buffer.compare(received, earlyPayload)).toBe(0);
    } finally {
      client?.close();
      hostData?.close();
      hostCtl.close();
      await relay.close();
    }
  });

  test("rejects mismatched host-data connId and cancels pending client when host-ctl disconnects", async () => {
    const relay = await startBlindRelay({ host: "127.0.0.1", port: 0 });
    const hostCtl = await openTcpPeer(relay.port);
    let client = null;
    let badData = null;
    try {
      hostCtl.sendJson({ role: "host-ctl", slotId: "drop-slot" });
      expect(await hostCtl.readJsonLine()).toEqual({ ok: true });

      client = await openTcpPeer(relay.port);
      client.sendJson({ role: "client", slotId: "drop-slot" });
      const pair = await hostCtl.readJsonLine();

      badData = await openTcpPeer(relay.port);
      badData.sendJson({ role: "host-data", slotId: "wrong-slot", connId: pair.connId });
      expect(await badData.readJsonLine()).toEqual({ ok: false, error: "pair_not_found" });
      await badData.waitEnd();

      // Dropping host-ctl must immediately fail the waiting client with host_offline
      hostCtl.close();
      expect(await client.readJsonLine()).toEqual({ ok: false, error: "host_offline" });
      await client.waitEnd();
    } finally {
      badData?.close();
      client?.close();
      hostCtl.close();
      await relay.close();
    }
  });
});

describe("iroh-installer", () => {
  test("platformPackageName maps all supported platforms including musl/arm and rejects unsupported ones", () => {
    expect(platformPackageName("win32", "x64")).toBe("@number0/iroh-win32-x64-msvc");
    expect(platformPackageName("win32", "arm64")).toBe("@number0/iroh-win32-arm64-msvc");
    expect(platformPackageName("darwin", "arm64")).toBe("@number0/iroh-darwin-arm64");
    expect(platformPackageName("darwin", "x64")).toBeNull();
    expect(platformPackageName("linux", "x64", { libc: "gnu" })).toBe("@number0/iroh-linux-x64-gnu");
    expect(platformPackageName("linux", "x64", { libc: "musl" })).toBe("@number0/iroh-linux-x64-musl");
    expect(platformPackageName("linux", "arm64", { libc: "gnu" })).toBe("@number0/iroh-linux-arm64-gnu");
    expect(platformPackageName("linux", "arm64", { libc: "musl" })).toBe("@number0/iroh-linux-arm64-musl");
    expect(platformPackageName("linux", "arm", { libc: "gnu" })).toBe("@number0/iroh-linux-arm-gnueabihf");
    expect(platformPackageName("linux", "arm", { libc: "musl" })).toBe("@number0/iroh-linux-arm-musleabihf");
    expect(platformPackageName("freebsd", "x64")).toBeNull();

    expect(detectLinuxLibc({ platform: "darwin" })).toBeNull();
    expect(detectLinuxLibc({ platform: "linux", reportHeader: { glibcVersionRuntime: "2.39" } })).toBe("gnu");
    expect(
      detectLinuxLibc({
        platform: "linux",
        reportHeader: {},
        existsSync: (p) => p === "/etc/alpine-release",
        readdirSync: () => [],
      }),
    ).toBe("musl");

    const intelMac = getIrohStatus("/tmp/unused", { platform: "darwin", arch: "x64" });
    expect(intelMac.supported).toBe(false);
    expect(intelMac.platformPkg).toBeNull();
    expect(intelMac.unsupportedReason).toContain("darwin-x64");
  });

  test("installIroh downloads, verifies sha512, unpacks atomically, and loads module", async () => {
    const platPkg = platformPackageName();
    expect(platPkg).toBeTruthy();
    const platSuffix = platPkg.split("/")[1];

    const mainTgz = buildUstarTgz({
      "package/package.json": JSON.stringify({ name: "@number0/iroh", version: "1.2.0", main: "index.js" }),
      "package/index.js": `const native = require(${JSON.stringify(platPkg)});\nmodule.exports = { ping: () => "pong:" + native.id };\n`,
    });
    const platTgz = buildUstarTgz({
      "package/package.json": JSON.stringify({ name: platPkg, version: "1.2.0", main: "native.cjs" }),
      "package/native.cjs": `module.exports = { id: ${JSON.stringify(platSuffix)} };\n`,
    });

    const server = http.createServer((req, res) => {
      if (req.url === "/@number0/iroh/-/iroh-1.2.0.tgz") {
        res.writeHead(200, { "content-length": mainTgz.tgz.length });
        return res.end(mainTgz.tgz);
      }
      if (req.url === `/${platPkg}/-/${platSuffix}-1.2.0.tgz`) {
        res.writeHead(200, { "content-length": platTgz.tgz.length });
        return res.end(platTgz.tgz);
      }
      res.writeHead(404);
      res.end("not found");
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    const port = server.address().port;
    const registryUrl = `http://127.0.0.1:${port}`;
    const tmpRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "iroh-install-ok-"));
    const irohDir = path.join(tmpRoot, "iroh");
    const integrityOverrides = {
      "@number0/iroh": mainTgz.sha512,
      [platPkg]: platTgz.sha512,
    };

    try {
      expect(getIrohStatus(irohDir).installed).toBe(false);
      const stages = [];
      const res = await installIroh(irohDir, {
        registries: [registryUrl],
        integrityOverrides,
        onProgress: (ev) => stages.push(ev.stage),
      });
      expect(res.ok).toBe(true);
      expect(res.installed).toBe(true);
      expect(res.version).toBe("1.2.0");
      expect(res.platformPkg).toBe(platPkg);
      expect(res.integrityOk).toBe(true);
      expect(stages).toContain("downloading");
      expect(stages).toContain("verifying");
      expect(stages).toContain("extracting");
      expect(stages).toContain("ready");

      const entries = await fsp.readdir(irohDir);
      expect(entries.some((e) => e.startsWith(".staging-"))).toBe(false);
      expect(entries).toContain("manifest.json");

      const status = getIrohStatus(irohDir, { integrityOverrides });
      expect(status).toEqual({
        installed: true,
        version: "1.2.0",
        platformPkg: platPkg,
        supported: true,
        unsupportedReason: null,
        integrityOk: true,
      });

      const mod = loadIrohModule(irohDir, { integrityOverrides });
      expect(mod.ping()).toBe(`pong:${platSuffix}`);

      // Second install call sees valid install and skips download
      const second = await installIroh(irohDir, { registries: ["http://127.0.0.1:1"], integrityOverrides });
      expect(second.alreadyInstalled).toBe(true);
      expect(second.installed).toBe(true);
    } finally {
      await new Promise((r) => server.close(r));
      await fsp.rm(tmpRoot, { recursive: true, force: true });
    }
  });

  test("falls back to secondary registry when primary mirror fails or serves tampered bytes", async () => {
    const platPkg = platformPackageName();
    const platSuffix = platPkg.split("/")[1];
    const mainTgz = buildUstarTgz({
      "package/package.json": JSON.stringify({ name: "@number0/iroh", version: "1.2.0", main: "index.js" }),
      "package/index.js": "module.exports = { fallbackOk: true };\n",
    });
    const platTgz = buildUstarTgz({
      "package/package.json": JSON.stringify({ name: platPkg, version: "1.2.0", main: "native.cjs" }),
      "package/native.cjs": "module.exports = {};\n",
    });

    const badMirror = http.createServer((_req, res) => {
      res.writeHead(502);
      res.end("bad gateway");
    });
    const goodMirror = http.createServer((req, res) => {
      if (req.url === "/@number0/iroh/-/iroh-1.2.0.tgz") {
        res.writeHead(200);
        return res.end(mainTgz.tgz);
      }
      if (req.url === `/${platPkg}/-/${platSuffix}-1.2.0.tgz`) {
        res.writeHead(200);
        return res.end(platTgz.tgz);
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise((r) => badMirror.listen(0, "127.0.0.1", r));
    await new Promise((r) => goodMirror.listen(0, "127.0.0.1", r));
    const badUrl = `http://127.0.0.1:${badMirror.address().port}`;
    const goodUrl = `http://127.0.0.1:${goodMirror.address().port}`;
    const tmpRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "iroh-fallback-"));
    const irohDir = path.join(tmpRoot, "iroh");
    const integrityOverrides = { "@number0/iroh": mainTgz.sha512, [platPkg]: platTgz.sha512 };

    try {
      const res = await installIroh(irohDir, {
        registries: [badUrl, goodUrl],
        integrityOverrides,
      });
      expect(res.ok).toBe(true);
      expect(res.integrityOk).toBe(true);
      expect(loadIrohModule(irohDir, { integrityOverrides }).fallbackOk).toBe(true);
    } finally {
      await new Promise((r) => badMirror.close(r));
      await new Promise((r) => goodMirror.close(r));
      await fsp.rm(tmpRoot, { recursive: true, force: true });
    }
  });

  test("1-byte tampered tarball fails sha512 verification and cleans up staging files", async () => {
    const platPkg = platformPackageName();
    const platSuffix = platPkg.split("/")[1];
    const mainTgz = buildUstarTgz({
      "package/package.json": JSON.stringify({ name: "@number0/iroh", version: "1.2.0", main: "index.js" }),
      "package/index.js": "module.exports = {};\n",
    });
    const platTgz = buildUstarTgz({
      "package/package.json": JSON.stringify({ name: platPkg, version: "1.2.0", main: "native.cjs" }),
      "package/native.cjs": "module.exports = {};\n",
    });

    // Tamper 1 byte in platform tarball after computing expected sha512
    const tamperedPlatBuf = Buffer.from(platTgz.tgz);
    tamperedPlatBuf[tamperedPlatBuf.length - 10] ^= 0x01;

    const server = http.createServer((req, res) => {
      if (req.url === "/@number0/iroh/-/iroh-1.2.0.tgz") {
        res.writeHead(200);
        return res.end(mainTgz.tgz);
      }
      if (req.url === `/${platPkg}/-/${platSuffix}-1.2.0.tgz`) {
        res.writeHead(200);
        return res.end(tamperedPlatBuf);
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    const registryUrl = `http://127.0.0.1:${server.address().port}`;
    const tmpRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "iroh-tamper-"));
    const irohDir = path.join(tmpRoot, "iroh");
    const integrityOverrides = {
      "@number0/iroh": mainTgz.sha512,
      [platPkg]: platTgz.sha512,
    };

    try {
      await expect(
        installIroh(irohDir, { registries: [registryUrl], integrityOverrides }),
      ).rejects.toThrow(/sha512 mismatch/);

      expect(getIrohStatus(irohDir).installed).toBe(false);
      // Either irohDir was cleanly removed or contains zero staging/node_modules artifacts
      expect(fs.existsSync(path.join(irohDir, "node_modules"))).toBe(false);
      expect(fs.existsSync(irohDir)).toBe(false);
    } finally {
      await new Promise((r) => server.close(r));
      await fsp.rm(tmpRoot, { recursive: true, force: true });
    }
  });

  test("rejects tar path traversal entries and cleans up staging dir", async () => {
    const platPkg = platformPackageName();
    const platSuffix = platPkg.split("/")[1];
    const evilTgz = buildUstarTgz({
      "package/../../evil.txt": "pwned",
    });
    const platTgz = buildUstarTgz({
      "package/package.json": JSON.stringify({ name: platPkg, version: "1.2.0", main: "native.cjs" }),
      "package/native.cjs": "module.exports = {};\n",
    });

    const server = http.createServer((req, res) => {
      if (req.url === "/@number0/iroh/-/iroh-1.2.0.tgz") {
        res.writeHead(200);
        return res.end(evilTgz.tgz);
      }
      if (req.url === `/${platPkg}/-/${platSuffix}-1.2.0.tgz`) {
        res.writeHead(200);
        return res.end(platTgz.tgz);
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    const registryUrl = `http://127.0.0.1:${server.address().port}`;
    const tmpRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "iroh-traversal-"));
    const irohDir = path.join(tmpRoot, "iroh");
    await fsp.mkdir(irohDir, { recursive: true });

    try {
      await expect(
        installIroh(irohDir, {
          registries: [registryUrl],
          integrityOverrides: { "@number0/iroh": evilTgz.sha512, [platPkg]: platTgz.sha512 },
        }),
      ).rejects.toThrow(/traversal/i);

      expect(fs.existsSync(path.join(tmpRoot, "evil.txt"))).toBe(false);
      expect(await fsp.readdir(irohDir)).toEqual([]);
    } finally {
      await new Promise((r) => server.close(r));
      await fsp.rm(tmpRoot, { recursive: true, force: true });
    }
  });
});
