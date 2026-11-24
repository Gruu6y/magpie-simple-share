import { describe, expect, test } from "bun:test";
import fsp from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { loadOrCreateIdentity } from "../lib/crypto.mjs";
import { createStore } from "../lib/store.mjs";
import { createTransportManager } from "../lib/transport-manager.mjs";
import {
  API_ALPN,
  PAIR_ALPN,
  dialDirectMtls,
  dialRelayMtls,
  startDirectHost,
  startRelayHost,
  testBlindRelayConnectivity,
} from "../lib/transport-mtls.mjs";
import {
  FRAME,
  sendHttpRequestOverChannel,
  serveHttpRequestOnChannel,
} from "../lib/wire.mjs";
import { startBlindRelay } from "../relay/simple-share-relay.mjs";

async function createIdentities(prefix) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), prefix));
  const [host, alice, bob, mallory] = await Promise.all([
    loadOrCreateIdentity(path.join(dir, "host.json")),
    loadOrCreateIdentity(path.join(dir, "alice.json")),
    loadOrCreateIdentity(path.join(dir, "bob.json")),
    loadOrCreateIdentity(path.join(dir, "mallory.json")),
  ]);
  return { dir, host, alice, bob, mallory };
}

function createTcpByteSpy(targetPort) {
  const capturedFromClients = [];
  const sockets = new Set();
  const server = net.createServer((clientSock) => {
    sockets.add(clientSock);
    const upstream = net.createConnection({ host: "127.0.0.1", port: targetPort });
    sockets.add(upstream);
    clientSock.on("data", (chunk) => {
      capturedFromClients.push(Buffer.from(chunk));
      upstream.write(chunk);
    });
    upstream.on("data", (chunk) => {
      capturedFromClients.push(Buffer.from(chunk));
      clientSock.write(chunk);
    });
    const closeBoth = () => {
      clientSock.destroy();
      upstream.destroy();
    };
    clientSock.on("error", closeBoth);
    upstream.on("error", closeBoth);
    clientSock.on("close", () => {
      sockets.delete(clientSock);
      upstream.destroy();
    });
    upstream.on("close", () => {
      sockets.delete(upstream);
      clientSock.destroy();
    });
  });

  return {
    async start() {
      await new Promise((r) => server.listen(0, "127.0.0.1", r));
      return server.address().port;
    },
    capturedTextAndPayloads() {
      const all = Buffer.concat(capturedFromClients);
      return { all, text: all.toString("utf8") };
    },
    async close() {
      for (const s of sockets) s.destroy();
      await new Promise((r) => server.close(r));
    },
  };
}

describe("Mode 3 Direct TLS 1.3 mTLS", () => {
  test("Alice passes mTLS API streaming; Mallory fails at TLS handshake with 0 app bytes; wrong host pin fails", async () => {
    const { dir, host, alice, mallory } = await createIdentities("m3-auth-");
    let appHits = 0;
    let inviteActive = false;
    const tlsErrors = [];

    const directHost = await startDirectHost({
      identity: host,
      host: "127.0.0.1",
      port: 0,
      isAuthorizedPeer: (pk) => pk === alice.pubKeyHex,
      getAuthorizedCertPems: () => [alice.certPem],
      hasActiveInvite: () => inviteActive,
      onTlsError: (err) => tlsErrors.push(err?.code || err?.message),
      onApiChannel: (channel, meta) => {
        appHits += 1;
        expect(meta.peerPubKeyHex).toBe(alice.pubKeyHex);
        serveHttpRequestOnChannel(channel, async (req) => {
          const bodyText = await new Response(req.body).text();
          return {
            status: 200,
            headers: { "content-type": "text/event-stream" },
            body: new ReadableStream({
              start(ctrl) {
                ctrl.enqueue(new TextEncoder().encode(`data: ${req.path}:${bodyText}\n\n`));
                ctrl.enqueue(new TextEncoder().encode("data: [DONE]\n\n"));
                ctrl.close();
              },
            }),
          };
        });
      },
      onPairChannel: (channel, meta) => {
        channel.onFrame((frame) => {
          if (frame.type === FRAME.PAIR_REQ) {
            channel.sendFrame(FRAME.PAIR_STATUS, { status: "pending", peer: meta.peerPubKeyHex });
          }
        });
      },
    });

    try {
      // 1. Alice succeeds and streams SSE
      const dialAlice = await dialDirectMtls(alice, {
        host: "127.0.0.1",
        port: directHost.port,
        expectedHostPubKeyHex: host.pubKeyHex,
        expectedHostCertPem: host.certPem,
        alpn: API_ALPN,
      });
      const res = await sendHttpRequestOverChannel(dialAlice.channel, {
        method: "POST",
        path: "/v1/chat/completions",
        headers: { "content-type": "application/json" },
        bodyStream: '{"model":"gpt-4o"}',
      });
      expect(res.status).toBe(200);
      expect(await new Response(res.body).text()).toBe('data: /v1/chat/completions:{"model":"gpt-4o"}\n\ndata: [DONE]\n\n');
      expect(appHits).toBe(1);
      await dialAlice.close();

      // 2. Mallory rejected at TLS handshake layer: 0 app bytes reach onApiChannel
      await expect(
        (async () => {
          const dialMallory = await dialDirectMtls(mallory, {
            host: "127.0.0.1",
            port: directHost.port,
            expectedHostPubKeyHex: host.pubKeyHex,
            expectedHostCertPem: host.certPem,
            alpn: API_ALPN,
          });
          try {
            await sendHttpRequestOverChannel(dialMallory.channel, {
              method: "GET",
              path: "/v1/models",
            });
          } finally {
            await dialMallory.close().catch(() => {});
          }
        })(),
      ).rejects.toThrow();
      expect(appHits).toBe(1);
      expect(tlsErrors.some((e) => String(e).includes("DEPTH_ZERO_SELF_SIGNED_CERT") || String(e).includes("CERT"))).toBe(true);

      // 3. Wrong host pin rejected at client handshake
      await expect(
        dialDirectMtls(alice, {
          host: "127.0.0.1",
          port: directHost.port,
          expectedHostPubKeyHex: mallory.pubKeyHex,
          expectedHostCertPem: mallory.certPem,
          alpn: API_ALPN,
        }),
      ).rejects.toThrow();
      expect(appHits).toBe(1);

      // 4. Pairing ALPN rejected when no active invite, succeeds when invite active
      const pairDenied = await dialDirectMtls(mallory, {
        host: "127.0.0.1",
        port: directHost.port,
        expectedHostPubKeyHex: host.pubKeyHex,
        alpn: PAIR_ALPN,
      }).catch((e) => ({ err: e }));
      if (!pairDenied?.err) {
        await expect(
          pairDenied.channel.onceFrame(FRAME.PAIR_STATUS, 500),
        ).rejects.toThrow();
        await pairDenied.close().catch(() => {});
      }

      inviteActive = true;
      const pairOk = await dialDirectMtls(mallory, {
        host: "127.0.0.1",
        port: directHost.port,
        expectedHostPubKeyHex: host.pubKeyHex,
        alpn: PAIR_ALPN,
      });
      await pairOk.channel.sendFrame(FRAME.PAIR_REQ, { hello: 1 });
      const statusFrame = await pairOk.channel.onceFrame(FRAME.PAIR_STATUS, 2000);
      expect(JSON.parse(Buffer.from(statusFrame.payload).toString("utf8"))).toEqual({
        status: "pending",
        peer: mallory.pubKeyHex,
      });
      await pairOk.close();
    } finally {
      await directHost.close();
      await fsp.rm(dir, { recursive: true, force: true });
    }
  });

  test("empty authorizedCertPems rejects ALL clients (no system CA fallback)", async () => {
    const { dir, host, alice } = await createIdentities("m3-empty-ca-");
    let appHits = 0;

    const directHost = await startDirectHost({
      identity: host,
      host: "127.0.0.1",
      port: 0,
      isAuthorizedPeer: () => false,
      getAuthorizedCertPems: () => [],
      hasActiveInvite: () => false,
      onApiChannel: () => {
        appHits += 1;
      },
    });

    try {
      await expect(
        (async () => {
          const dial = await dialDirectMtls(alice, {
            host: "127.0.0.1",
            port: directHost.port,
            expectedHostPubKeyHex: host.pubKeyHex,
            expectedHostCertPem: host.certPem,
            alpn: API_ALPN,
          });
          try {
            await sendHttpRequestOverChannel(dial.channel, { method: "GET", path: "/v1/models" });
          } finally {
            await dial.close().catch(() => {});
          }
        })(),
      ).rejects.toThrow();
      expect(appHits).toBe(0);
    } finally {
      await directHost.close();
      await fsp.rm(dir, { recursive: true, force: true });
    }
  });
});

describe("Mode 2 Blind Relay TCP & WS mTLS", () => {
  test("Mode 2 TCP relay bridges inner TLS 1.3 mTLS while spy sees zero plaintext prompt/path/key", async () => {
    const { dir, host, alice, mallory } = await createIdentities("m2-tcp-");
    const relayToken = "blind-secret-123";
    const relay = await startBlindRelay({ host: "127.0.0.1", port: 0, token: relayToken });
    const spy = createTcpByteSpy(relay.port);
    const spyPort = await spy.start();
    let appHits = 0;

    const relayHost = await startRelayHost({
      identity: host,
      relayAddr: `127.0.0.1:${spyPort}`,
      relayToken,
      isAuthorizedPeer: (pk) => pk === alice.pubKeyHex,
      getAuthorizedCertPems: () => [alice.certPem],
      hasActiveInvite: () => false,
      onApiChannel: (channel) => {
        appHits += 1;
        serveHttpRequestOnChannel(channel, async (req) => {
          const body = await new Response(req.body).text();
          return {
            status: 200,
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ echoPath: req.path, len: body.length, secretResp: "TOP_SECRET_REPLY_999" }),
          };
        });
      },
    });

    try {
      const clientDial = await dialRelayMtls(alice, {
        relayAddr: `127.0.0.1:${spyPort}`,
        relayToken,
        expectedHostPubKeyHex: host.pubKeyHex,
        expectedHostCertPem: host.certPem,
        alpn: API_ALPN,
      });

      const res = await sendHttpRequestOverChannel(clientDial.channel, {
        method: "POST",
        path: "/v1/chat/completions",
        headers: { "x-secret-hdr": "MAGPIE_SECRET_HDR" },
        bodyStream: '{"model":"claude-sonnet-4-5","prompt":"TOP_SECRET_PROMPT_XYZ"}',
      });
      const json = JSON.parse(await new Response(res.body).text());
      expect(res.status).toBe(200);
      expect(json.echoPath).toBe("/v1/chat/completions");
      expect(appHits).toBe(1);
      await clientDial.close();

      // Verify spy captured TLS 1.3 handshake (0x16 0x03) and ZERO plaintext secrets
      const { all, text } = spy.capturedTextAndPayloads();
      expect(all.includes(Buffer.from([0x16, 0x03]))).toBe(true);
      expect(text).not.toContain("TOP_SECRET_PROMPT_XYZ");
      expect(text).not.toContain("TOP_SECRET_REPLY_999");
      expect(text).not.toContain("/v1/chat/completions");
      expect(text).not.toContain("claude-sonnet-4-5");
      expect(text).not.toContain("MAGPIE_SECRET_HDR");

      // Mallory rejected at inner TLS handshake inside relay tunnel
      await expect(
        (async () => {
          const badDial = await dialRelayMtls(mallory, {
            relayAddr: `127.0.0.1:${spyPort}`,
            relayToken,
            expectedHostPubKeyHex: host.pubKeyHex,
            expectedHostCertPem: host.certPem,
            alpn: API_ALPN,
          });
          try {
            await sendHttpRequestOverChannel(badDial.channel, { method: "GET", path: "/v1/models" });
          } finally {
            await badDial.close().catch(() => {});
          }
        })(),
      ).rejects.toThrow();
      expect(appHits).toBe(1);
    } finally {
      await relayHost.close();
      await spy.close();
      await relay.close();
      await fsp.rm(dir, { recursive: true, force: true });
    }
  });

  test("Mode 2 WebSocket (/ws) relay bridges inner TLS 1.3 mTLS and testBlindRelayConnectivity verifies TCP & WS", async () => {
    const { dir, host, alice } = await createIdentities("m2-ws-");
    const relayToken = "ws-token-456";
    const relay = await startBlindRelay({ host: "127.0.0.1", port: 0, token: relayToken });
    const wsAddr = `ws://127.0.0.1:${relay.port}/ws`;

    const relayHost = await startRelayHost({
      identity: host,
      relayAddr: wsAddr,
      relayToken,
      isAuthorizedPeer: (pk) => pk === alice.pubKeyHex,
      getAuthorizedCertPems: () => [alice.certPem],
      hasActiveInvite: () => false,
      onApiChannel: (channel) => {
        serveHttpRequestOnChannel(channel, async () => ({
          status: 200,
          headers: { "content-type": "text/event-stream" },
          body: "data: ws-mtls-ok\n\n",
        }));
      },
    });

    try {
      const dial = await dialRelayMtls(alice, {
        relayAddr: wsAddr,
        relayToken,
        expectedHostPubKeyHex: host.pubKeyHex,
        expectedHostCertPem: host.certPem,
        alpn: API_ALPN,
      });
      const res = await sendHttpRequestOverChannel(dial.channel, { method: "GET", path: "/v1/models" });
      expect(res.status).toBe(200);
      expect(await new Response(res.body).text()).toBe("data: ws-mtls-ok\n\n");
      await dial.close();

      const tcpProbe = await testBlindRelayConnectivity({ relayAddr: `127.0.0.1:${relay.port}`, relayToken });
      expect(tcpProbe.ok).toBe(true);
      expect(tcpProbe.blindVerified).toBe(true);

      const wsProbe = await testBlindRelayConnectivity({ relayAddr: wsAddr, relayToken });
      expect(wsProbe.ok).toBe(true);
      expect(wsProbe.blindVerified).toBe(true);

      const badProbe = await testBlindRelayConnectivity({ relayAddr: wsAddr, relayToken: "wrong-token" });
      expect(badProbe.ok).toBe(false);
    } finally {
      await relayHost.close();
      await relay.close();
      await fsp.rm(dir, { recursive: true, force: true });
    }
  });
});

describe("TransportManager lifecycle, revocation & strict no-fallback", () => {
  test("reconfigure() revokes Alice immediately while Bob stays connected; no fallback when relay/direct closed", async () => {
    const { dir, host, alice, bob } = await createIdentities("tm-life-");
    const store = createStore(path.join(dir, "state.json"));
    await store.load();
    await store.update((s) => {
      s.sharingEnabled = true;
      s.mode = "direct";
      s.network.directHost = "127.0.0.1";
      s.network.directPort = 0;
      s.members = [
        { id: "m-alice", name: "Alice", clientPubKeyHex: alice.pubKeyHex, clientCertPem: alice.certPem, status: "active" },
        { id: "m-bob", name: "Bob", clientPubKeyHex: bob.pubKeyHex, clientCertPem: bob.certPem, status: "active" },
      ];
    });

    const hostMgr = createTransportManager({
      identity: host,
      irohDir: path.join(dir, "iroh-unused"),
      store,
      directBindHost: "127.0.0.1",
      onApiRequest: async (memberId, req) => ({
        status: 200,
        headers: { "content-type": "text/plain" },
        body: `ok:${memberId}:${req.path}`,
      }),
    });

    const aliceStore = createStore(path.join(dir, "alice-state.json"));
    const bobStore = createStore(path.join(dir, "bob-state.json"));
    await aliceStore.load();
    await bobStore.load();
    const aliceMgr = createTransportManager({ identity: alice, irohDir: path.join(dir, "a-iroh"), store: aliceStore });
    const bobMgr = createTransportManager({ identity: bob, irohDir: path.join(dir, "b-iroh"), store: bobStore });

    try {
      const status = await hostMgr.start();
      expect(status.listening).toBe(true);
      expect(status.activeMode).toBe("direct");
      const ep = hostMgr.getHostEndpointPayload();
      expect(ep.directPort).toBeGreaterThan(0);

      const shareTemplate = {
        mode: "direct",
        ep,
        hostPubKeyHex: host.pubKeyHex,
        hostCertPem: host.certPem,
      };

      const aliceConn = await aliceMgr.dialApi(shareTemplate);
      const bobConn = await bobMgr.dialApi(shareTemplate);

      const rA1 = await sendHttpRequestOverChannel(aliceConn.channel, { method: "GET", path: "/v1/models" });
      expect(await new Response(rA1.body).text()).toBe("ok:m-alice:/v1/models");

      // Revoke Alice and reconfigure
      await store.update((s) => {
        s.members = s.members.filter((m) => m.id !== "m-alice");
      });
      await hostMgr.reconfigure();

      // Alice's existing channel was destroyed & new dial fails
      await expect(
        sendHttpRequestOverChannel(aliceConn.channel, { method: "GET", path: "/v1/models" }),
      ).rejects.toThrow();

      // Bob keeps working cleanly!
      const rB1 = await sendHttpRequestOverChannel(bobConn.channel, { method: "GET", path: "/v1/models" });
      expect(await new Response(rB1.body).text()).toBe("ok:m-bob:/v1/models");

      await aliceConn.close().catch(() => {});
      await bobConn.close();

      // Strict no-fallback on closed relay (Mode 2) and closed direct port (Mode 3)
      const deadPort = ep.directPort;
      await hostMgr.stop();
      await expect(
        aliceMgr.dialApi({ mode: "direct", ep: { directHost: "127.0.0.1", directPort: deadPort }, hostPubKeyHex: host.pubKeyHex, hostCertPem: host.certPem }),
      ).rejects.toThrow();
      await expect(
        aliceMgr.dialApi({ mode: "self-relay", ep: { relayAddr: `127.0.0.1:${deadPort}` }, hostPubKeyHex: host.pubKeyHex, hostCertPem: host.certPem }),
      ).rejects.toThrow();

      const directCheck = await aliceMgr.testDirect({ directHost: "127.0.0.1", directPort: deadPort });
      expect(directCheck.ok).toBe(true);
      expect(directCheck.reachable).toBe(false);
    } finally {
      await aliceMgr.stop();
      await bobMgr.stop();
      await hostMgr.stop();
      await fsp.rm(dir, { recursive: true, force: true });
    }
  });

  test("switches cleanly from Mode 3 direct to Mode 2 self-relay via reconfigure() and keeps paused peer at app layer", async () => {
    const { dir, host, alice } = await createIdentities("tm-switch-");
    const relay = await startBlindRelay({ host: "127.0.0.1", port: 0, token: "sw-tok" });
    const store = createStore(path.join(dir, "state.json"));
    await store.load();
    await store.update((s) => {
      s.sharingEnabled = true;
      s.mode = "direct";
      s.network.directHost = "127.0.0.1";
      s.network.directPort = 0;
      s.network.relayAddr = `ws://127.0.0.1:${relay.port}/ws`;
      s.network.relayToken = "sw-tok";
      s.members = [
        { id: "m-alice", name: "Alice", clientPubKeyHex: alice.pubKeyHex, clientCertPem: alice.certPem, status: "paused" },
      ];
    });

    const hostMgr = createTransportManager({
      identity: host,
      irohDir: path.join(dir, "iroh-none"),
      store,
      directBindHost: "127.0.0.1",
      onApiRequest: async (memberId, _req, ctx) => ({
        status: ctx.member.status === "paused" ? 403 : 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ memberId, status: ctx.member.status }),
      }),
    });

    const aliceStore = createStore(path.join(dir, "alice-state.json"));
    await aliceStore.load();
    const aliceMgr = createTransportManager({ identity: alice, irohDir: path.join(dir, "a-none"), store: aliceStore });

    try {
      const s1 = await hostMgr.start();
      expect(s1.listening).toBe(true);
      expect(s1.activeMode).toBe("direct");
      const oldDirectPort = s1.boundPort;

      // Switch to Mode 2 self-relay
      await store.update((s) => {
        s.mode = "self-relay";
      });
      const s2 = await hostMgr.reconfigure();
      expect(s2.listening).toBe(true);
      expect(s2.activeMode).toBe("self-relay");

      // Old Mode 3 port must be closed
      const probeOld = await aliceMgr.testDirect({ directHost: "127.0.0.1", directPort: oldDirectPort });
      expect(probeOld.reachable).toBe(false);

      // Paused member reaches onApiRequest so host-gateway returns 403 share_paused
      const ep2 = hostMgr.getHostEndpointPayload();
      const d2 = await aliceMgr.dialApi({ mode: "self-relay", ep: ep2, hostPubKeyHex: host.pubKeyHex, hostCertPem: host.certPem });
      const res = await sendHttpRequestOverChannel(d2.channel, { method: "GET", path: "/v1/models" });
      expect(res.status).toBe(403);
      expect(JSON.parse(await new Response(res.body).text())).toEqual({ memberId: "m-alice", status: "paused" });
      await d2.close();
    } finally {
      await aliceMgr.stop();
      await hostMgr.stop();
      await relay.close();
      await fsp.rm(dir, { recursive: true, force: true });
    }
  });
});
