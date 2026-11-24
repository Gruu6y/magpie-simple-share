import { describe, expect, test } from "bun:test";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { loadOrCreateIdentity } from "../lib/crypto.mjs";
import {
  getIrohStatus,
  platformPackageName,
} from "../lib/iroh-installer.mjs";
import { createStore } from "../lib/store.mjs";
import {
  API_ALPN,
  PAIR_ALPN,
  dialApi,
  dialPair,
  startIrohHost,
} from "../lib/transport-iroh.mjs";
import { createTransportManager } from "../lib/transport-manager.mjs";
import {
  FRAME,
  sendHttpRequestOverChannel,
  serveHttpRequestOnChannel,
} from "../lib/wire.mjs";
import { stageLocalIrohDir } from "./helpers/platform.mjs";

describe("Mode 1 Iroh QUIC transport (real @number0/iroh@1.2.0)", () => {
  test("pairing, EndpointId match, unauthorized instant close, and SSE streaming", async () => {
    const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), "iroh-mode1-"));
    const irohDir = path.join(tmpDir, "iroh");
    await stageLocalIrohDir(irohDir);

    expect(getIrohStatus(irohDir)).toEqual({
      installed: true,
      version: "1.2.0",
      platformPkg: platformPackageName(),
      supported: true,
      unsupportedReason: null,
      integrityOk: true,
    });

    const hostId = await loadOrCreateIdentity(path.join(tmpDir, "host.json"));
    const aliceId = await loadOrCreateIdentity(path.join(tmpDir, "alice.json"));
    const malloryId = await loadOrCreateIdentity(path.join(tmpDir, "mallory.json"));

    let inviteActive = false;
    let apiStreamsServed = 0;

    const host = await startIrohHost({
      identity: hostId,
      irohDir,
      relayMode: "minimal",
      bindAddr: "127.0.0.1:0",
      isAuthorizedPeer: (pk) => pk === aliceId.pubKeyHex,
      hasActiveInvite: () => inviteActive,
      onPairChannel: (channel, meta) => {
        channel.onFrame((f) => {
          if (f.type === FRAME.PAIR_REQ) {
            channel.sendFrame(FRAME.PAIR_STATUS, { status: "pending", peer: meta.peerPubKeyHex });
          }
        });
      },
      onApiChannel: (channel, meta) => {
        apiStreamsServed += 1;
        expect(meta.peerPubKeyHex).toBe(aliceId.pubKeyHex);
        serveHttpRequestOnChannel(channel, async (req) => ({
          status: 200,
          headers: { "content-type": "text/event-stream" },
          body: new ReadableStream({
            start(ctrl) {
              ctrl.enqueue(new TextEncoder().encode(`data: iroh-ok:${req.path}\n\n`));
              ctrl.enqueue(new TextEncoder().encode("data: [DONE]\n\n"));
              ctrl.close();
            },
          }),
        }));
      },
    });

    try {
      expect(host.endpointId).toBe(hostId.irohEndpointId);
      const addrInfo = host.getAddrInfo();
      expect(addrInfo.directAddrs.length).toBeGreaterThan(0);

      // 1. Pairing rejected when no active invite
      const pairBlocked = await dialPair(
        aliceId,
        irohDir,
        {
          targetIrohId: host.endpointId,
          directAddrs: addrInfo.directAddrs,
          relayMode: "minimal",
        },
        { relayMode: "minimal", bindAddr: "127.0.0.1:0" },
      ).catch((e) => ({ err: e }));
      if (!pairBlocked?.err) {
        await pairBlocked.channel.sendFrame(FRAME.PAIR_REQ, { hello: 1 }).catch(() => {});
        await expect(pairBlocked.channel.onceFrame(FRAME.PAIR_STATUS, 800)).rejects.toThrow();
        await pairBlocked.close().catch(() => {});
      }

      // 2. Pairing succeeds when invite active
      inviteActive = true;
      const pairOk = await dialPair(
        aliceId,
        irohDir,
        {
          targetIrohId: host.endpointId,
          directAddrs: addrInfo.directAddrs,
          relayMode: "minimal",
        },
        { relayMode: "minimal", bindAddr: "127.0.0.1:0" },
      );
      expect(pairOk.peerPubKeyHex).toBe(hostId.pubKeyHex);
      await pairOk.channel.sendFrame(FRAME.PAIR_REQ, { inviteId: "i1" });
      const pairResp = await pairOk.channel.onceFrame(FRAME.PAIR_STATUS, 3000);
      expect(JSON.parse(Buffer.from(pairResp.payload).toString("utf8"))).toEqual({
        status: "pending",
        peer: aliceId.pubKeyHex,
      });
      await pairOk.close();

      // 3. Authorized Alice streams SSE over API_ALPN
      const apiOk = await dialApi(
        aliceId,
        irohDir,
        {
          targetIrohId: host.endpointId,
          directAddrs: addrInfo.directAddrs,
          relayMode: "minimal",
        },
        { relayMode: "minimal", bindAddr: "127.0.0.1:0" },
      );
      expect(apiOk.linkInfo.linkType).toBe("P2P 直连");
      const res = await sendHttpRequestOverChannel(apiOk.channel, {
        method: "POST",
        path: "/v1/chat/completions",
        bodyStream: '{"stream":true}',
      });
      expect(res.status).toBe(200);
      expect(await new Response(res.body).text()).toBe("data: iroh-ok:/v1/chat/completions\n\ndata: [DONE]\n\n");
      expect(apiStreamsServed).toBe(1);
      await apiOk.close();

      // 4. Unauthorized Mallory rejected immediately with 0 streams accepted
      const badApi = await dialApi(
        malloryId,
        irohDir,
        {
          targetIrohId: host.endpointId,
          directAddrs: addrInfo.directAddrs,
          relayMode: "minimal",
        },
        { relayMode: "minimal", bindAddr: "127.0.0.1:0" },
      ).catch((e) => ({ err: e }));
      if (!badApi?.err) {
        await expect(
          sendHttpRequestOverChannel(badApi.channel, { method: "GET", path: "/v1/models" }),
        ).rejects.toThrow();
        await badApi.close().catch(() => {});
      }
      expect(apiStreamsServed).toBe(1);
    } finally {
      await host.close();
      await fsp.rm(tmpDir, { recursive: true, force: true });
    }
  },
  90_000,
);

  test("TransportManager Mode 1 reuses QUIC connection and revokes peer immediately on reconfigure()", async () => {
    const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), "iroh-tm-"));
    const irohDir = path.join(tmpDir, "iroh");
    await stageLocalIrohDir(irohDir);

    const hostId = await loadOrCreateIdentity(path.join(tmpDir, "host.json"));
    const aliceId = await loadOrCreateIdentity(path.join(tmpDir, "alice.json"));

    const hostStore = createStore(path.join(tmpDir, "host-state.json"));
    await hostStore.load();
    await hostStore.update((s) => {
      s.sharingEnabled = true;
      s.mode = "p2p";
      s.members = [
        {
          id: "m-alice",
          name: "Alice",
          clientPubKeyHex: aliceId.pubKeyHex,
          clientCertPem: aliceId.certPem,
          status: "active",
        },
      ];
    });

    const aliceStore = createStore(path.join(tmpDir, "alice-state.json"));
    await aliceStore.load();

    let hits = 0;
    const hostMgr = createTransportManager({
      identity: hostId,
      irohDir,
      store: hostStore,
      irohOptions: { relayMode: "minimal", bindAddr: "127.0.0.1:0" },
      onApiRequest: async (memberId, req) => {
        hits += 1;
        return { status: 200, headers: { "content-type": "text/plain" }, body: `${memberId}:${req.path}` };
      },
    });
    const aliceMgr = createTransportManager({
      identity: aliceId,
      irohDir,
      store: aliceStore,
      irohOptions: { relayMode: "minimal", bindAddr: "127.0.0.1:0" },
    });

    try {
      const st = await hostMgr.start();
      expect(st.listening).toBe(true);
      expect(st.activeMode).toBe("p2p");
      const ep = hostMgr.getHostEndpointPayload();
      expect(ep.irohEndpointId).toBe(hostId.irohEndpointId);

      const share = { mode: "p2p", ep, hostPubKeyHex: hostId.pubKeyHex };

      // Two sequential streams over pooled Iroh QUIC connection
      const d1 = await aliceMgr.dialApi(share);
      const r1 = await sendHttpRequestOverChannel(d1.channel, { method: "GET", path: "/v1/models" });
      expect(await new Response(r1.body).text()).toBe("m-alice:/v1/models");
      await d1.close();

      const d2 = await aliceMgr.dialApi(share);
      const r2 = await sendHttpRequestOverChannel(d2.channel, { method: "GET", path: "/v1/magpie/limit" });
      expect(await new Response(r2.body).text()).toBe("m-alice:/v1/magpie/limit");
      await d2.close();
      expect(hits).toBe(2);

      // Revoke Alice and call reconfigure()
      await hostStore.update((s) => {
        s.members = [];
      });
      await hostMgr.reconfigure();

      const d3 = await aliceMgr.dialApi(share).catch((e) => ({ err: e }));
      if (!d3?.err) {
        await expect(
          sendHttpRequestOverChannel(d3.channel, { method: "GET", path: "/v1/models" }),
        ).rejects.toThrow();
        await d3.close().catch(() => {});
      }
      expect(hits).toBe(2);
    } finally {
      await aliceMgr.stop();
      await hostMgr.stop();
      await fsp.rm(tmpDir, { recursive: true, force: true });
    }
  },
  90_000,
);

  test("TransportManager reports clear error when Mode 1 iroh component is not installed (no fallback)", async () => {
    const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), "iroh-missing-"));
    const hostId = await loadOrCreateIdentity(path.join(tmpDir, "host.json"));
    const store = createStore(path.join(tmpDir, "state.json"));
    await store.load();
    await store.update((s) => {
      s.sharingEnabled = true;
      s.mode = "p2p";
    });
    const mgr = createTransportManager({
      identity: hostId,
      irohDir: path.join(tmpDir, "missing-iroh"),
      store,
    });
    try {
      const st = await mgr.start();
      expect(st.listening).toBe(false);
      expect(st.activeMode).toBe("p2p");
      expect(st.error).toBeTruthy();
    } finally {
      await mgr.stop();
      await fsp.rm(tmpDir, { recursive: true, force: true });
    }
  });
});
