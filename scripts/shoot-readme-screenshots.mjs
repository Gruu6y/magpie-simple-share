/**
 * Generate sanitized README screenshots from the shipped UI + in-process server.
 *
 *   PLAYWRIGHT_CORE_PATH=/path/to/playwright-core/index.mjs bun scripts/shoot-readme-screenshots.mjs
 *
 * Uses isolated temporary directories, synthetic RFC 5737 documentation IPs
 * (203.0.113.x), synthetic device names, and synthetic mock Magpie state so no
 * personal machine paths, real keys, or host Magpie files appear in public images.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { loadOrCreateIdentity } from "../lib/crypto.mjs";
import { getIrohStatus } from "../lib/iroh-installer.mjs";
import { startServer } from "../lib/server.mjs";
import { createStore } from "../lib/store.mjs";
import { launchTestBrowser, stageLocalIrohDir } from "../test/helpers/platform.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ASSETS_DIR = path.join(REPO_ROOT, "assets");

function fakeFp(label) {
  return crypto.createHash("sha256").update(label).digest("hex").slice(0, 16);
}

function fakePubHex(label) {
  return crypto.createHash("sha256").update(label).digest("hex");
}

async function main() {
  const tmpRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "simple-share-shots-"));
  let server = null;
  let browser = null;

  try {
    const dataDir = path.join(tmpRoot, "data");
    const magpieCfgDir = path.join(tmpRoot, "magpie-config");
    await fsp.mkdir(dataDir, { recursive: true });
    await fsp.mkdir(magpieCfgDir, { recursive: true });

    const irohRoot = path.join(dataDir, "iroh");
    await stageLocalIrohDir(irohRoot);

    const hostIdentity = await loadOrCreateIdentity(path.join(dataDir, "identity.json"));
    const now = Date.now();
    const hour = 60 * 60 * 1000;

    const memberHome = {
      id: "m-demo-laptop",
      name: "家里笔记本",
      clientPubKeyHex: fakePubHex("demo-laptop-pub"),
      clientFp: fakeFp("demo-laptop-fp"),
      magpieKeyId: "kid-demo-1",
      magpieKeyName: "ss-home-laptop",
      magpieKeySecret: "sk-magpie-key-demo-only-1",
      status: "active",
      joinedAt: now - 5 * 24 * hour,
      lastUsedAt: now - 12 * 60 * 1000,
      period: "day",
      tokenLimitWan: 200,
      costLimit: 25,
      concurrency: 2,
      models: ["deepseek/deepseek-chat", "anthropic/claude-sonnet-4-5", "openai/gpt-5.2"],
    };

    const memberFriend = {
      id: "m-demo-workstation",
      name: "朋友的工作站",
      clientPubKeyHex: fakePubHex("demo-workstation-pub"),
      clientFp: fakeFp("demo-workstation-fp"),
      magpieKeyId: "kid-demo-2",
      magpieKeyName: "ss-friend-ws",
      magpieKeySecret: "sk-magpie-key-demo-only-2",
      status: "paused",
      joinedAt: now - 14 * 24 * hour,
      lastUsedAt: now - 26 * hour,
      period: "week",
      tokenLimitWan: 500,
      costLimit: 60,
      concurrency: 2,
      models: ["deepseek/deepseek-chat", "google/gemini-2.5-pro"],
    };

    const pendingSister = {
      id: "pend-demo-sister",
      name: "妹妹的 MacBook",
      clientPubKeyHex: fakePubHex("demo-sister-pub"),
      clientFp: fakeFp("demo-sister-fp"),
      sas: "4829",
      mode: "p2p",
      requestedAt: now - 90 * 1000,
      inviteId: "inv-demo-1",
    };

    const receivedDemo = {
      id: "recv-demo-1",
      hostName: "朋友的工作室主机",
      hostPubKeyHex: fakePubHex("demo-remote-host-pub"),
      hostFp: fakeFp("demo-remote-host-fp"),
      providerId: "mshare-studio",
      bridgePort: 34951,
      bridgeToken: "demo-bridge-token",
      mode: "p2p",
      linkStatus: "P2P 直连 · 22ms",
      status: "active",
      period: "day",
      usedTokens: 342_000,
      tokenLimitWan: 200,
      usedCost: 2.18,
      costLimit: 25,
      limitVisible: true,
      models: ["deepseek/deepseek-chat", "openai/gpt-5.2", "claude/claude-sonnet-4-5"],
    };

    const store = createStore(path.join(dataDir, "state.json"));
    await store.load();
    await store.update((draft) => {
      draft.hostName = "书房台式机";
      draft.sharingEnabled = true;
      draft.tosAcknowledged = true;
      draft.mode = "p2p";
      draft.network = {
        irohRelayUrl: "",
        relayAddr: "203.0.113.10:3499",
        relayToken: "demo-relay-token",
        directHost: "home.example.com",
        directPort: 3497,
      };
      draft.visibility = { limit: true, quotas: false };
      draft.pending = [pendingSister];
      draft.members = [memberHome, memberFriend];
      draft.received = [receivedDemo];
      draft.usageEvents = [
        {
          id: "ev-1",
          ts: now - 2 * hour,
          memberId: memberHome.id,
          model: "anthropic/claude-sonnet-4-5",
          turns: 14,
          inputTokens: 168_400,
          outputTokens: 24_600,
          costUsd: 1.54,
        },
        {
          id: "ev-2",
          ts: now - 30 * 60 * 1000,
          memberId: memberHome.id,
          model: "deepseek/deepseek-chat",
          turns: 28,
          inputTokens: 112_000,
          outputTokens: 37_000,
          costUsd: 0.42,
        },
        {
          id: "ev-3",
          ts: now - 4 * hour,
          memberId: memberHome.id,
          model: "openai/gpt-5.2",
          turns: 5,
          inputTokens: 29_500,
          outputTokens: 6_100,
          costUsd: 0.58,
        },
        {
          id: "ev-4",
          ts: now - 3 * 24 * hour,
          memberId: memberFriend.id,
          model: "google/gemini-2.5-pro",
          turns: 19,
          inputTokens: 240_000,
          outputTokens: 31_200,
          costUsd: 1.12,
        },
      ];
    });

    const env = {
      ...process.env,
      MAGPIE_CONFIG_DIR: magpieCfgDir,
      MAGPIE_SIMPLE_SHARE_DATA: dataDir,
      MAGPIE_SIMPLE_SHARE_DATA_DIR: dataDir,
      MAGPIE_ADDR: "127.0.0.1:3425",
    };

    const availableModels = [
      { id: "anthropic/claude-sonnet-4-5", displayName: "Claude Sonnet 4.5", provider: "anthropic", kind: "api" },
      { id: "deepseek/deepseek-chat", displayName: "DeepSeek Chat", provider: "deepseek", kind: "api" },
      { id: "openai/gpt-5.2", displayName: "GPT-5.2", provider: "openai", kind: "api" },
      { id: "google/gemini-2.5-pro", displayName: "Gemini 2.5 Pro", provider: "google", kind: "api" },
      { id: "claude/claude-sonnet-4-5", displayName: "Claude Code (个人订阅)", provider: "claude", kind: "sub" },
    ];

    const irohStatus = getIrohStatus(irohRoot);

    server = await startServer({
      port: 0,
      dataDir,
      identity: hostIdentity,
      store,
      env,
      transportOptions: {
        directBindHost: "127.0.0.1",
        irohOptions: { relayMode: "minimal", bindAddr: "127.0.0.1:0" },
      },
      discoverGatewayFn: async () => ({
        ok: true,
        running: true,
        url: "http://127.0.0.1:3425",
        addr: "127.0.0.1:3425",
        version: "0.1.4758",
      }),
      fetchModelsFn: async () => availableModels,
      getIrohStatusFn: () => irohStatus,
    });

    browser = await launchTestBrowser();
    const ctx = await browser.newContext({
      viewport: { width: 1240, height: 860 },
      deviceScaleFactor: 2,
    });
    const page = await ctx.newPage();

    const errors = [];
    page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
    page.on("console", (msg) => {
      if (msg.type() === "error") errors.push(`console.error: ${msg.text()}`);
    });

    await page.goto(`${server.url}/?theme=light`, { waitUntil: "networkidle" });
    await page.waitForSelector(".member-row .detail-grid", { timeout: 5000 });
    await page.waitForTimeout(250);

    await fsp.mkdir(ASSETS_DIR, { recursive: true });

    // 1. Owned tab (default)
    await page.screenshot({
      path: path.join(ASSETS_DIR, "screenshot-owned.png"),
      fullPage: true,
    });

    // 2. Received tab
    await page.click("#tab-received");
    await page.waitForSelector(".received-card", { timeout: 5000 });
    await page.waitForTimeout(200);
    await page.screenshot({
      path: path.join(ASSETS_DIR, "screenshot-received.png"),
      fullPage: true,
    });

    // 3. Network & Security tab (Mode 1 active & ready, all 6 security checks green, zero toast)
    await page.click("#tab-network");
    await page.waitForSelector("#panel-network:not([hidden])", { timeout: 5000 });
    await page.waitForSelector("#iroh-state-badge", { timeout: 5000 });
    await page.waitForTimeout(200);
    await page.screenshot({
      path: path.join(ASSETS_DIR, "screenshot-network.png"),
      fullPage: true,
    });

    if (errors.length > 0) {
      throw new Error(`UI console/page errors during screenshot capture:\n${errors.join("\n")}`);
    }

    console.log("Generated screenshots:");
    for (const file of ["screenshot-owned.png", "screenshot-received.png", "screenshot-network.png"]) {
      const st = fs.statSync(path.join(ASSETS_DIR, file));
      console.log(`  assets/${file} (${Math.round(st.size / 1024)} KB)`);
    }
  } finally {
    if (browser) await browser.close().catch(() => {});
    if (server) await server.close().catch(() => {});
    await fsp.rm(tmpRoot, { recursive: true, force: true }).catch(() => {});
  }
}

await main();
