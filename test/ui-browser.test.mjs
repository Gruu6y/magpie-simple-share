import { afterEach, describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startServer } from "../lib/server.mjs";
import { startBlindRelay } from "../relay/simple-share-relay.mjs";
import { canLaunchTestBrowser, launchTestBrowser, stageLocalIrohDir } from "./helpers/platform.mjs";

const UI_DIR = path.resolve(fileURLToPath(new URL("../ui", import.meta.url)));

const HAS_BROWSER = await canLaunchTestBrowser();
const browserTest = HAS_BROWSER || process.env.REQUIRE_BROWSER_TESTS === "1" ? test : test.skip;

const cleanups = [];
const tempDirs = [];

function makeTempDir(prefix = "ss-ui-") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function makeIsolatedEnv(baseDir, magpieAddr) {
  const homeDir = path.join(baseDir, "home");
  const xdgConfig = path.join(baseDir, "xdg-config");
  const xdgCache = path.join(baseDir, "xdg-cache");
  const localAppData = path.join(baseDir, "local-appdata");
  const appData = path.join(baseDir, "appdata");
  const magpieConfig = path.join(xdgConfig, "magpie");
  const dataDir = path.join(baseDir, "simple-share-data");
  for (const d of [homeDir, xdgConfig, xdgCache, localAppData, appData, magpieConfig, dataDir]) {
    fs.mkdirSync(d, { recursive: true });
  }
  return {
    dataDir,
    env: {
      ...process.env,
      HOME: homeDir,
      USERPROFILE: homeDir,
      XDG_CONFIG_HOME: xdgConfig,
      XDG_CACHE_HOME: xdgCache,
      LOCALAPPDATA: localAppData,
      APPDATA: appData,
      MAGPIE_CONFIG_DIR: magpieConfig,
      MAGPIE_SIMPLE_SHARE_DATA: dataDir,
      MAGPIE_SIMPLE_SHARE_DATA_DIR: dataDir,
      MAGPIE_ADDR: magpieAddr,
      MAGPIE_NO_ACCOUNTS: "1",
    },
  };
}

function resolveScreenshotDir() {
  const configured = (process.env.UI_SCREENSHOT_DIR || "").trim();
  if (configured) {
    fs.mkdirSync(configured, { recursive: true });
    return configured;
  }
  return makeTempDir("ss-ui-shots-");
}

function attachPageMonitors(page, label, errors, assetResponses) {
  page.on("pageerror", (err) => errors.push(`[${label} pageerror] ${err.message}`));
  page.on("console", (msg) => {
    if (msg.type() === "error") {
      errors.push(`[${label} console.error] ${msg.text()}`);
    }
  });
  page.on("requestfailed", (req) => {
    errors.push(`[${label} requestfailed] ${req.url()} (${req.failure()?.errorText || "failed"})`);
  });
  page.on("response", (res) => {
    const status = res.status();
    const url = res.url();
    if (status >= 400) {
      errors.push(`[${label} http ${status}] ${url}`);
    }
    try {
      const pathname = new URL(url).pathname;
      if (pathname === "/style.css" || pathname === "/app.js" || pathname === "/host-theme.js") {
        assetResponses.set(`${label}:${pathname}`, status);
      }
    } catch {}
  });
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
      fs.rmSync(tempDirs.pop(), { recursive: true, force: true });
    } catch {}
  }
});

describe("Headless Chrome UI & sandbox iframe E2E", () => {
  browserTest(
    "drives Host & Receiver flows, 3 tabs, Mode 1/2/3 switches, QR invite, SAS approval, pause/resume, streaming test, and sandboxed iframe theme sync with 0 console/page errors",
    async () => {
      const screenshotDir = resolveScreenshotDir();
      const hostBaseDir = makeTempDir("ss-ui-host-");
      const recvBaseDir = makeTempDir("ss-ui-recv-");

      const validKeys = new Map();
      let keySeq = 0;

      const hostMockMagpie = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch(req) {
          const p = new URL(req.url).pathname;
          if (p === "/api/hello") {
            return Response.json({ name: "magpie", version: "0.1.4572" });
          }
          if (p === "/v1/models") {
            return Response.json({
              object: "list",
              data: [
                { id: "deepseek/deepseek-chat", display_name: "DeepSeek Chat", owned_by: "deepseek" },
                { id: "claude/claude-sonnet-4-6", display_name: "Claude Sonnet 4.6", owned_by: "claude" },
              ],
            });
          }
          if (p === "/v1/magpie/limit") {
            const secret = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
            const keyName = validKeys.get(secret) || "";
            return Response.json({ key: keyName, limited: Boolean(keyName) });
          }
          if (p === "/v1/chat/completions") {
            return new Response(
              'data: {"id":"ui-1","model":"deepseek/deepseek-chat","choices":[{"index":0,"delta":{"content":"UPSTREAM_UI_OK"}}]}\n\n' +
                'data: {"id":"ui-1","model":"deepseek/deepseek-chat","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":18,"completion_tokens":8,"total_tokens":26}}\n\n' +
                "data: [DONE]\n\n",
              { headers: { "content-type": "text/event-stream" } },
            );
          }
          return new Response("Not Found", { status: 404 });
        },
      });
      cleanups.push(() => hostMockMagpie.stop(true));

      const hostIso = makeIsolatedEnv(hostBaseDir, `127.0.0.1:${hostMockMagpie.port}`);
      const recvIso = makeIsolatedEnv(recvBaseDir, "127.0.0.1:59990");
      await stageLocalIrohDir(path.join(hostIso.dataDir, "iroh"));
      await stageLocalIrohDir(path.join(recvIso.dataDir, "iroh"));

      const relay = await startBlindRelay({ host: "127.0.0.1", port: 0, token: "ui-relay-tok" });
      cleanups.push(() => relay.close());

      const directProbe = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response("") });
      const freeDirectPort = directProbe.port;
      directProbe.stop(true);

      const hostSrv = await startServer({
        port: 0,
        dataDir: hostIso.dataDir,
        env: hostIso.env,
        transportOptions: {
          directBindHost: "127.0.0.1",
          irohOptions: { relayMode: "minimal", bindAddr: "127.0.0.1:0" },
        },
        createKeyFn: async ({ name }) => {
          keySeq += 1;
          const keyId = `kid-ui-${keySeq}`;
          const keySecret = `sk-magpie-key-ui-${keySeq}`;
          validKeys.set(keySecret, name);
          return { keyId, keyName: name, keySecret };
        },
        updateKeyFn: async ({ keyId }) => ({ ok: true, keyId }),
        removeKeyFn: async ({ keyId }) => {
          const suffix = `-${keyId.replace("kid-ui-", "")}`;
          for (const [sec] of validKeys.entries()) {
            if (sec.endsWith(suffix)) validKeys.delete(sec);
          }
          return { ok: true, keyId };
        },
      });
      cleanups.push(() => hostSrv.close());

      const recvSrv = await startServer({
        port: 0,
        dataDir: recvIso.dataDir,
        env: recvIso.env,
        transportOptions: {
          directBindHost: "127.0.0.1",
          irohOptions: { relayMode: "minimal", bindAddr: "127.0.0.1:0" },
        },
        discoverGatewayFn: async () => ({ ok: false, running: false, url: "", addr: "", version: "" }),
        fetchModelsFn: async () => [],
        addProviderFn: async (p) => ({ ok: true, ...p }),
        removeProviderFn: async ({ id }) => ({ ok: true, id }),
      });
      cleanups.push(() => recvSrv.close());

      // Local Magpie-like host wrapper serving <iframe sandbox="allow-scripts">
      const wrapperServer = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch() {
          const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Magpie Sandbox Wrapper</title>
  <link rel="icon" href="data:," />
</head>
<body style="margin:0;background:#111;">
  <iframe id="magpie-frame" sandbox="allow-scripts" src="${hostSrv.url}/?theme=light" style="width:100vw;height:100vh;border:0;"></iframe>
</body>
</html>`;
          return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } });
        },
      });
      cleanups.push(() => wrapperServer.stop(true));

      const browser = await launchTestBrowser();
      cleanups.push(() => browser.close());

      // Use isolated BrowserContexts so Host & Receiver tabs never background-throttle each other.
      const hostCtx = await browser.newContext({ viewport: { width: 1280, height: 860 } });
      const recvCtx = await browser.newContext({ viewport: { width: 1280, height: 860 } });
      const sandboxCtx = await browser.newContext({ viewport: { width: 1280, height: 860 } });
      cleanups.push(() => hostCtx.close());
      cleanups.push(() => recvCtx.close());
      cleanups.push(() => sandboxCtx.close());

      const hostPage = await hostCtx.newPage();
      const recvPage = await recvCtx.newPage();
      const sandboxPage = await sandboxCtx.newPage();

      const allErrors = [];
      const assetResponses = new Map();
      attachPageMonitors(hostPage, "host", allErrors, assetResponses);
      attachPageMonitors(recvPage, "recv", allErrors, assetResponses);
      attachPageMonitors(sandboxPage, "sandbox", allErrors, assetResponses);

      // 1. Direct page open on Host + verify all 3 tabs
      await hostPage.goto(hostSrv.url, { waitUntil: "domcontentloaded" });
      await hostPage.waitForSelector("#host-name-text");
      await hostPage.waitForFunction(() => document.querySelector("#gateway-status-pill")?.textContent?.includes("magpie"));

      expect(await hostPage.textContent("#tab-owned")).toContain("我分享出去的");
      expect(await hostPage.textContent("#tab-received")).toContain("分享给我的");
      expect(await hostPage.textContent("#tab-network")).toContain("连接与安全");

      await hostPage.click("#tab-received");
      expect(await hostPage.isVisible("#panel-received")).toBe(true);

      await hostPage.click("#tab-network");
      expect(await hostPage.isVisible("#panel-network")).toBe(true);
      expect(await hostPage.textContent("#iroh-state-badge")).toContain("已就绪");
      expect(await hostPage.textContent("#badge-mode")).toContain("模式 1");

      // 2. Mode 1 -> Mode 2 -> Mode 3 -> Mode 1 -> Mode 2 switches in UI
      await hostPage.click('[data-select-mode="self-relay"]');
      await hostPage.fill("#input-relay-addr", `127.0.0.1:${relay.port}`);
      await hostPage.fill("#input-relay-token", "ui-relay-tok");
      await hostPage.click("#btn-test-relay");
      await hostPage.waitForFunction(
        () => document.querySelector("#relay-test-result")?.textContent?.includes("盲管道连通正常"),
      );
      await hostPage.click("#btn-save-self-relay");
      await hostPage.waitForFunction(
        () => document.querySelector("#badge-mode")?.textContent?.includes("模式 2"),
      );

      await hostPage.click('[data-select-mode="direct"]');
      await hostPage.fill("#input-direct-host", "127.0.0.1");
      await hostPage.fill("#input-direct-port", String(freeDirectPort));
      await hostPage.click("#btn-test-direct");
      await hostPage.waitForFunction(
        () => (document.querySelector("#direct-test-result")?.textContent || "").trim().length > 0,
      );
      await hostPage.click("#btn-save-direct");
      await hostPage.waitForFunction(
        () => document.querySelector("#badge-mode")?.textContent?.includes("模式 3"),
      );

      // Switch back to Mode 1 P2P and verify badge updates
      await hostPage.click('[data-select-mode="p2p"]');
      await hostPage.waitForFunction(
        () => document.querySelector("#badge-mode")?.textContent?.includes("模式 1"),
      );

      // Switch to Mode 2 self-relay for pairing & screenshot of Network & Security tab
      await hostPage.click('[data-select-mode="self-relay"]');
      await hostPage.waitForFunction(
        () => document.querySelector("#badge-mode")?.textContent?.includes("模式 2"),
      );
      await hostPage.screenshot({ path: path.join(screenshotDir, "ui-network-security.png"), fullPage: false });

      // 3. Host toggle ON (triggers ToS dialog) -> confirm -> generate invite & QR code
      await hostPage.click("#tab-owned");
      await hostPage.click("label:has(#toggle-sharing)");
      await hostPage.waitForSelector("#dlg-tos[open]");
      await hostPage.click("#btn-confirm-tos");
      await hostPage.waitForFunction(() => document.querySelector("#toggle-sharing")?.checked === true);
      await hostPage.waitForFunction(() => !document.querySelector("#btn-create-invite")?.disabled);

      await hostPage.click("#btn-create-invite");
      await hostPage.waitForSelector("#dlg-invite[open]");
      const inviteCode = await hostPage.inputValue("#invite-code-input");
      expect(inviteCode.startsWith("mshare1:")).toBe(true);

      await hostPage.click("#btn-toggle-qr");
      await hostPage.waitForSelector("#invite-qr-svg path");
      const qrMetrics = await hostPage.evaluate(() => {
        const svg = document.querySelector("#invite-qr-svg");
        const pathEl = svg?.querySelector("path");
        const rect = svg?.getBoundingClientRect();
        return {
          pathLen: (pathEl?.getAttribute("d") || "").length,
          width: rect?.width || 0,
          height: rect?.height || 0,
        };
      });
      expect(qrMetrics.pathLen).toBeGreaterThan(200);
      expect(qrMetrics.width).toBeGreaterThan(100);
      expect(qrMetrics.height).toBeGreaterThan(100);
      await hostPage.screenshot({ path: path.join(screenshotDir, "ui-invite-qr.png"), fullPage: false });
      await hostPage.click("#dlg-invite [data-close-dlg]");

      // 4. Receiver browser flow: open tab -> paste invite -> parse -> 4 transparency facts -> apply
      await recvPage.goto(recvSrv.url, { waitUntil: "domcontentloaded" });
      await recvPage.waitForSelector("#tab-received");
      await recvPage.click("#tab-received");
      await recvPage.click("#btn-open-paste");
      await recvPage.waitForSelector("#dlg-paste[open]");
      await recvPage.fill("#paste-code-textarea", inviteCode);
      await recvPage.click("#btn-parse-invite");
      await recvPage.waitForSelector("#paste-step-2:not([hidden])");
      expect(await recvPage.locator("#paste-step-2 .fact-item").count()).toBe(4);

      await recvPage.fill("#input-device-name", "Chrome-Receiver");
      await recvPage.click("#btn-send-apply");
      await recvPage.waitForSelector("#receiver-waiting-wrap .wait-card .sas-big");
      const recvSas = (await recvPage.textContent("#receiver-waiting-wrap .wait-card .sas-big")).trim();
      expect(recvSas).toMatch(/^\d{4}$/);

      // 5. Host browser flow: see pending -> verify matching SAS -> check sub model warning -> approve
      await hostPage.waitForSelector("#pending-list .pending-card", { timeout: 6000 });
      await hostPage.click("#pending-list [data-open-approve]");
      await hostPage.waitForSelector("#dlg-approve[open]");
      const hostSas = (await hostPage.textContent("#approve-sas")).trim();
      expect(hostSas).toBe(recvSas);

      // Select the personal subscription model as well to verify ToS warning appears dynamically
      const subCheckbox = hostPage.locator('#approve-model-picker input[value="claude/claude-sonnet-4-6"]');
      await subCheckbox.check();
      expect(await hostPage.isHidden("#approve-tos-warn")).toBe(false);

      await hostPage.click("#btn-confirm-approve");
      await hostPage.waitForSelector(".member-row", { timeout: 5000 });

      // 6. Pause & Resume in Host UI
      await hostPage.click("[data-toggle-pause]");
      await hostPage.waitForFunction(
        () => document.querySelector(".member-row")?.textContent?.includes("已暂停"),
      );
      await hostPage.click("[data-toggle-pause]");
      await hostPage.waitForFunction(
        () => document.querySelector(".member-row")?.textContent?.includes("正常"),
      );

      // 7. Receiver browser flow: share appears -> run streaming connectivity test
      await recvPage.waitForSelector(".received-card", { timeout: 6000 });
      await recvPage.click(".received-card [data-test-stream]");
      await recvPage.waitForSelector(".received-card .stream-console");
      await recvPage.waitForFunction(
        () => document.querySelector(".received-card .stream-console")?.textContent?.includes("UPSTREAM_UI_OK"),
      );
      const streamConsoleText = await recvPage.textContent(".received-card .stream-console");
      expect(streamConsoleText).toContain("26 tokens");
      await recvPage.screenshot({ path: path.join(screenshotDir, "ui-receiver-stream.png"), fullPage: false });

      // Verify Host usage table updates with the streamed request
      await hostPage.waitForFunction(
        () => document.querySelector(".member-usage")?.textContent?.includes("26 tokens"),
        { timeout: 6000 },
      );

      // 8. <iframe sandbox="allow-scripts"> wrapper + postMessage light/dark theme sync + zero sandbox errors
      await sandboxPage.goto(`http://127.0.0.1:${wrapperServer.port}/`, { waitUntil: "domcontentloaded" });
      await sandboxPage.waitForSelector("#magpie-frame");

      const innerFrame = await (await sandboxPage.$("#magpie-frame")).contentFrame();
      expect(innerFrame).not.toBeNull();
      await innerFrame.waitForSelector(".member-row", { timeout: 5000 });

      // Confirm initial theme from ?theme=light, opaque null origin, and strict storage blocking
      const sandboxCheck = await innerFrame.evaluate(() => {
        let localStorageBlocked = false;
        let cookieBlocked = false;
        try {
          void window.localStorage;
        } catch {
          localStorageBlocked = true;
        }
        try {
          void document.cookie;
        } catch {
          cookieBlocked = true;
        }
        return {
          theme: document.documentElement.dataset.theme,
          origin: window.origin,
          bg: getComputedStyle(document.body).backgroundColor,
          localStorageBlocked,
          cookieBlocked,
        };
      });
      expect(sandboxCheck.theme).toBe("light");
      expect(sandboxCheck.origin).toBe("null");
      expect(sandboxCheck.localStorageBlocked).toBe(true);
      expect(sandboxCheck.cookieBlocked).toBe(true);

      // Verify interactive tab switching works inside strict sandboxed iframe
      await innerFrame.click("#tab-network");
      expect(await innerFrame.isVisible("#panel-network")).toBe(true);
      await innerFrame.click("#tab-owned");
      expect(await innerFrame.isVisible("#panel-owned")).toBe(true);

      // Spoofed/invalid postMessage should be ignored
      await sandboxPage.evaluate(() => {
        const frame = document.getElementById("magpie-frame");
        frame.contentWindow.postMessage({ magpie: 0, event: "theme", data: { dark: true } }, "*");
        frame.contentWindow.postMessage({ magpie: 1, event: "other", data: { dark: true } }, "*");
      });
      await innerFrame.waitForTimeout(100);
      expect(await innerFrame.evaluate(() => document.documentElement.dataset.theme)).toBe("light");

      // Send Magpie host postMessage dark theme -> verify live switch and CSS update
      await sandboxPage.evaluate(() => {
        const frame = document.getElementById("magpie-frame");
        frame.contentWindow.postMessage({ magpie: 1, event: "theme", data: { dark: true, lang: "zh-CN" } }, "*");
      });
      await innerFrame.waitForFunction(
        () =>
          document.documentElement.dataset.theme === "dark" &&
          getComputedStyle(document.body).backgroundColor === "rgb(20, 19, 16)",
      );
      await sandboxPage.waitForTimeout(250);
      const darkBg = await innerFrame.evaluate(() => getComputedStyle(document.body).backgroundColor);
      expect(darkBg).not.toBe(sandboxCheck.bg);
      await sandboxPage.screenshot({ path: path.join(screenshotDir, "ui-sandbox-dark.png"), fullPage: false });

      // Send Magpie host postMessage light theme -> verify live switch back
      await sandboxPage.evaluate(() => {
        const frame = document.getElementById("magpie-frame");
        frame.contentWindow.postMessage({ magpie: 1, event: "theme", data: { dark: false, lang: "zh-CN" } }, "*");
      });
      await innerFrame.waitForFunction(() => document.documentElement.dataset.theme === "light");
      const lightAgainBg = await innerFrame.evaluate(() => getComputedStyle(document.body).backgroundColor);
      expect(lightAgainBg).toBe(sandboxCheck.bg);

      // Verify all local UI assets returned HTTP 200 across direct pages and sandboxed iframe
      for (const label of ["host", "recv", "sandbox"]) {
        for (const asset of ["/style.css", "/app.js", "/host-theme.js"]) {
          expect(assetResponses.get(`${label}:${asset}`)).toBe(200);
        }
      }

      // Assert 0 pageerror, 0 console.error, 0 requestfailed, 0 HTTP >= 400
      expect(allErrors).toEqual([]);
    },
    60_000,
  );

  browserTest(
    "drives Host invite TTL selector, offline HTML card export (download + sandbox fallback), online shareUrl display, and custom shareBaseUrl persistence with 0 errors",
    async () => {
      const screenshotDir = resolveScreenshotDir();
      const sessionToken = "test-ui-contract-token-1234";
      let shareBaseUrl = "";
      let inviteSeq = 0;
      const createdInvites = [];
      const revokedIds = [];
      const cardRequests = [];
      const shareBaseUrlUpdates = [];
      const invitesById = new Map();

      const mimeByExt = {
        ".html": "text/html; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".js": "text/javascript; charset=utf-8",
      };

      const stubServer = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        async fetch(req) {
          const url = new URL(req.url);
          const p = url.pathname;
          const origin = req.headers.get("origin");
          const corsHeaders = {
            "access-control-allow-origin": origin ?? "*",
            vary: "Origin",
          };

          if (p.startsWith("/api/")) {
            if (req.method === "OPTIONS") {
              return new Response(null, {
                status: 204,
                headers: {
                  ...corsHeaders,
                  "access-control-allow-methods": "GET, POST, PATCH, DELETE",
                  "access-control-allow-headers": "x-simple-share-token, content-type",
                },
              });
            }
            if (req.headers.get("x-simple-share-token") !== sessionToken) {
              return Response.json(
                { error: "unauthorized", message: "Invalid token" },
                { status: 401, headers: corsHeaders },
              );
            }

            if (p === "/api/state" && req.method === "GET") {
              return Response.json(
                {
                  mode: "p2p",
                  sharingEnabled: true,
                  tosAcknowledged: true,
                  identity: {
                    hostName: "家里台式机",
                    fingerprint: "ed25519:a1b2·c3d4·e5f6·0718",
                    irohEndpointId: "a".repeat(64),
                  },
                  network: {
                    irohRelayUrl: "",
                    relayAddr: "",
                    relayToken: "",
                    directHost: "",
                    directPort: 3497,
                    shareBaseUrl,
                  },
                  irohStatus: { installed: true, integrityOk: true, supported: true, version: "1.2.0" },
                  magpieGateway: { ok: true, running: true, addr: "127.0.0.1:3425", version: "0.1.4572" },
                  transportStatus: { mode: "p2p", active: true, error: "" },
                  members: [],
                  pending: [],
                  received: [],
                  receivedPending: [],
                  availableModels: [],
                  usageByMember: {},
                  visibility: { limit: true, quotas: false },
                },
                { headers: corsHeaders },
              );
            }

            if (p === "/api/host/invites" && req.method === "POST") {
              let body = {};
              try {
                body = await req.json();
              } catch {}
              const ttlSec = Number.isInteger(body?.ttlSec) ? body.ttlSec : 300;
              inviteSeq += 1;
              const id = `inv-ui-${inviteSeq}`;
              const code = `mshare1:eyJ2IjoxLCJpZCI6IiR7aWR9In0_${inviteSeq}`;
              const expiresAt = Date.now() + ttlSec * 1000;
              const shareUrl = shareBaseUrl ? `${shareBaseUrl.replace(/\/+$/, "")}/#${code}` : "";
              const cardFilename = `simple-share-invite-${inviteSeq}.html`;
              const inv = { id, code, mode: "p2p", ttlSec, expiresAt, shareUrl, cardFilename };
              createdInvites.push({ id, ttlSec, shareUrl });
              invitesById.set(id, inv);
              return Response.json(inv, { headers: corsHeaders });
            }

            const cardMatch = /^\/api\/host\/invites\/([^/]+)\/card$/.exec(p);
            if (cardMatch && req.method === "GET") {
              const id = decodeURIComponent(cardMatch[1]);
              const inv = invitesById.get(id);
              if (!inv) {
                return Response.json({ error: "not_found", message: "Invite not found" }, { status: 404, headers: corsHeaders });
              }
              cardRequests.push(id);
              const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>简单分享离线邀请卡</title></head><body><h1>来自家里台式机的邀请</h1><pre>${inv.code}</pre></body></html>`;
              return Response.json(
                { ok: true, id, filename: inv.cardFilename, html },
                { headers: corsHeaders },
              );
            }

            const delMatch = /^\/api\/host\/invites\/([^/]+)$/.exec(p);
            if (delMatch && req.method === "DELETE") {
              const id = decodeURIComponent(delMatch[1]);
              revokedIds.push(id);
              invitesById.delete(id);
              return Response.json({ ok: true, id }, { headers: corsHeaders });
            }

            if (p === "/api/host/share-base-url" && req.method === "POST") {
              const body = await req.json();
              const raw = String(body?.shareBaseUrl ?? "").trim();
              if (raw && !/^https?:\/\/[^\s?#]+$/i.test(raw)) {
                return Response.json(
                  { error: "invalid_share_base_url", message: "请输入合法的 http:// 或 https:// 地址" },
                  { status: 400, headers: corsHeaders },
                );
              }
              shareBaseUrl = raw.replace(/\/+$/, "");
              shareBaseUrlUpdates.push(shareBaseUrl);
              return Response.json({ ok: true, shareBaseUrl }, { headers: corsHeaders });
            }

            return Response.json({ error: "not_found", message: "Not found" }, { status: 404, headers: corsHeaders });
          }

          if (p === "/" || p === "/index.html") {
            const html = fs
              .readFileSync(path.join(UI_DIR, "index.html"), "utf8")
              .replaceAll("__SIMPLE_SHARE_TOKEN__", sessionToken);
            return new Response(html, {
              headers: {
                "content-type": mimeByExt[".html"],
                "cache-control": "no-store",
                "content-security-policy":
                  "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; " +
                  "connect-src 'self' http: https:; font-src 'self'; object-src 'none'; base-uri 'none'; " +
                  "form-action 'none'",
              },
            });
          }

          const rel = p.replace(/^\/+/, "");
          const full = path.join(UI_DIR, rel);
          if (rel && !rel.includes("..") && fs.existsSync(full)) {
            const ext = path.extname(full).toLowerCase();
            return new Response(fs.readFileSync(full), {
              headers: {
                ...corsHeaders,
                "content-type": mimeByExt[ext] || "application/octet-stream",
                "cache-control": "no-store",
              },
            });
          }
          return new Response("Not Found", { status: 404 });
        },
      });
      cleanups.push(() => stubServer.stop(true));

      const sandboxWrapper = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch() {
          const html = `<!doctype html><html><head><meta charset="utf-8"><link rel="icon" href="data:,"></head><body style="margin:0;"><iframe id="stub-frame" sandbox="allow-scripts" src="http://127.0.0.1:${stubServer.port}/?theme=light" style="width:100vw;height:100vh;border:0;"></iframe></body></html>`;
          return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } });
        },
      });
      cleanups.push(() => sandboxWrapper.stop(true));

      const browser = await launchTestBrowser();
      cleanups.push(() => browser.close());

      const hostCtx = await browser.newContext({ viewport: { width: 1280, height: 860 }, acceptDownloads: true });
      const sandboxCtx = await browser.newContext({ viewport: { width: 1280, height: 860 } });
      cleanups.push(() => hostCtx.close());
      cleanups.push(() => sandboxCtx.close());

      const page = await hostCtx.newPage();
      const sandboxPage = await sandboxCtx.newPage();
      const errors = [];
      const assets = new Map();
      attachPageMonitors(page, "invite-host", errors, assets);
      attachPageMonitors(sandboxPage, "invite-sandbox", errors, assets);

      await page.goto(`http://127.0.0.1:${stubServer.port}/`, { waitUntil: "domcontentloaded" });
      await page.waitForFunction(() => !document.querySelector("#btn-create-invite")?.disabled);

      // 1. Open invite dialog -> default TTL 300s (5 min), empty shareUrl tip shown
      await page.click("#btn-create-invite");
      await page.waitForSelector("#dlg-invite[open]");
      expect(createdInvites.length).toBe(1);
      expect(createdInvites[0].ttlSec).toBe(300);
      expect(await page.inputValue("#invite-ttl-select")).toBe("300");
      expect(await page.isVisible("#btn-ttl-preset-1800")).toBe(true);
      expect(await page.isHidden("#invite-link-row")).toBe(true);
      expect(await page.isVisible("#invite-link-empty-tip")).toBe(true);
      expect(await page.textContent("#invite-countdown")).toMatch(/^0[45]:\d{2} 后过期$/);

      // 2. Click one-click 30-min preset -> revokes old invite, creates 1800s invite
      await page.click("#btn-ttl-preset-1800");
      await page.waitForFunction(
        () =>
          document.querySelector("#invite-ttl-select")?.value === "1800" &&
          !document.querySelector("#invite-ttl-select")?.disabled &&
          document.querySelector("#btn-ttl-preset-1800")?.hidden === true,
      );
      expect(revokedIds).toContain("inv-ui-1");
      expect(createdInvites[1].ttlSec).toBe(1800);
      expect(await page.isHidden("#btn-ttl-preset-1800")).toBe(true);
      expect(await page.textContent("#invite-countdown")).toMatch(/^(29|30):\d{2} 后过期$/);

      // 3. Switch TTL dropdown to 7200s (2 hours) -> revokes old invite, formats HH:MM:SS
      await page.selectOption("#invite-ttl-select", "7200");
      await page.waitForFunction(
        () =>
          !document.querySelector("#invite-ttl-select")?.disabled &&
          (document.querySelector("#invite-countdown")?.textContent?.includes("01:59:") ||
            document.querySelector("#invite-countdown")?.textContent?.includes("02:00:00")),
      );
      expect(revokedIds).toContain("inv-ui-2");
      expect(createdInvites[2].ttlSec).toBe(7200);

      // 4. Export offline HTML invite card -> triggers real Blob download with matching content
      const [download] = await Promise.all([
        page.waitForEvent("download"),
        page.click("#btn-export-invite-card"),
      ]);
      expect(cardRequests).toEqual(["inv-ui-3"]);
      expect(download.suggestedFilename()).toBe("simple-share-invite-3.html");
      const downloadedPath = path.join(makeTempDir("ss-ui-dl-"), download.suggestedFilename());
      await download.saveAs(downloadedPath);
      const downloadedHtml = fs.readFileSync(downloadedPath, "utf8");
      expect(downloadedHtml).toContain("简单分享离线邀请卡");
      expect(downloadedHtml).toContain("mshare1:");

      // 5. Jump from empty shareUrl tip to Network & Security -> Share Base URL input
      await page.click("#btn-jump-share-base-url");
      await page.waitForFunction(() => !document.querySelector("#dlg-invite")?.open);
      expect(await page.isVisible("#panel-network")).toBe(true);
      expect(await page.isVisible("#input-share-base-url")).toBe(true);

      // Verify dirty input protection across poll cycle
      await page.fill("#input-share-base-url", "https://share.example.cn/join");
      await page.locator("#tab-network").focus();
      await page.waitForTimeout(2700);
      expect(await page.inputValue("#input-share-base-url")).toBe("https://share.example.cn/join");

      // Save custom domestic Share Base URL
      await page.click("#btn-save-share-base-url");
      await page.waitForFunction(() =>
        document.querySelector("#share-base-url-result")?.textContent?.includes("已保存在线邀请页地址"),
      );
      expect(shareBaseUrlUpdates).toEqual(["https://share.example.cn/join"]);
      await page.screenshot({ path: path.join(screenshotDir, "ui-share-base-url.png"), fullPage: false });

      // 6. Re-open invite dialog -> online shareUrl row visible with expected URL
      await page.click("#tab-owned");
      await page.click("#btn-create-invite");
      await page.waitForSelector("#dlg-invite[open]");
      expect(await page.isVisible("#invite-link-row")).toBe(true);
      expect(await page.isHidden("#invite-link-empty-tip")).toBe(true);
      const displayedShareUrl = await page.inputValue("#invite-link-input");
      const displayedInviteCode = await page.inputValue("#invite-code-input");
      expect(displayedShareUrl).toBe(`https://share.example.cn/join/#${displayedInviteCode}`);

      // Capture light & dark theme screenshots of updated invite dialog
      await page.screenshot({ path: path.join(screenshotDir, "ui-invite-dialog-light.png"), fullPage: false });
      await page.evaluate(() => {
        document.documentElement.dataset.theme = "dark";
      });
      await page.waitForTimeout(120);
      await page.screenshot({ path: path.join(screenshotDir, "ui-invite-dialog-dark.png"), fullPage: false });
      await page.evaluate(() => {
        document.documentElement.dataset.theme = "light";
      });
      await page.click("#dlg-invite [data-close-dlg]");

      // Clear Share Base URL
      await page.click("#tab-network");
      await page.click("#btn-clear-share-base-url");
      await page.waitForFunction(() =>
        document.querySelector("#share-base-url-result")?.textContent?.includes("已清空"),
      );
      expect(await page.inputValue("#input-share-base-url")).toBe("");
      expect(shareBaseUrlUpdates).toEqual(["https://share.example.cn/join", ""]);

      // 7. Inside <iframe sandbox="allow-scripts">, card export gracefully shows fallback notice without console errors
      await sandboxPage.goto(`http://127.0.0.1:${sandboxWrapper.port}/`, { waitUntil: "domcontentloaded" });
      const frame = await (await sandboxPage.waitForSelector("#stub-frame")).contentFrame();
      expect(frame).not.toBeNull();
      await frame.waitForFunction(() => !document.querySelector("#btn-create-invite")?.disabled);
      await frame.click("#btn-create-invite");
      await frame.waitForSelector("#dlg-invite[open]");
      await frame.click("#btn-export-invite-card");
      await frame.waitForSelector("#invite-card-fallback:not([hidden])");
      expect(await frame.isVisible("#btn-copy-invite-card-html")).toBe(true);

      expect(errors).toEqual([]);
    },
    60_000,
  );

  browserTest(
    "handles receiver #invite= and #mshare1: hash auto-handoff to Step 2 confirmation, scrubs location.hash, and NEVER auto-submits /api/receiver/apply",
    async () => {
      const screenshotDir = resolveScreenshotDir();
      const hostBaseDir = makeTempDir("ss-handoff-host-");
      const recvBaseDir = makeTempDir("ss-handoff-recv-");

      const hostIso = makeIsolatedEnv(hostBaseDir, "127.0.0.1:59991");
      const recvIso = makeIsolatedEnv(recvBaseDir, "127.0.0.1:59992");

      const relay = await startBlindRelay({ host: "127.0.0.1", port: 0, token: "handoff-tok" });
      cleanups.push(() => relay.close());

      const hostSrv = await startServer({
        port: 0,
        dataDir: hostIso.dataDir,
        env: hostIso.env,
        discoverGatewayFn: async () => ({ ok: true, running: true, url: "http://127.0.0.1:59991", addr: "127.0.0.1:59991", version: "0.1.4572" }),
        fetchModelsFn: async () => [{ id: "deepseek/deepseek-chat", label: "DeepSeek Chat", provider: "deepseek", kind: "api" }],
      });
      cleanups.push(() => hostSrv.close());

      const recvSrv = await startServer({
        port: 0,
        dataDir: recvIso.dataDir,
        env: recvIso.env,
        discoverGatewayFn: async () => ({ ok: false, running: false, url: "", addr: "", version: "" }),
        fetchModelsFn: async () => [],
      });
      cleanups.push(() => recvSrv.close());

      // Configure Host in Mode 2 self-relay and generate a real invite code
      const hostHeaders = { "content-type": "application/json", "x-simple-share-token": hostSrv.token };
      const modeRes = await fetch(`${hostSrv.url}/api/network/mode`, {
        method: "POST",
        headers: hostHeaders,
        body: JSON.stringify({
          mode: "self-relay",
          network: { relayAddr: `127.0.0.1:${relay.port}`, relayToken: "handoff-tok" },
        }),
      });
      expect(modeRes.ok).toBe(true);

      const toggleRes = await fetch(`${hostSrv.url}/api/host/toggle`, {
        method: "POST",
        headers: hostHeaders,
        body: JSON.stringify({ enabled: true, tosAcknowledged: true }),
      });
      expect(toggleRes.ok).toBe(true);

      const invRes = await fetch(`${hostSrv.url}/api/host/invites`, {
        method: "POST",
        headers: hostHeaders,
      });
      expect(invRes.ok).toBe(true);
      const invite = await invRes.json();
      expect(invite.code.startsWith("mshare1:")).toBe(true);

      const hostStateRes = await fetch(`${hostSrv.url}/api/state`, { headers: hostHeaders });
      const hostState = await hostStateRes.json();

      const browser = await launchTestBrowser();
      cleanups.push(() => browser.close());
      const ctx = await browser.newContext({ viewport: { width: 1280, height: 860 } });
      cleanups.push(() => ctx.close());

      const recvPage = await ctx.newPage();
      const errors = [];
      const assets = new Map();
      const parseRequests = [];
      const applyRequests = [];
      attachPageMonitors(recvPage, "handoff-recv", errors, assets);
      recvPage.on("request", (req) => {
        try {
          const p = new URL(req.url()).pathname;
          if (p === "/api/receiver/parse") parseRequests.push(req.url());
          if (p === "/api/receiver/apply") applyRequests.push(req.url());
        } catch {}
      });

      // 1. Initial page load with encoded #invite=mshare1%3A... hash
      await recvPage.goto(`${recvSrv.url}/#invite=${encodeURIComponent(invite.code)}`, {
        waitUntil: "domcontentloaded",
      });
      await recvPage.waitForSelector("#dlg-paste[open]");
      await recvPage.waitForSelector("#paste-step-2:not([hidden])");

      // Hash must be cleared immediately and tab switched to "received"
      expect(await recvPage.evaluate(() => window.location.hash)).toBe("");
      expect(await recvPage.isVisible("#panel-received")).toBe(true);
      expect(await recvPage.textContent("#apply-host-fp")).toBe(hostState.identity.fingerprint);
      expect(await recvPage.locator("#paste-step-2 .fact-item").count()).toBe(4);
      expect(await recvPage.isVisible("#btn-send-apply")).toBe(true);
      expect(parseRequests.length).toBe(1);

      // SECURITY INVARIANT: NEVER auto-submit /api/receiver/apply
      await recvPage.waitForTimeout(300);
      expect(applyRequests).toEqual([]);
      const recvStateAfterBoot = await (
        await fetch(`${recvSrv.url}/api/state`, { headers: { "x-simple-share-token": recvSrv.token } })
      ).json();
      expect(recvStateAfterBoot.receivedPending || []).toEqual([]);

      await recvPage.screenshot({ path: path.join(screenshotDir, "ui-hash-handoff-step2.png"), fullPage: false });

      // 2. Dynamic hashchange with direct #mshare1:... format on an already-loaded page
      await recvPage.click("#dlg-paste [data-close-dlg]");
      await recvPage.click("#tab-owned");
      expect(await recvPage.isVisible("#panel-owned")).toBe(true);

      await recvPage.evaluate((code) => {
        window.location.hash = `#${code}`;
      }, invite.code);
      await recvPage.waitForSelector("#dlg-paste[open]");
      await recvPage.waitForSelector("#paste-step-2:not([hidden])");
      expect(await recvPage.evaluate(() => window.location.hash)).toBe("");
      expect(await recvPage.isVisible("#panel-received")).toBe(true);
      expect(applyRequests).toEqual([]);

      // 3. Invalid hash must be ignored and must not open dialog
      await recvPage.click("#dlg-paste [data-close-dlg]");
      await recvPage.evaluate(() => {
        window.location.hash = "#invite=javascript:alert(1)";
      });
      await recvPage.waitForTimeout(200);
      expect(await recvPage.evaluate(() => Boolean(document.querySelector("#dlg-paste")?.open))).toBe(false);

      // 4. Manual paste of full share URL https://.../#mshare1:... into #paste-code-textarea
      await recvPage.click("#btn-open-paste");
      await recvPage.waitForSelector("#dlg-paste[open]");
      await recvPage.fill("#paste-code-textarea", `https://share.example.cn/join/#${invite.code}`);
      await recvPage.click("#btn-parse-invite");
      await recvPage.waitForSelector("#paste-step-2:not([hidden])");
      expect(await recvPage.textContent("#apply-host-fp")).toBe(hostState.identity.fingerprint);
      expect(applyRequests).toEqual([]);

      expect(errors).toEqual([]);
    },
    60_000,
  );
});
