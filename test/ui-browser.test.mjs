import { afterEach, describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startServer } from "../lib/server.mjs";
import { startBlindRelay } from "../relay/simple-share-relay.mjs";
import { canLaunchTestBrowser, launchTestBrowser, stageLocalIrohDir } from "./helpers/platform.mjs";

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
});
