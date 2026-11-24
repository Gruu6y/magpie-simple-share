import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import {
  IROH_INTEGRITY,
  IROH_VERSION,
  detectLinuxLibc,
  installIroh,
  platformPackageName,
} from "../../lib/iroh-installer.mjs";
import { resolveMagpieBinary } from "../../lib/magpie-cli.mjs";

let sharedIrohCachePromise = null;

/**
 * Resolves the Magpie CLI binary for tests across Windows, macOS, and Linux.
 */
export function resolveTestMagpieBin(env = process.env) {
  return resolveMagpieBinary(env);
}

/**
 * Returns true when an executable Magpie CLI binary is available for E2E tests.
 */
export function hasTestMagpieBin(env = process.env) {
  const bin = resolveTestMagpieBin(env);
  if (!bin) return false;
  if (fs.existsSync(bin)) return true;
  if (!bin.includes("/") && !bin.includes("\\")) {
    return Boolean(Bun.which(bin));
  }
  return false;
}

async function ensureIrohCacheDir() {
  const platPkg = platformPackageName();
  if (!platPkg) {
    throw new Error(`Unsupported platform/arch for @number0/iroh: ${process.platform}-${process.arch}`);
  }
  const platSuffix = platPkg.split("/")[1];

  const envProbe = (process.env.IROH_PROBE_NODE_MODULES || "").trim();
  if (envProbe) {
    const mainDir = path.join(envProbe, "iroh");
    const platDir = path.join(envProbe, platSuffix);
    if (fs.existsSync(mainDir) && fs.existsSync(platDir)) {
      return { baseNodeModules: envProbe, platPkg, platSuffix };
    }
  }

  if (!sharedIrohCachePromise) {
    sharedIrohCachePromise = (async () => {
      const cacheRoot = path.join(os.tmpdir(), `magpie-simple-share-iroh-cache-${platSuffix}`);
      await installIroh(cacheRoot, { timeoutMs: 90_000 });
      return {
        baseNodeModules: path.join(cacheRoot, "node_modules", "@number0"),
        platPkg,
        platSuffix,
      };
    })().catch((err) => {
      sharedIrohCachePromise = null;
      throw err;
    });
  }

  return sharedIrohCachePromise;
}

/**
 * Populates an isolated `irohDir` for Mode 1 QUIC tests across Windows, macOS, and Linux.
 */
export async function stageLocalIrohDir(irohDir) {
  const { baseNodeModules, platPkg, platSuffix } = await ensureIrohCacheDir();
  const scopeDir = path.join(irohDir, "node_modules", "@number0");
  await fsp.mkdir(scopeDir, { recursive: true });

  const srcMain = path.join(baseNodeModules, "iroh");
  const srcPlat = path.join(baseNodeModules, platSuffix);
  const linkType = process.platform === "win32" ? "junction" : "dir";
  await fsp.symlink(srcMain, path.join(scopeDir, "iroh"), linkType);
  await fsp.symlink(srcPlat, path.join(scopeDir, platSuffix), linkType);

  const manifest = {
    version: IROH_VERSION,
    platform: process.platform,
    arch: process.arch,
    libc: detectLinuxLibc(),
    platformPkg: platPkg,
    integrityVerified: true,
    customIntegrity: false,
    installedAt: new Date().toISOString(),
    packages: {
      "@number0/iroh": { version: IROH_VERSION, integrity: IROH_INTEGRITY["@number0/iroh"] },
      [platPkg]: { version: IROH_VERSION, integrity: IROH_INTEGRITY[platPkg] || "" },
    },
  };
  await fsp.writeFile(path.join(irohDir, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n", "utf8");
}

function findInPath(binName) {
  const pathVal = process.env.PATH || "";
  const delim = process.platform === "win32" ? ";" : ":";
  for (const rawDir of pathVal.split(delim)) {
    const dir = rawDir.trim().replace(/^"(.*)"$/, "$1");
    if (!dir) continue;
    const candidate = path.join(dir, binName);
    if (fs.existsSync(candidate)) return candidate;
  }
  return "";
}

async function resolvePlaywrightCore() {
  const candidates = [];
  const envPw = (process.env.PLAYWRIGHT_CORE_PATH || "").trim();
  if (envPw) candidates.push(envPw);
  candidates.push("playwright-core");

  let lastErr = null;
  for (const spec of candidates) {
    try {
      const mod = await import(spec);
      if (mod?.chromium || mod?.default?.chromium) {
        return { pw: mod?.chromium ? mod : mod.default, error: null };
      }
    } catch (err) {
      lastErr = err;
    }
  }
  return { pw: null, error: lastErr };
}

function resolveBrowserTarget(pw) {
  const envChrome = (process.env.CHROME_PATH || "").trim();
  const exeCandidates = [];
  if (envChrome) exeCandidates.push(envChrome);

  if (process.platform === "win32") {
    exeCandidates.push(
      "C:/Program Files/Google/Chrome/Application/chrome.exe",
      "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
      process.env.LOCALAPPDATA
        ? path.join(process.env.LOCALAPPDATA, "Google", "Chrome", "Application", "chrome.exe")
        : "",
      "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
      "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
    );
  } else if (process.platform === "darwin") {
    exeCandidates.push(
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      path.join(os.homedir(), "Applications", "Google Chrome.app", "Contents", "MacOS", "Google Chrome"),
      "/Applications/Chromium.app/Contents/MacOS/Chromium",
      "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
      "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    );
  } else {
    exeCandidates.push(
      findInPath("google-chrome"),
      findInPath("google-chrome-stable"),
      findInPath("chromium"),
      findInPath("chromium-browser"),
      "/usr/bin/google-chrome",
      "/usr/bin/google-chrome-stable",
      "/usr/bin/chromium",
      "/usr/bin/chromium-browser",
      "/snap/bin/chromium",
    );
  }

  try {
    const pwChromium = pw.chromium.executablePath?.();
    if (pwChromium) exeCandidates.push(pwChromium);
  } catch {}

  const executablePath = exeCandidates.find((p) => p && fs.existsSync(p));
  if (executablePath) {
    return { engine: "chromium", executablePath };
  }

  try {
    const pwWebkit = pw.webkit?.executablePath?.();
    if (pwWebkit && fs.existsSync(pwWebkit)) {
      return { engine: "webkit", executablePath: pwWebkit };
    }
  } catch {}

  return null;
}

/**
 * Returns true when playwright-core and a supported headless browser executable are available.
 */
export async function canLaunchTestBrowser() {
  const { pw } = await resolvePlaywrightCore();
  if (!pw) return false;
  return Boolean(resolveBrowserTarget(pw));
}

/**
 * Dynamically resolves playwright-core and launches a headless browser on Windows, macOS, or Linux.
 */
export async function launchTestBrowser() {
  const { pw, error: lastErr } = await resolvePlaywrightCore();
  if (!pw) {
    throw new Error(
      `playwright-core is not available (set PLAYWRIGHT_CORE_PATH or install playwright-core): ${lastErr?.message || ""}`,
    );
  }

  const target = resolveBrowserTarget(pw);
  if (target?.engine === "chromium") {
    return await pw.chromium.launch({
      executablePath: target.executablePath,
      headless: true,
      args: ["--no-sandbox"],
    });
  }
  if (target?.engine === "webkit") {
    return await pw.webkit.launch({ headless: true });
  }

  return await pw.chromium.launch({
    headless: true,
    args: ["--no-sandbox"],
  });
}
