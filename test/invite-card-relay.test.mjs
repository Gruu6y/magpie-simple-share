import { describe, expect, test } from "bun:test";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { encodeInvite, fingerprintFromPubKey } from "../lib/crypto.mjs";
import {
  buildBootstrapCommand,
  buildShareUrl,
  deriveRelayShareUrl,
  makeInviteCardFilename,
  renderInviteJoinHtml,
} from "../lib/invite-card.mjs";
import { startBlindRelay } from "../relay/simple-share-relay.mjs";

const REPO_ROOT = path.resolve(import.meta.dir, "..");
const EXPECTED_JOIN_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

function makeSampleInvite(overrides = {}) {
  const pk = crypto.randomBytes(32).toString("hex");
  const payload = {
    v: 1,
    m: "p2p",
    h: "Alice的台式机",
    pk,
    id: "inv-abc123456789",
    s: crypto.randomBytes(16).toString("hex"),
    exp: Date.now() + 1800_000,
    ep: { irohEndpointId: pk, relayUrl: "" },
    ...overrides,
  };
  return {
    code: encodeInvite(payload),
    payload,
    fp: fingerprintFromPubKey(payload.pk),
  };
}

function runProcess(cmd, args, { env = process.env, timeoutMs = 15_000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      try { child.kill(); } catch {}
      reject(new Error(`Command timed out: ${cmd} ${args.join(" ")}`));
    }, timeoutMs);
    child.stdout.on("data", (d) => { stdout += d.toString("utf8"); });
    child.stderr.on("data", (d) => { stderr += d.toString("utf8"); });
    child.once("error", (err) => { clearTimeout(timer); reject(err); });
    child.once("close", (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}

describe("deriveRelayShareUrl & buildShareUrl", () => {
  test("derives HTTP(S) /join URLs from IPv4, IPv6, tcp://, ws://, and wss:// relay addresses", () => {
    const code = "mshare1:AbCdEf_0123-xyz";

    expect(deriveRelayShareUrl("118.24.68.19:3499")).toBe("http://118.24.68.19:3499/join");
    expect(deriveRelayShareUrl("118.24.68.19:3499", code)).toBe(`http://118.24.68.19:3499/join/#${code}`);
    expect(deriveRelayShareUrl("118.24.68.19:80")).toBe("http://118.24.68.19/join");
    expect(deriveRelayShareUrl("tcp://118.24.68.19:3499", code)).toBe(`http://118.24.68.19:3499/join/#${code}`);

    expect(deriveRelayShareUrl("[240e:3b1:82c0::1a4]:3499")).toBe("http://[240e:3b1:82c0::1a4]:3499/join");
    expect(deriveRelayShareUrl("[::1]:3499", code)).toBe(`http://[::1]:3499/join/#${code}`);

    expect(deriveRelayShareUrl("ws://1.2.3.4:3499/ws")).toBe("http://1.2.3.4:3499/join");
    expect(deriveRelayShareUrl("ws://[::1]:3499/ws", code)).toBe(`http://[::1]:3499/join/#${code}`);
    expect(deriveRelayShareUrl("wss://relay.example.com/ws")).toBe("https://relay.example.com/join");
    expect(deriveRelayShareUrl("wss://relay.example.com/ws", code)).toBe(`https://relay.example.com/join/#${code}`);
    expect(deriveRelayShareUrl("wss://relay.example.com:8443/ws", code)).toBe(`https://relay.example.com:8443/join/#${code}`);
    expect(deriveRelayShareUrl("wss://relay.example.com/edge/ws")).toBe("https://relay.example.com/edge/join");
  });

  test("returns empty string on invalid or unsafe relay addresses and invite fragments", () => {
    const invalids = [
      "",
      "   ",
      null,
      undefined,
      "1.2.3.4",
      "1.2.3.4:0",
      "1.2.3.4:65536",
      "1.2.3.4:03499",
      "240e:3b1::1:3499",
      "http://1.2.3.4:3499/join",
      "https://relay.example.com/join",
      "javascript:alert(1)",
      "ws://user:pass@relay.example.com/ws",
      "wss://relay.example.com/ws?secret=1",
      "wss://relay.example.com/ws#frag",
      "1.2.3.4:3499\nInjected: 1",
      "1.2.3.4:3499/path",
    ];
    for (const bad of invalids) {
      expect(deriveRelayShareUrl(bad)).toBe("");
    }
    expect(deriveRelayShareUrl("1.2.3.4:3499", "mshare1:bad\nline")).toBe("");
    expect(deriveRelayShareUrl("1.2.3.4:3499", "mshare1:bad<script>")).toBe("");
  });

  test("buildShareUrl prioritizes valid shareBaseUrl, delegates self-relay, and rejects query/hash/whitespace", () => {
    const code = "mshare1:Test_Code-99";
    expect(
      buildShareUrl({
        shareBaseUrl: "https://share.cn-host.example/join/",
        mode: "p2p",
        relayAddr: "1.2.3.4:3499",
        inviteCode: code,
      }),
    ).toBe(`https://share.cn-host.example/join/#${code}`);

    expect(
      buildShareUrl({
        shareBaseUrl: "https://share.cn-host.example/join///",
        inviteCode: "",
      }),
    ).toBe("https://share.cn-host.example/join");

    // Invalid shareBaseUrl (query/hash/whitespace/creds) falls back to self-relay or ""
    expect(
      buildShareUrl({
        shareBaseUrl: "https://bad.example/join?a=1",
        mode: "self-relay",
        relayAddr: "118.24.68.19:3499",
        inviteCode: code,
      }),
    ).toBe(`http://118.24.68.19:3499/join/#${code}`);

    expect(buildShareUrl({ shareBaseUrl: "https://bad.example/join#x", mode: "p2p", inviteCode: code })).toBe("");
    expect(buildShareUrl({ shareBaseUrl: "https://user:pass@bad.example/join", mode: "p2p", inviteCode: code })).toBe("");
    expect(buildShareUrl({ shareBaseUrl: "javascript:alert(1)", mode: "direct", inviteCode: code })).toBe("");
    expect(buildShareUrl({ mode: "p2p", relayAddr: "1.2.3.4:3499", inviteCode: code })).toBe("");
  });
});

describe("makeInviteCardFilename & buildBootstrapCommand", () => {
  test("sanitizes path separators, traversal sequences, quotes, and control chars for safe filenames", () => {
    expect(makeInviteCardFilename("Alice-Workstation")).toBe("simple-share-invite-Alice-Workstation.html");
    const dangerous = makeInviteCardFilename("../../etc/passwd\\..\\bad\r\n\"<>|?*\x00");
    expect(dangerous.endsWith(".html")).toBe(true);
    expect(dangerous).not.toMatch(/[\/\\:*?"<>|\r\n\x00]/);
    expect(dangerous).not.toContain("..");
    expect(/^[\x20-\x7e]+$/.test(dangerous)).toBe(true);

    expect(makeInviteCardFilename("")).toBe("simple-share-invite.html");
    expect(makeInviteCardFilename("我的客厅台式机")).toBe("simple-share-invite.html");
  });

  test("generates clean single-line domestic npmmirror bootstrap commands without leaking inviteCode remotely", () => {
    const { code } = makeSampleInvite();
    const winCmd = buildBootstrapCommand({ platform: "windows", inviteCode: code, port: 3494 });
    const unixCmd = buildBootstrapCommand({ platform: "unix", inviteCode: code, port: 3494 });

    for (const cmd of [winCmd, unixCmd]) {
      expect(cmd).not.toMatch(/[\r\n]/);
      expect(cmd).toContain("https://registry.npmmirror.com");
      expect(cmd).toContain("@gruu6y/page-simple-share");
      expect(cmd).toContain(`http://127.0.0.1:3494/#invite=${encodeURIComponent(code)}`);
      // Invite code must NEVER appear next to any non-loopback URL
      const nonLoopbackUrls = cmd.match(/https?:\/\/(?!127\.0\.0\.1)[^\s'"]+/g) || [];
      for (const u of nonLoopbackUrls) {
        expect(u).not.toContain("mshare1");
        expect(u).not.toContain(code.slice(8, 20));
      }
    }
    expect(winCmd).toContain("Start-Process");
    expect(unixCmd).toContain("command -v magpie");
  });

  test("rejects shell injection payloads in inviteCode, packageName, and npmRegistry", () => {
    const badCodes = [
      "mshare1:abc;calc.exe",
      "mshare1:abc$(whoami)",
      "mshare1:abc' || id #",
      "mshare1:abc\" & dir",
      "mshare1:abc\nrm -rf /",
      "notmshare:abc123",
    ];
    for (const bad of badCodes) {
      expect(() => buildBootstrapCommand({ platform: "windows", inviteCode: bad })).toThrow();
      expect(() => buildBootstrapCommand({ platform: "unix", inviteCode: bad })).toThrow();
    }
    expect(() => buildBootstrapCommand({ packageName: "@bad/pkg;rm -rf /" })).toThrow();
    expect(() => buildBootstrapCommand({ npmRegistry: "https://registry.npmmirror.com';id;'" })).toThrow();
    expect(() => buildBootstrapCommand({ port: 99999 })).toThrow();
  });
});

describe("renderInviteJoinHtml & static docs/join/index.html", () => {
  test("renders self-contained offline card (~15-30KB) with zero external links and full UX elements", () => {
    const { code, fp, payload } = makeSampleInvite({ m: "self-relay", ep: { relayAddr: "118.24.68.19:3499" } });
    const html = renderInviteJoinHtml({
      inviteCode: code,
      hostName: payload.h,
      hostFp: fp,
      mode: "self-relay",
      expiresAt: payload.exp,
      endpointHint: "118.24.68.19:3499",
      port: 3494,
    });

    const bytes = Buffer.byteLength(html, "utf8");
    expect(bytes).toBeGreaterThanOrEqual(12_000);
    expect(bytes).toBeLessThanOrEqual(30_000);

    // Zero external CDN/font/script/image loads
    expect(html).not.toMatch(/<script\b[^>]*\bsrc=/i);
    expect(html).not.toMatch(/<link\b[^>]*\bhref=["']https?:/i);
    expect(html).not.toMatch(/<img\b[^>]*\bsrc=["']https?:/i);
    expect(html).not.toMatch(/@import\b/i);
    expect(html).not.toMatch(/url\(\s*['"]?https?:/i);

    // Core visual & functional features
    expect(html).toContain("prefers-color-scheme:dark");
    expect(html).toContain(payload.h);
    expect(html).toContain(fp);
    expect(html).toContain("模式 2 · 自建极简盲中转");
    expect(html).toContain("118.24.68.19:3499");
    expect(html).toContain("MicroMessenger");
    expect(html).toContain("Windows (PowerShell)");
    expect(html).toContain("macOS (终端)");
    expect(html).toContain("Linux (Shell)");
    expect(html).toContain("1. 请求经端到端加密发往对方电脑的 magpie 执行");
    expect(html).toContain("2. 你的项目文件和命令仍在自己电脑上执行");
    expect(html).toContain("3. 对方只看得到你的设备昵称与累计用量");
    expect(html).toContain("4. 发送申请后，需核对 4 位配对码并经对方同意");
    expect(html).toContain(`http://127.0.0.1:3494/#invite=${encodeURIComponent(code)}`);
    expect(html).toContain("magpie plugin registry https://registry.npmmirror.com");
    expect(html).toContain("magpie plugin add @gruu6y/page-simple-share");

    // Inline script parses cleanly & pure-JS SHA-256 matches node:crypto fingerprint
    const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
    expect(scriptMatch).toBeTruthy();
    expect(() => new Function(scriptMatch[1])).not.toThrow();
    expect(scriptMatch[1]).not.toContain("innerHTML");

    const fnMatch = scriptMatch[1].match(/function sha256Hex\(bytes\)\{[\s\S]*?return out\}/);
    expect(fnMatch).toBeTruthy();
    const sha256Js = new Function("bytes", `${fnMatch[0]}\nreturn sha256Hex(bytes);`);
    const pubBytes = Buffer.from(payload.pk, "hex");
    const h = sha256Js(new Uint8Array(pubBytes)).slice(0, 16);
    expect(`ed25519:${h.slice(0, 4)}·${h.slice(4, 8)}·${h.slice(8, 12)}·${h.slice(12, 16)}`).toBe(fp);
  });

  test("strictly neutralizes XSS payloads in hostName, endpointHint, hostFp, and script JSON", () => {
    const xssHost = `</script><img src=x onerror=alert(1)>"'<b>Evil</b>`;
    const xssHint = `"><svg onload=alert(2)></script><!--`;
    const xssFp = `ed25519:<script>alert(3)</script>`;
    const { code } = makeSampleInvite({ h: xssHost });

    const html = renderInviteJoinHtml({
      inviteCode: code,
      hostName: xssHost,
      hostFp: xssFp,
      mode: "direct",
      expiresAt: Date.now() + 60_000,
      endpointHint: xssHint,
    });

    // No unescaped HTML tags or script-closing breakout anywhere in rendered output
    expect(html).not.toContain("<img src=x");
    expect(html).not.toContain("<svg onload=");
    expect(html).not.toContain("<script>alert(3)</script>");
    expect(html).not.toContain("<b>Evil</b>");

    // Embedded JSON script block must escape </script> as \u003c/script\u003e and parse back cleanly
    const jsonBlock = html.match(/<script id="ss-card-data" type="application\/json">([\s\S]*?)<\/script>/);
    expect(jsonBlock).toBeTruthy();
    expect(jsonBlock[1]).not.toContain("</script>");
    expect(jsonBlock[1]).toContain("\\u003c/script\\u003e");
    const parsed = JSON.parse(jsonBlock[1]);
    expect(parsed.hostName).toBe(xssHost);
    expect(parsed.endpointHint).toBe(xssHint);
  });

  test("static /join mode omits secrets and matches pre-rendered docs/join/index.html", () => {
    const staticHtml = renderInviteJoinHtml({ inviteCode: "" });
    const jsonBlock = staticHtml.match(/<script id="ss-card-data" type="application\/json">([\s\S]*?)<\/script>/);
    const parsed = JSON.parse(jsonBlock[1]);
    expect(parsed.staticMode).toBe(true);
    expect(parsed.inviteCode).toBe("");
    expect(staticHtml).toContain("location.hash");

    const diskHtml = fs.readFileSync(path.join(REPO_ROOT, "docs", "join", "index.html"), "utf8");
    expect(diskHtml).toBe(staticHtml);
  });
});

describe("Mode 2 blind relay GET /join route & standalone Docker compatibility", () => {
  test("GET /join, GET /join/, and HEAD /join return 200 HTML with strict CSP and Cache-Control: no-store", async () => {
    const relay = await startBlindRelay({ host: "127.0.0.1", port: 0, token: "test-token" });
    try {
      for (const route of ["/join", "/join/"]) {
        const res = await fetch(`http://127.0.0.1:${relay.port}${route}`);
        expect(res.status).toBe(200);
        expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
        expect(res.headers.get("cache-control")).toBe("no-store");
        expect(res.headers.get("content-security-policy")).toBe(EXPECTED_JOIN_CSP);
        expect(res.headers.get("x-content-type-options")).toBe("nosniff");
        expect(res.headers.get("referrer-policy")).toBe("no-referrer");

        const body = await res.text();
        expect(body).toContain("<!doctype html>");
        expect(body).toContain("magpie-simple-share");
        expect(body).toContain("location.hash");
        expect(body).not.toMatch(/<script\b[^>]*\bsrc=/i);
      }

      const headRes = await fetch(`http://127.0.0.1:${relay.port}/join`, { method: "HEAD" });
      expect(headRes.status).toBe(200);
      expect(headRes.headers.get("content-security-policy")).toBe(EXPECTED_JOIN_CSP);
      expect(await headRes.text()).toBe("");

      // Existing /health still works
      const health = await fetch(`http://127.0.0.1:${relay.port}/health`);
      expect(health.status).toBe(200);
      expect(await health.json()).toEqual({ ok: true, mode: "blind-relay" });
    } finally {
      await relay.close();
    }
  });

  test("relay/simple-share-relay.mjs runs standalone without ../lib/invite-card.mjs (Docker ./relay context)", async () => {
    const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), "ss-standalone-relay-"));
    const standaloneScript = path.join(tmpDir, "simple-share-relay.mjs");
    await fsp.copyFile(path.join(REPO_ROOT, "relay", "simple-share-relay.mjs"), standaloneScript);

    const child = spawn(process.execPath, [standaloneScript], {
      cwd: tmpDir,
      env: { ...process.env, HOST: "127.0.0.1", PORT: "0" },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });

    try {
      const listeningLine = await new Promise((resolve, reject) => {
        let out = "";
        let err = "";
        const timer = setTimeout(() => reject(new Error(`Relay startup timeout: ${out} ${err}`)), 8000);
        child.stdout.on("data", (d) => {
          out += d.toString("utf8");
          const m = /listening on [^:\s]+:(\d+)/.exec(out);
          if (m) { clearTimeout(timer); resolve(Number(m[1])); }
        });
        child.stderr.on("data", (d) => { err += d.toString("utf8"); });
        child.once("exit", (c) => { clearTimeout(timer); reject(new Error(`Exited early (${c}): ${err}`)); });
      });

      const res = await fetch(`http://127.0.0.1:${listeningLine}/join`);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
      expect(res.headers.get("cache-control")).toBe("no-store");
      expect(res.headers.get("content-security-policy")).toBe(EXPECTED_JOIN_CSP);
      const html = await res.text();
      expect(html).toContain("<!doctype html>");
      expect(html).toContain("location.hash");
      expect(html).toContain("https://registry.npmmirror.com");
      expect(html).not.toMatch(/<script\b[^>]*\bsrc=/i);
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        await new Promise((resolve) => {
          const t = setTimeout(resolve, 2000);
          child.once("exit", () => { clearTimeout(t); resolve(); });
          try { child.kill(); } catch { clearTimeout(t); resolve(); }
        });
      }
      await fsp.rm(tmpDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }).catch(() => {});
    }
  });
});

describe("Domestic bootstrap scripts (scripts/bootstrap.ps1 & scripts/bootstrap.sh)", () => {
  test("both scripts enforce npmmirror, SHA256 verification, strict invite validation, and no remote secret upload", () => {
    const ps1 = fs.readFileSync(path.join(REPO_ROOT, "scripts", "bootstrap.ps1"), "utf8");
    const sh = fs.readFileSync(path.join(REPO_ROOT, "scripts", "bootstrap.sh"), "utf8");

    expect(ps1).toContain("https://registry.npmmirror.com");
    expect(ps1).toContain("@gruu6y/page-simple-share");
    expect(ps1).toContain("Get-FileHash");
    expect(ps1).toContain("SHA256");
    expect(ps1).toContain("mshare1:[A-Za-z0-9_-]+");
    expect(ps1).toContain("MAGPIE_DOWNLOAD_MIRROR");

    expect(sh).toContain("https://registry.npmmirror.com");
    expect(sh).toContain("@gruu6y/page-simple-share");
    expect(sh).toContain("sha256sum");
    expect(sh).toContain("shasum -a 256");
    expect(sh).toContain("mshare1:[A-Za-z0-9_-]+");
    expect(sh).toContain("MAGPIE_DOWNLOAD_MIRROR");
  });

  test("scripts/bootstrap.ps1 dry-run accepts share URL and rejects shell-injection payloads", async () => {
    if (process.platform !== "win32") return;
    const psExe = Bun.which("pwsh") || Bun.which("powershell");
    if (!psExe) return;

    const { code } = makeSampleInvite({ m: "p2p" });
    const shareUrl = `https://relay.example.com/join/#${code}`;
    const scriptPath = path.join(REPO_ROOT, "scripts", "bootstrap.ps1");

    const okRes = await runProcess(psExe, [
      "-NoProfile",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      scriptPath,
      "-Invite",
      shareUrl,
      "-DryRun",
    ]);
    expect(okRes.code).toBe(0);
    expect(okRes.stdout).toContain("https://registry.npmmirror.com");
    expect(okRes.stdout).toContain(`http://127.0.0.1:3494/#invite=${encodeURIComponent(code)}`);
    expect(okRes.stdout).toContain("Mode 1 Iroh");

    // Verify -Apply -DryRun path & PowerShell AST parse of generated 1-liner
    const applyRes = await runProcess(psExe, [
      "-NoProfile",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      scriptPath,
      shareUrl,
      "-Name",
      "家人的电脑",
      "-Apply",
      "-DryRun",
    ]);
    expect(applyRes.code).toBe(0);
    expect(applyRes.stdout).toContain("SAS");

    const oneLiner = buildBootstrapCommand({ platform: "windows", inviteCode: code });
    const parseRes = await runProcess(psExe, [
      "-NoProfile",
      "-Command",
      "$err = $null; $null = [System.Management.Automation.Language.Parser]::ParseInput($env:SS_CMD, [ref]$null, [ref]$err); if ($err.Count -gt 0) { Write-Error ($err | Out-String); exit 1 }",
    ], { env: { ...process.env, SS_CMD: oneLiner } });
    expect(parseRes.code).toBe(0);

    const badRes = await runProcess(psExe, [
      "-NoProfile",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      scriptPath,
      "-Invite",
      "not-a-valid-code;calc",
      "-DryRun",
    ]);
    expect(badRes.code).not.toBe(0);
  });

  test("scripts/bootstrap.sh passes POSIX syntax check and dry-run when sh is available", async () => {
    const candidates = process.platform === "win32"
      ? ["C:\\Program Files\\Git\\bin\\sh.exe", "C:\\Program Files\\Git\\usr\\bin\\sh.exe"]
      : [Bun.which("sh")].filter(Boolean);
    const shExe = candidates.find((p) => p && fs.existsSync(p));
    if (!shExe) return;

    const scriptPath = path.join(REPO_ROOT, "scripts", "bootstrap.sh");
    const syntax = await runProcess(shExe, ["-n", scriptPath]);
    expect(syntax.code).toBe(0);

    const { code } = makeSampleInvite({ m: "p2p" });
    const okRes = await runProcess(shExe, [scriptPath, "--invite", `https://relay.example.com/join/#${code}`, "--dry-run"]);
    expect(okRes.code).toBe(0);
    expect(okRes.stdout).toContain("https://registry.npmmirror.com");
    expect(okRes.stdout).toContain(`http://127.0.0.1:3494/#invite=${encodeURIComponent(code)}`);
    expect(okRes.stdout).toContain("Mode 1 Iroh");

    const unixOneLiner = buildBootstrapCommand({ platform: "unix", inviteCode: code });
    const oneLinerSyntax = await runProcess(shExe, ["-n", "-c", unixOneLiner]);
    expect(oneLinerSyntax.code).toBe(0);

    const badRes = await runProcess(shExe, [scriptPath, "--invite", "bad$(whoami)", "--dry-run"]);
    expect(badRes.code).not.toBe(0);
  });
});
