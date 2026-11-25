import crypto from "node:crypto";

export const DEFAULT_PACKAGE_NAME = "@gruu6y/page-simple-share";
export const DEFAULT_NPM_REGISTRY = "https://registry.npmmirror.com";
export const DEFAULT_PORT = 3494;

const INVITE_CODE_RE = /^mshare1:[A-Za-z0-9_-]+$/;
const SAFE_FRAGMENT_RE = /^[A-Za-z0-9:_-]+$/;
const PACKAGE_NAME_RE = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
const SHELL_UNSAFE_URL_RE = /[\s\r\n\0'"`$\\;|&<>()]/;

const MODE_LABELS = Object.freeze({
  p2p: "模式 1 · Iroh P2P 打洞 + 盲中转",
  "self-relay": "模式 2 · 自建极简盲中转",
  direct: "模式 3 · 公网 IPv6/IPv4 直连",
});

function escHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeJsonForScript(obj) {
  return JSON.stringify(obj)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

function normalizePort(port, { strict = false } = {}) {
  if (port === undefined || port === null || port === "") return DEFAULT_PORT;
  const n = Number(port);
  if (Number.isInteger(n) && n >= 1 && n <= 65535) return n;
  if (strict) throw new Error(`Invalid port: ${String(port)}`);
  return DEFAULT_PORT;
}

function normalizeHttpBaseUrl(raw) {
  if (typeof raw !== "string") return "";
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 256 || /[\s\r\n\0]/.test(trimmed)) return "";
  if (trimmed.includes("?") || trimmed.includes("#")) return "";
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return "";
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "";
  if (parsed.username || parsed.password || parsed.search || parsed.hash || !parsed.hostname) {
    return "";
  }
  return parsed.href.replace(/\/+$/, "");
}

function normalizeFragmentCode(inviteCode) {
  if (inviteCode === undefined || inviteCode === null || inviteCode === "") {
    return { ok: true, code: "" };
  }
  if (typeof inviteCode !== "string") return { ok: false, code: "" };
  const trimmed = inviteCode.trim();
  if (!trimmed) return { ok: true, code: "" };
  if (/[\s\r\n\0<>'"]/.test(trimmed) || !SAFE_FRAGMENT_RE.test(trimmed)) {
    return { ok: false, code: "" };
  }
  return { ok: true, code: trimmed };
}

function fingerprintFromPubKeyHex(pubKeyHex) {
  if (typeof pubKeyHex !== "string" || !/^[0-9a-fA-F]{64}$/.test(pubKeyHex)) return "";
  const h = crypto
    .createHash("sha256")
    .update(Buffer.from(pubKeyHex.toLowerCase(), "hex"))
    .digest("hex")
    .slice(0, 16);
  return `ed25519:${h.slice(0, 4)}·${h.slice(4, 8)}·${h.slice(8, 12)}·${h.slice(12, 16)}`;
}

function tryDecodeInviteMeta(inviteCode) {
  if (typeof inviteCode !== "string") return null;
  const trimmed = inviteCode.trim();
  if (!INVITE_CODE_RE.test(trimmed)) return null;
  try {
    const raw = Buffer.from(trimmed.slice("mshare1:".length), "base64url").toString("utf8");
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || parsed.v !== 1) return null;
    const ep = parsed.ep && typeof parsed.ep === "object" ? parsed.ep : null;
    let endpointHint = "";
    if (parsed.m === "self-relay" && typeof ep?.relayAddr === "string") {
      endpointHint = ep.relayAddr.trim();
    } else if (parsed.m === "direct" && typeof ep?.directHost === "string") {
      const dp = Number(ep.directPort) || 3497;
      endpointHint = `${ep.directHost.trim()}:${dp}`;
    } else if (parsed.m === "p2p" && typeof ep?.irohEndpointId === "string" && ep.irohEndpointId.trim()) {
      endpointHint = `Iroh ${ep.irohEndpointId.trim().slice(0, 12)}…`;
    }
    return {
      hostName: typeof parsed.h === "string" ? parsed.h.trim() : "",
      hostFp: fingerprintFromPubKeyHex(parsed.pk),
      mode: typeof parsed.m === "string" ? parsed.m : "",
      expiresAt: typeof parsed.exp === "number" && Number.isFinite(parsed.exp) ? parsed.exp : 0,
      endpointHint,
    };
  } catch {
    return null;
  }
}

/**
 * Convert Mode 2 relay address (`IP:port`, `[ipv6]:port`, `ws://host[:port]/ws`,
 * `wss://host[:port]/ws`, or `tcp://host:port`) into `http(s)://<host>/join`
 * (or `.../join/#${inviteCode}` when inviteCode is provided).
 * Returns `""` on invalid or empty input.
 */
export function deriveRelayShareUrl(relayAddr, inviteCode = "") {
  if (typeof relayAddr !== "string") return "";
  const raw = relayAddr.trim();
  if (!raw || raw.length > 512 || /[\s\r\n\0]/.test(raw)) return "";

  const frag = normalizeFragmentCode(inviteCode);
  if (!frag.ok) return "";

  let joinBase = "";
  if (/^wss?:\/\//i.test(raw)) {
    if (raw.includes("?") || raw.includes("#")) return "";
    let parsed;
    try {
      parsed = new URL(raw);
    } catch {
      return "";
    }
    if (parsed.protocol !== "ws:" && parsed.protocol !== "wss:") return "";
    if (parsed.username || parsed.password || parsed.search || parsed.hash || !parsed.hostname) {
      return "";
    }
    const scheme = parsed.protocol === "wss:" ? "https:" : "http:";
    let basePath = parsed.pathname.replace(/\/+$/, "");
    if (basePath === "/ws") basePath = "";
    else if (basePath.endsWith("/ws")) basePath = basePath.slice(0, -3);
    joinBase = `${scheme}//${parsed.host}${basePath}/join`;
  } else {
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw) && !/^tcp:\/\//i.test(raw)) {
      return "";
    }
    const clean = raw.replace(/^tcp:\/\//i, "");
    if (!clean || /[/?#@\\]/.test(clean)) return "";

    let host;
    let portStr;
    if (clean.startsWith("[")) {
      const m = /^\[([^\]]+)\]:(\d{1,5})$/.exec(clean);
      if (!m) return "";
      host = `[${m[1]}]`;
      portStr = m[2];
    } else {
      const firstColon = clean.indexOf(":");
      const lastColon = clean.lastIndexOf(":");
      if (firstColon <= 0 || firstColon !== lastColon) return "";
      host = clean.slice(0, firstColon);
      portStr = clean.slice(firstColon + 1);
      if (!host || /[[\]]/.test(host)) return "";
    }

    const port = Number(portStr);
    if (!Number.isInteger(port) || port < 1 || port > 65535 || String(port) !== portStr) {
      return "";
    }

    let parsed;
    try {
      parsed = new URL(`http://${host}:${port}/join`);
    } catch {
      return "";
    }
    if (!parsed.hostname) return "";
    if (clean.startsWith("[") && !parsed.hostname.startsWith("[")) return "";
    joinBase = `http://${parsed.host}/join`;
  }

  return frag.code ? `${joinBase}/#${frag.code}` : joinBase;
}

/**
 * Build an online share URL from explicit `shareBaseUrl` or Mode 2 `self-relay` address.
 */
export function buildShareUrl({ shareBaseUrl = "", mode = "", relayAddr = "", inviteCode = "" } = {}) {
  const frag = normalizeFragmentCode(inviteCode);
  if (!frag.ok) return "";

  const validBase = normalizeHttpBaseUrl(shareBaseUrl);
  if (validBase) {
    return frag.code ? `${validBase}/#${frag.code}` : validBase;
  }

  if (mode === "self-relay" && relayAddr) {
    return deriveRelayShareUrl(relayAddr, frag.code);
  }

  return "";
}

/**
 * Generate a safe ASCII `.html` filename for offline invite cards
 * (sanitizes path separators, traversal sequences, quotes, and control chars;
 * safe for both filesystems and HTTP Content-Disposition headers).
 */
export function makeInviteCardFilename(hostName = "") {
  const slug = String(hostName ?? "")
    .normalize("NFKC")
    .replace(/[\x00-\x1f\x7f/\\<>:"|?*]+/g, "-")
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/\.{2,}/g, "-")
    .replace(/-+/g, "-")
    .replace(/^[-.]+|[-.]+$/g, "")
    .slice(0, 40)
    .replace(/[-.]+$/g, "");
  return slug ? `simple-share-invite-${slug}.html` : "simple-share-invite.html";
}

/**
 * Build a clean, single-line domestic-friendly bootstrap command
 * (PowerShell for `"windows"`, POSIX sh for `"unix"`).
 * Strictly validates `inviteCode` (`mshare1:[A-Za-z0-9_-]+`), uses `npmmirror`,
 * and never transmits `inviteCode` to any remote host.
 */
export function buildBootstrapCommand({
  platform = "windows",
  inviteCode = "",
  packageName = DEFAULT_PACKAGE_NAME,
  npmRegistry = DEFAULT_NPM_REGISTRY,
  port = DEFAULT_PORT,
} = {}) {
  const rawCode = typeof inviteCode === "string" ? inviteCode.trim() : "";
  if (inviteCode !== "" && inviteCode !== undefined && inviteCode !== null) {
    if (typeof inviteCode !== "string" || !INVITE_CODE_RE.test(rawCode)) {
      throw new Error("Invalid inviteCode format (expected mshare1:[A-Za-z0-9_-]+)");
    }
  }

  const pkg = typeof packageName === "string" ? packageName.trim() : "";
  if (!PACKAGE_NAME_RE.test(pkg)) {
    throw new Error(`Invalid packageName: ${String(packageName)}`);
  }

  const reg = normalizeHttpBaseUrl(npmRegistry);
  if (!reg || SHELL_UNSAFE_URL_RE.test(reg)) {
    throw new Error(`Invalid npmRegistry URL: ${String(npmRegistry)}`);
  }

  const portNum = normalizePort(port, { strict: true });
  const plat = String(platform ?? "windows").trim().toLowerCase();
  const isWindows = plat === "windows" || plat === "win32" || plat === "powershell";
  const isUnix = plat === "unix" || plat === "macos" || plat === "darwin" || plat === "linux" || plat === "posix" || plat === "sh";
  if (!isWindows && !isUnix) {
    throw new Error(`Unsupported platform: ${String(platform)}`);
  }

  const healthUrl = `http://127.0.0.1:${portNum}/api/health`;
  const handoffUrl = rawCode
    ? `http://127.0.0.1:${portNum}/#invite=${encodeURIComponent(rawCode)}`
    : `http://127.0.0.1:${portNum}/`;

  if (isWindows) {
    return (
      `& { $m=(Get-Command magpie -EA 0 | Select-Object -ExpandProperty Source); ` +
      `if(-not $m){ $c="$env:LOCALAPPDATA\\Programs\\magpie\\magpie.exe"; if(Test-Path $c){ $m=$c } }; ` +
      `if(-not $m){ Write-Host '未检测到 Magpie，请先下载安装：https://usemagpie.ai （国内免梯子请见页面手动步骤）'; return }; ` +
      `if(((& $m plugin list --json 2>$null) -join '') -notmatch 'simple-share'){ ` +
      `& $m plugin registry '${reg}'; & $m plugin add '${pkg}' }; ` +
      `try { $null=Invoke-RestMethod '${healthUrl}' -TimeoutSec 1 } catch { Start-Process -FilePath $m; Start-Sleep -Seconds 2 }; ` +
      `Start-Process '${handoffUrl}' }`
    );
  }

  return (
    `M=$(command -v magpie 2>/dev/null || true); ` +
    `for p in "$HOME/.local/bin/magpie" /opt/homebrew/bin/magpie /usr/local/bin/magpie /Applications/magpie.app/Contents/MacOS/magpie /Applications/Magpie.app/Contents/MacOS/magpie; do [ -z "$M" ] && [ -x "$p" ] && M="$p"; done; ` +
    `if [ -z "$M" ]; then printf '%s\\n' '未检测到 Magpie，请先下载安装：https://usemagpie.ai （国内免梯子请见页面手动步骤）'; ` +
    `else if ! "$M" plugin list --json 2>/dev/null | grep -q 'simple-share'; then "$M" plugin registry '${reg}' && "$M" plugin add '${pkg}'; fi; ` +
    `if ! curl -fsS '${healthUrl}' >/dev/null 2>&1; then ("$M" serve >/dev/null 2>&1 &); sleep 2; fi; ` +
    `U='${handoffUrl}'; (command -v open >/dev/null 2>&1 && open "$U") || (command -v xdg-open >/dev/null 2>&1 && xdg-open "$U") || printf '请在浏览器打开: %s\\n' "$U"; fi`
  );
}

/**
 * Render a self-contained, zero-external-dependency HTML document (~16-24KB)
 * supporting BOTH:
 *  (a) Offline `.html` invite card (when `inviteCode` is embedded), AND
 *  (b) Static `/join` landing page (when `inviteCode === ""`, parsing `location.hash` purely client-side).
 */
export function renderInviteJoinHtml({
  inviteCode = "",
  hostName = "",
  hostFp = "",
  mode = "",
  expiresAt = 0,
  endpointHint = "",
  packageName = DEFAULT_PACKAGE_NAME,
  npmRegistry = DEFAULT_NPM_REGISTRY,
  port = DEFAULT_PORT,
} = {}) {
  const safePort = normalizePort(port);
  const safePkg = PACKAGE_NAME_RE.test(String(packageName ?? "").trim())
    ? String(packageName).trim()
    : DEFAULT_PACKAGE_NAME;
  const safeReg = (() => {
    const u = normalizeHttpBaseUrl(npmRegistry);
    return u && !SHELL_UNSAFE_URL_RE.test(u) ? u : DEFAULT_NPM_REGISTRY;
  })();

  const rawCode = typeof inviteCode === "string" ? inviteCode.trim() : "";
  const hasValidEmbeddedCode = Boolean(rawCode && INVITE_CODE_RE.test(rawCode));
  const invalidEmbeddedCode = Boolean(rawCode && !hasValidEmbeddedCode);
  const decoded = hasValidEmbeddedCode ? tryDecodeInviteMeta(rawCode) : null;

  const finalHostName = String(hostName || decoded?.hostName || "").trim();
  const finalHostFp = String(hostFp || decoded?.hostFp || "").trim();
  const finalMode = String(mode || decoded?.mode || "").trim();
  const finalExpiresAt =
    Number.isFinite(Number(expiresAt)) && Number(expiresAt) > 0
      ? Number(expiresAt)
      : decoded?.expiresAt || 0;
  const finalEndpointHint = String(endpointHint || decoded?.endpointHint || "").trim();

  const isOfflineCard = hasValidEmbeddedCode;
  const modeText = MODE_LABELS[finalMode] || (finalMode ? `通道：${finalMode}` : "等待解析通道");
  const localHref = isOfflineCard
    ? `http://127.0.0.1:${safePort}/#invite=${encodeURIComponent(rawCode)}`
    : `http://127.0.0.1:${safePort}/`;

  const winCmd = buildBootstrapCommand({
    platform: "windows",
    inviteCode: isOfflineCard ? rawCode : "",
    packageName: safePkg,
    npmRegistry: safeReg,
    port: safePort,
  });

  const embeddedData = {
    staticMode: !isOfflineCard && !invalidEmbeddedCode,
    invalidCode: invalidEmbeddedCode,
    inviteCode: isOfflineCard ? rawCode : "",
    hostName: finalHostName,
    hostFp: finalHostFp,
    mode: finalMode,
    expiresAt: finalExpiresAt,
    endpointHint: finalEndpointHint,
    packageName: safePkg,
    npmRegistry: safeReg,
    port: safePort,
  };

  const titleHost = finalHostName ? `${finalHostName} 的分享邀请` : "接收分享邀请";

  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="color-scheme" content="light dark" />
<meta name="referrer" content="no-referrer" />
<title>${escHtml(titleHost)} · 简单分享 (magpie-simple-share)</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg' viewBox='0 0 128 128'%3E%3Crect width='128' height='128' fill='%23faf8f1'/%3E%3Crect x='6' y='6' width='116' height='116' fill='%23faf8f1' stroke='%2317150f' stroke-width='4'/%3E%3Crect x='36' y='98' width='56' height='5' fill='%23b83a15'/%3E%3C/svg%3E" />
<style>
:root{color-scheme:light dark;--paper:#f4f1e7;--paper-2:#ece7da;--paper-3:#faf8f1;--ink:#17150f;--ink-2:#3b372e;--muted:#6b6453;--faint:#9a9280;--line:#d7cfbc;--line-strong:#b2a793;--red:#b83a15;--red-deep:#9a2c0d;--red-soft:rgba(184,58,21,.08);--blue:#2d5777;--blue-soft:rgba(45,87,119,.09);--green:#3f6137;--green-soft:rgba(63,97,55,.1);--amber:#8a5d16;--amber-soft:rgba(138,93,22,.1);--shadow:rgba(23,21,15,.08);--radius:3px;--font:"PingFang SC","Hiragino Sans GB","Microsoft YaHei","Noto Sans SC",system-ui,-apple-system,"Segoe UI",sans-serif;--mono:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){--paper:#141310;--paper-2:#1c1a15;--paper-3:#100f0c;--ink:#f2ede1;--ink-2:#d3ccbb;--muted:#9b9382;--faint:#6f685a;--line:#332f27;--line-strong:#4b453a;--red:#e0673c;--red-deep:#c94e26;--red-soft:rgba(224,103,60,.14);--blue:#7fa8c9;--blue-soft:rgba(127,168,201,.14);--green:#8fae82;--green-soft:rgba(143,174,130,.14);--amber:#d4a44c;--amber-soft:rgba(212,164,76,.14);--shadow:rgba(0,0,0,.45)}}
:root[data-theme="dark"]{color-scheme:dark;--paper:#141310;--paper-2:#1c1a15;--paper-3:#100f0c;--ink:#f2ede1;--ink-2:#d3ccbb;--muted:#9b9382;--faint:#6f685a;--line:#332f27;--line-strong:#4b453a;--red:#e0673c;--red-deep:#c94e26;--red-soft:rgba(224,103,60,.14);--blue:#7fa8c9;--blue-soft:rgba(127,168,201,.14);--green:#8fae82;--green-soft:rgba(143,174,130,.14);--amber:#d4a44c;--amber-soft:rgba(212,164,76,.14);--shadow:rgba(0,0,0,.45)}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:var(--paper);color:var(--ink)}
body{font:14.5px/1.62 var(--font);-webkit-font-smoothing:antialiased}
button,input,textarea{font:inherit;color:inherit}[hidden]{display:none!important}
code,pre,.mono{font-family:var(--mono)}::selection{background:var(--red);color:var(--paper)}
:focus-visible{outline:2px solid var(--red);outline-offset:2px}
.spine{position:fixed;top:0;bottom:0;left:0;width:5px;background:var(--red);z-index:100}
.shell{max-width:780px;margin:0 auto;padding:26px 24px 64px 29px}
.header{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap;padding-bottom:18px;border-bottom:1px solid var(--line);margin-bottom:18px}
.brand{display:flex;align-items:center;gap:14px;flex:1;min-width:240px}
.brand-mark{width:44px;height:44px;flex:0 0 auto;border:1.5px solid var(--ink);background:var(--paper-3);display:grid;place-items:center;position:relative}
.brand-mark::after{content:"";position:absolute;left:8px;right:8px;bottom:6px;height:3px;background:var(--red)}
.brand-mark svg{width:21px;height:21px;transform:translateY(-2px)}
.brand h1{margin:0;font:700 20px/1.25 var(--font);display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.pkg-tag{font:500 11px/1 var(--mono);color:var(--muted);border:1px solid var(--line-strong);padding:3px 7px;border-radius:var(--radius)}
.brand p{margin:4px 0 0;font-size:13px;color:var(--muted)}
.theme-pill{padding:5px 11px;border:1px solid var(--line-strong);border-radius:999px;background:var(--paper-3);color:var(--ink-2);font-size:12.5px;cursor:pointer}
.theme-pill:hover{border-color:var(--red);color:var(--red)}
.banner{padding:12px 15px;margin-bottom:16px;border:1px solid rgba(184,58,21,.35);border-left:3px solid var(--red);background:var(--red-soft);font-size:13px}
.banner.warn{border-color:rgba(138,93,22,.35);border-left-color:var(--amber);background:var(--amber-soft);color:var(--ink)}
.banner strong{display:block;margin-bottom:2px}
.card{background:var(--paper-3);border:1px solid var(--line);padding:18px 20px;margin-bottom:18px}
.card.hero{border-left:3px solid var(--red)}
.hero-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap}
.hero-title{margin:0;font-size:18px;font-weight:700}
.badges{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.badge{display:inline-flex;align-items:center;gap:5px;font-size:12px;font-weight:500;padding:3px 9px;border-radius:999px;background:var(--paper-2);color:var(--ink-2);white-space:nowrap}
.badge.info{background:var(--blue-soft);color:var(--blue)}.badge.ok{background:var(--green-soft);color:var(--green)}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-top:14px;padding-top:14px;border-top:1px dashed var(--line);font-size:12.5px}
.meta-item{background:var(--paper);border:1px solid var(--line);padding:9px 11px}
.meta-label{color:var(--muted);font-size:11.5px;display:block;margin-bottom:2px}
.meta-val{font-weight:600;word-break:break-all}.meta-val.is-expired{color:var(--red)}
.sec-head{display:flex;align-items:baseline;justify-content:space-between;gap:10px;flex-wrap:wrap;padding-bottom:9px;border-bottom:1px solid var(--line);margin-bottom:12px}
.sec-head h2{margin:0;font-size:15.5px;font-weight:600}.sec-sub{font-size:12px;color:var(--muted)}
.fact-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px}
.fact-item{padding:10px 12px;background:var(--paper);border:1px solid var(--line);font-size:12.5px}
.fact-item strong{display:block;color:var(--ink);font-size:13px;margin-bottom:2px}.fact-item span{color:var(--muted)}
.actions{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:12px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:8px 15px;border-radius:var(--radius);border:1px solid var(--line-strong);background:var(--paper);color:var(--ink);font-size:13.5px;font-weight:500;cursor:pointer;text-decoration:none;white-space:nowrap}
.btn:hover:not(:disabled){border-color:var(--ink);background:var(--paper-2)}
.btn.primary{background:var(--red);border-color:var(--red);color:#fff}
.btn.primary:hover:not(:disabled){background:var(--red-deep);border-color:var(--red-deep)}
.btn.sm{padding:5px 11px;font-size:12.5px}.btn[aria-disabled="true"]{opacity:.45;pointer-events:none}
.code-box{display:flex;align-items:stretch;gap:8px;padding:8px 10px;background:var(--paper);border:1px solid var(--line-strong);border-radius:var(--radius);margin-top:10px}
.code-box pre,.code-box input{margin:0;flex:1;min-width:0;border:0;background:transparent;font:12px/1.5 var(--mono);color:var(--ink);white-space:pre-wrap;word-break:break-all}
.code-box input:focus{outline:none}
.os-tabs{display:inline-flex;border:1px solid var(--line-strong);border-radius:var(--radius);overflow:hidden;margin-bottom:10px}
.os-tab{border:0;background:var(--paper);padding:6px 14px;font-size:12.5px;color:var(--muted);cursor:pointer}
.os-tab+.os-tab{border-left:1px solid var(--line-strong)}.os-tab.is-active{background:var(--ink);color:var(--paper-3);font-weight:600}
.steps{margin:12px 0 0;padding-left:20px;color:var(--ink-2);font-size:13px;display:grid;gap:7px}
.steps code{background:var(--paper-2);padding:2px 5px;border-radius:var(--radius);font-size:12px}
.paste-box{display:grid;gap:8px;margin-top:10px}
.paste-box textarea{width:100%;padding:9px 11px;border:1px solid var(--line-strong);border-radius:var(--radius);background:var(--paper);font:12.5px/1.5 var(--mono);resize:vertical}
.note{font-size:12px;color:var(--muted);margin:10px 0 0}
.foot{margin-top:22px;padding-top:14px;border-top:1px solid var(--line);font-size:12px;color:var(--faint);display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}
.toast{position:fixed;right:20px;bottom:20px;padding:9px 14px;background:var(--ink);color:var(--paper-3);border-radius:var(--radius);font-size:13px;box-shadow:0 8px 24px var(--shadow);z-index:200}
@media(max-width:600px){.shell{padding:18px 14px 48px 19px}.code-box{flex-direction:column}}
</style>
</head>
<body>
<div class="spine" aria-hidden="true"></div>
<div class="shell">
<header class="header">
  <div class="brand">
    <div class="brand-mark" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="12" r="2.6"></circle><circle cx="18" cy="6" r="2.6"></circle><circle cx="18" cy="18" r="2.6"></circle><line x1="8.4" y1="10.8" x2="15.6" y2="7.2"></line><line x1="8.4" y1="13.2" x2="15.6" y2="16.8"></line></svg>
    </div>
    <div>
      <h1>简单分享 <span class="pkg-tag">magpie-simple-share</span></h1>
      <p>离线零外链邀请页 · 邀请码仅在当前浏览器本地解析，绝不上传至任何服务器</p>
    </div>
  </div>
  <button type="button" class="theme-pill" id="btn-theme">◑ 浅色 / 深色</button>
</header>

<div class="banner warn" id="wechat-banner" role="alert" hidden>
  <strong>检测到微信内置浏览器（MicroMessenger）</strong>
  请点击右上角「···」选择<strong>「在默认浏览器中打开」</strong>（电脑端点击右上角「用默认浏览器打开」），以便一键唤起本机 Magpie 或复制安装命令。
</div>

<div class="banner" id="error-banner" role="alert"${invalidEmbeddedCode ? "" : " hidden"}>
  <strong>邀请码格式无效或已损坏</strong>
  <span id="error-text">${invalidEmbeddedCode ? "嵌入的邀请码不符合 mshare1: 规范，请联系分享方重新生成。" : ""}</span>
</div>

<section class="card hero" id="hero-card">
  <div class="hero-top">
    <div>
      <h2 class="hero-title" id="card-host-title">${escHtml(finalHostName ? `${finalHostName} 邀请你共用模型额度` : "等待解析分享邀请")}</h2>
      <p class="note" id="card-subtitle" style="margin-top:4px;">${isOfflineCard ? "此离线卡片不含任何真实 API Key，仅用于建立端到端加密配对握手。" : "链接中 # 后面的邀请码仅在当前浏览器本地解析，不会发送给任何服务器。"}</p>
    </div>
    <div class="badges">
      <span class="badge info" id="card-mode-badge">${escHtml(modeText)}</span>
      <span class="badge ok" id="card-offline-badge">${isOfflineCard ? "离线卡片 · 零外链" : "纯本地解析 · 零上传"}</span>
    </div>
  </div>
  <div class="meta-grid" id="meta-grid">
    <div class="meta-item">
      <span class="meta-label">宿主 Ed25519 公钥指纹（首包防中间人）</span>
      <span class="meta-val mono" id="card-host-fp">${escHtml(finalHostFp || "待解析")}</span>
    </div>
    <div class="meta-item">
      <span class="meta-label">有效期（仅一次有效）</span>
      <span class="meta-val" id="card-countdown">${finalExpiresAt > 0 ? "计算剩余时间…" : "待解析"}</span>
    </div>
    <div class="meta-item" id="endpoint-item"${finalEndpointHint ? "" : " hidden"}>
      <span class="meta-label">连接端点提示</span>
      <span class="meta-val mono" id="card-endpoint">${escHtml(finalEndpointHint)}</span>
    </div>
  </div>
  <div class="paste-box" id="manual-paste-section"${isOfflineCard ? " hidden" : ""}>
    <label for="manual-code-input" style="font-size:12.5px;color:var(--ink-2);font-weight:500;">未在网址中检测到 #mshare1:... 邀请码？也可在此粘贴并在本机解析：</label>
    <textarea id="manual-code-input" rows="2" placeholder="粘贴 mshare1:... 邀请码或完整分享链接"></textarea>
    <div><button type="button" class="btn sm" id="btn-manual-parse">本地解析邀请码</button></div>
  </div>
</section>

<section class="card">
  <div class="sec-head"><h2>接收前请知晓（4 项透明事实）</h2><span class="sec-sub">双向公钥钉死 · 零虚拟网卡</span></div>
  <div class="fact-list">
    <div class="fact-item"><strong>1. 请求经端到端加密发往对方电脑的 magpie 执行</strong><span>传输通道采用双向 Ed25519 公钥加密，任何中转节点无法解密正文；用量计入对方额度。</span></div>
    <div class="fact-item"><strong>2. 你的项目文件和命令仍在自己电脑上执行</strong><span>不会开放对方访问你电脑的权限，也不安装任何虚拟网卡（无 TUN），不冲突代理。</span></div>
    <div class="fact-item"><strong>3. 对方只看得到你的设备昵称与累计用量</strong><span>插件日志不记录提示词与回复正文；模型对话会经对方 magpie 发往上游模型商。</span></div>
    <div class="fact-item"><strong>4. 发送申请后，需核对 4 位配对码并经对方同意</strong><span>对方可随时调整可用模型、额度，或暂停/撤销这个分享。</span></div>
  </div>
</section>

<section class="card" id="path-installed">
  <div class="sec-head"><h2>方式 A · 已安装 Magpie 与简单分享插件</h2><span class="sec-sub">打开后先核对指纹与 4 项说明，不会自动提交申请</span></div>
  <div class="actions">
    <a class="btn primary" id="btn-open-local" href="${escHtml(localHref)}"${isOfflineCard ? "" : ' aria-disabled="true"'}>一键打开本机简单分享（127.0.0.1:${safePort}）</a>
    <button type="button" class="btn" id="btn-copy-code"${isOfflineCard ? "" : " disabled"}>复制原始邀请码（mshare1:...）</button>
  </div>
  <div class="code-box"><input type="text" id="raw-code-input" readonly value="${escHtml(isOfflineCard ? rawCode : "")}" placeholder="解析后显示 mshare1:... 原始邀请码" aria-label="原始邀请码" /></div>
  <p class="note">提示：若点击「一键打开」后提示无法连接 127.0.0.1:${safePort}，说明本机尚未启动 Magpie 或未安装插件，请看下方「方式 B」。</p>
</section>

<section class="card" id="path-install">
  <div class="sec-head"><h2>方式 B · 首次使用 / 未安装插件（国内免梯子）</h2><span class="sec-sub">使用国内镜像 ${escHtml(safeReg)} · 绝不上传邀请码</span></div>
  <div class="os-tabs" role="tablist" aria-label="选择你的操作系统">
    <button type="button" class="os-tab is-active" data-os="windows" role="tab" aria-selected="true">Windows (PowerShell)</button>
    <button type="button" class="os-tab" data-os="macos" role="tab" aria-selected="false">macOS (终端)</button>
    <button type="button" class="os-tab" data-os="linux" role="tab" aria-selected="false">Linux (Shell)</button>
  </div>
  <div class="code-box"><pre id="bootstrap-cmd-text">${escHtml(winCmd)}</pre><button type="button" class="btn primary sm" id="btn-copy-cmd">复制一键命令</button></div>
  <p class="note" id="os-tip">在 Windows 按 Win+X 打开「终端 / PowerShell」粘贴回车即可；命令仅在本机运行，邀请码不会发往任何外部服务器。</p>
  <details style="margin-top:14px;" open>
    <summary style="cursor:pointer;font-size:13px;font-weight:600;color:var(--ink-2);">手动分步安装（无梯子环境备用）</summary>
    <ol class="steps">
      <li>下载安装并启动 Magpie（官网 <code>https://usemagpie.ai</code>，如受限可向分享方索取离线安装包）。</li>
      <li>切换国内插件镜像源：<code>magpie plugin registry ${escHtml(safeReg)}</code></li>
      <li>安装简单分享插件：<code>magpie plugin add ${escHtml(safePkg)}</code></li>
      <li>打开左侧「简单分享」→「分享给我的」→「输入分享邀请…」，粘贴上方 <code>mshare1:...</code> 邀请码并核对 4 位配对码即可。</li>
    </ol>
  </details>
</section>

<footer class="foot"><span>magpie-simple-share · 零中心化服务器 · 双向公钥加密</span><span>零外部 CDN / 字体 / 统计脚本</span></footer>
</div>
<div id="toast-wrap" aria-live="polite"></div>
<script id="ss-card-data" type="application/json">${safeJsonForScript(embeddedData)}</script>
<script>
(function(){
"use strict";
var INVITE_RE=/^mshare1:[A-Za-z0-9_-]+$/;
var MODE_LABELS={p2p:"模式 1 · Iroh P2P 打洞 + 盲中转","self-relay":"模式 2 · 自建极简盲中转",direct:"模式 3 · 公网 IPv6/IPv4 直连"};
var cfg={};try{cfg=JSON.parse(document.getElementById("ss-card-data").textContent||"{}")}catch(e){}
var state={code:cfg.inviteCode||"",hostName:cfg.hostName||"",hostFp:cfg.hostFp||"",mode:cfg.mode||"",expiresAt:Number(cfg.expiresAt)||0,endpointHint:cfg.endpointHint||"",os:"windows",port:Number(cfg.port)||3494,pkg:cfg.packageName||"@gruu6y/page-simple-share",reg:cfg.npmRegistry||"https://registry.npmmirror.com"};
function $(id){return document.getElementById(id)}
function toast(msg){var w=$("toast-wrap");if(!w)return;w.textContent="";var el=document.createElement("div");el.className="toast";el.textContent=String(msg||"");w.appendChild(el);setTimeout(function(){if(el.parentNode)el.parentNode.removeChild(el)},2400)}
function fallbackCopy(t){try{var a=document.createElement("textarea");a.value=t;a.setAttribute("readonly","");a.style.position="fixed";a.style.left="-9999px";document.body.appendChild(a);a.select();document.execCommand("copy");document.body.removeChild(a);toast("已复制到剪贴板")}catch(e){toast("请手动选中复制")}}
function copyText(t){if(!t)return;if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(function(){toast("已复制到剪贴板")},function(){fallbackCopy(t)});return}fallbackCopy(t)}
function sha256Hex(bytes){
var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
var len=bytes.length,bl=len*8,pl=(((len+9)+63)>>6)<<6,buf=new Uint8Array(pl);buf.set(bytes);buf[len]=0x80;
var dv=new DataView(buf.buffer);dv.setUint32(pl-8,Math.floor(bl/0x100000000),false);dv.setUint32(pl-4,bl>>>0,false);
var w=new Int32Array(64);
for(var o=0;o<pl;o+=64){
for(var i=0;i<16;i++)w[i]=dv.getInt32(o+i*4,false);
for(var j=16;j<64;j++){var s0=((w[j-15]>>>7)|(w[j-15]<<25))^((w[j-15]>>>18)|(w[j-15]<<14))^(w[j-15]>>>3),s1=((w[j-2]>>>17)|(w[j-2]<<15))^((w[j-2]>>>19)|(w[j-2]<<13))^(w[j-2]>>>10);w[j]=(w[j-16]+s0+w[j-7]+s1)|0}
var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
for(var r=0;r<64;r++){var S1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7)),ch=(e&f)^(~e&g),t1=(h+S1+ch+K[r]+w[r])|0,S0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10)),maj=(a&b)^(a&c)^(b&c),t2=(S0+maj)|0;h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0}
H[0]=(H[0]+a)|0;H[1]=(H[1]+b)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0}
var out="";for(var k=0;k<8;k++)out+=(H[k]>>>0).toString(16).padStart(8,"0");return out}
function fpFromHex(pk){if(typeof pk!=="string"||!/^[0-9a-fA-F]{64}$/.test(pk))return"";var b=new Uint8Array(32);for(var i=0;i<32;i++)b[i]=parseInt(pk.slice(i*2,i*2+2),16);var h=sha256Hex(b).slice(0,16);return"ed25519:"+h.slice(0,4)+"·"+h.slice(4,8)+"·"+h.slice(8,12)+"·"+h.slice(12,16)}
function extractInviteCode(raw){if(!raw)return"";var s=String(raw).trim();if(s.charAt(0)==="#")s=s.slice(1);try{if(s.indexOf("%")!==-1)s=decodeURIComponent(s)}catch(e){}var m=/mshare1:[A-Za-z0-9_-]+/.exec(s);return m&&INVITE_RE.test(m[0])?m[0]:""}
function decodeInvite(code){
if(!INVITE_RE.test(code))return null;
var b64=code.slice(8).replace(/-/g,"+").replace(/_/g,"/");while(b64.length%4)b64+="=";
var bin=atob(b64),bytes=new Uint8Array(bin.length);for(var i=0;i<bin.length;i++)bytes[i]=bin.charCodeAt(i);
var txt=typeof TextDecoder!=="undefined"?new TextDecoder("utf-8").decode(bytes):decodeURIComponent(escape(bin));
var p=JSON.parse(txt);if(!p||p.v!==1||!p.h||!p.pk||!p.m||!p.s||!p.exp)return null;
var ep=p.ep&&typeof p.ep==="object"?p.ep:null,hint="";
if(p.m==="self-relay"&&ep&&ep.relayAddr)hint=String(ep.relayAddr);
else if(p.m==="direct"&&ep&&ep.directHost)hint=String(ep.directHost)+":"+(Number(ep.directPort)||3497);
else if(p.m==="p2p"&&ep&&ep.irohEndpointId)hint="Iroh "+String(ep.irohEndpointId).slice(0,12)+"…";
return{hostName:String(p.h),hostFp:fpFromHex(String(p.pk)),mode:String(p.m),expiresAt:Number(p.exp)||0,endpointHint:hint}}
function makeBootstrapCmd(os){
var vc=state.code&&INVITE_RE.test(state.code)?state.code:"";
var hu="http://127.0.0.1:"+state.port+"/api/health";
var u=vc?"http://127.0.0.1:"+state.port+"/#invite="+encodeURIComponent(vc):"http://127.0.0.1:"+state.port+"/";
if(os==="windows"){return"& { $m=(Get-Command magpie -EA 0 | Select-Object -ExpandProperty Source); if(-not $m){ $c=\\"$env:LOCALAPPDATA\\\\Programs\\\\magpie\\\\magpie.exe\\"; if(Test-Path $c){ $m=$c } }; if(-not $m){ Write-Host '未检测到 Magpie，请先下载安装：https://usemagpie.ai （国内免梯子请见页面手动步骤）'; return }; if(((& $m plugin list --json 2>$null) -join '') -notmatch 'simple-share'){ & $m plugin registry '"+state.reg+"'; & $m plugin add '"+state.pkg+"' }; try { $null=Invoke-RestMethod '"+hu+"' -TimeoutSec 1 } catch { Start-Process -FilePath $m; Start-Sleep -Seconds 2 }; Start-Process '"+u+"' }"}
return"M=$(command -v magpie 2>/dev/null || true); for p in \\"$HOME/.local/bin/magpie\\" /opt/homebrew/bin/magpie /usr/local/bin/magpie /Applications/magpie.app/Contents/MacOS/magpie /Applications/Magpie.app/Contents/MacOS/magpie; do [ -z \\"$M\\" ] && [ -x \\"$p\\" ] && M=\\"$p\\"; done; if [ -z \\"$M\\" ]; then printf '%s\\\\n' '未检测到 Magpie，请先下载安装：https://usemagpie.ai （国内免梯子请见页面手动步骤）'; else if ! \\"$M\\" plugin list --json 2>/dev/null | grep -q 'simple-share'; then \\"$M\\" plugin registry '"+state.reg+"' && \\"$M\\" plugin add '"+state.pkg+"'; fi; if ! curl -fsS '"+hu+"' >/dev/null 2>&1; then (\\"$M\\" serve >/dev/null 2>&1 &); sleep 2; fi; U='"+u+"'; (command -v open >/dev/null 2>&1 && open \\"$U\\") || (command -v xdg-open >/dev/null 2>&1 && xdg-open \\"$U\\") || printf '请在浏览器打开: %s\\\\n' \\"$U\\"; fi"}
function renderCountdown(){
var el=$("card-countdown");if(!el)return;
if(!state.expiresAt){el.textContent="待解析";el.classList.remove("is-expired");return}
var left=Math.floor((state.expiresAt-Date.now())/1000);
if(left<=0){el.textContent="已过期 · 请联系对方重新生成";el.classList.add("is-expired");return}
el.classList.remove("is-expired");
var h=Math.floor(left/3600),m=Math.floor((left%3600)/60),s=left%60;
el.textContent=h>0?(h+" 小时 "+String(m).padStart(2,"0")+" 分 "+String(s).padStart(2,"0")+" 秒后过期"):(String(m).padStart(2,"0")+":"+String(s).padStart(2,"0")+" 后过期")}
function renderOs(){
var tabs=document.querySelectorAll(".os-tab");
for(var i=0;i<tabs.length;i++){var on=tabs[i].getAttribute("data-os")===state.os;tabs[i].classList.toggle("is-active",on);tabs[i].setAttribute("aria-selected",on?"true":"false")}
$("bootstrap-cmd-text").textContent=makeBootstrapCmd(state.os);
var tip=$("os-tip");
if(state.os==="windows")tip.textContent="在 Windows 按 Win+X 打开「终端 / PowerShell」粘贴回车即可；命令仅在本机运行，邀请码不会发往任何外部服务器。";
else if(state.os==="macos")tip.textContent="在 macOS 打开「终端（Terminal）」粘贴回车即可；全程使用国内镜像，邀请码仅传给本机 127.0.0.1。";
else tip.textContent="在 Linux 终端粘贴回车即可；如为无桌面环境，将自动打印本机访问地址。"}
function renderView(){
$("card-host-title").textContent=state.hostName?(state.hostName+" 邀请你共用模型额度"):"等待解析分享邀请";
$("card-mode-badge").textContent=MODE_LABELS[state.mode]||(state.mode?("通道："+state.mode):"等待解析通道");
$("card-host-fp").textContent=state.hostFp||"待解析";
var ep=$("endpoint-item");if(state.endpointHint){$("card-endpoint").textContent=state.endpointHint;ep.hidden=false}else{ep.hidden=true}
$("raw-code-input").value=state.code||"";$("btn-copy-code").disabled=!state.code;
var ob=$("btn-open-local");
if(state.code){ob.setAttribute("href","http://127.0.0.1:"+state.port+"/#invite="+encodeURIComponent(state.code));ob.removeAttribute("aria-disabled");$("manual-paste-section").hidden=true}
else{ob.setAttribute("href","http://127.0.0.1:"+state.port+"/");ob.setAttribute("aria-disabled","true");$("manual-paste-section").hidden=false}
renderCountdown();renderOs()}
function applyRawCode(raw){
var code=extractInviteCode(raw);
if(!code){$("error-text").textContent="未识别到合法的 mshare1:... 邀请码，请检查是否完整复制。";$("error-banner").hidden=false;return}
var meta=null;try{meta=decodeInvite(code)}catch(e){}
if(!meta){$("error-text").textContent="邀请码内容解析失败或版本不兼容，请联系分享方重新生成。";$("error-banner").hidden=false;return}
$("error-banner").hidden=true;state.code=code;state.hostName=meta.hostName;state.hostFp=meta.hostFp;state.mode=meta.mode;state.expiresAt=meta.expiresAt;state.endpointHint=meta.endpointHint;renderView()}
var ua=navigator.userAgent||"";if(/MicroMessenger/i.test(ua))$("wechat-banner").hidden=false;
var plat=(navigator.platform||ua||"").toLowerCase();
if(/mac|darwin/.test(plat))state.os="macos";else if(/linux|x11/.test(plat)&&!/android/.test(plat))state.os="linux";else state.os="windows";
if(!state.code&&location.hash){var hc=extractInviteCode(location.hash);if(hc)applyRawCode(hc)}
window.addEventListener("hashchange",function(){if(cfg.staticMode&&location.hash){var hc2=extractInviteCode(location.hash);if(hc2)applyRawCode(hc2)}});
$("btn-copy-code").addEventListener("click",function(){copyText(state.code)});
$("btn-copy-cmd").addEventListener("click",function(){copyText($("bootstrap-cmd-text").textContent)});
$("btn-manual-parse").addEventListener("click",function(){applyRawCode($("manual-code-input").value)});
var osTabs=document.querySelectorAll(".os-tab");
for(var i=0;i<osTabs.length;i++){osTabs[i].addEventListener("click",function(ev){state.os=ev.currentTarget.getAttribute("data-os")||"windows";renderOs()})}
$("btn-theme").addEventListener("click",function(){var cur=document.documentElement.getAttribute("data-theme");var dark=cur?cur==="dark":(window.matchMedia&&window.matchMedia("(prefers-color-scheme: dark)").matches);document.documentElement.setAttribute("data-theme",dark?"light":"dark")});
renderView();setInterval(renderCountdown,1000);
})();
</script>
</body>
</html>
`;
}

