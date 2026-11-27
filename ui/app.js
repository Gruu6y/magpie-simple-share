import { applyInitialTheme, followHostTheme } from "./host-theme.js";

const TOKEN_HEADER = "x-simple-share-token";
const POLL_INTERVAL_MS = 2500;

const MODE_META = {
  p2p: {
    short: "模式 1 · P2P",
    full: "模式 1 · Iroh P2P 打洞 + 盲中转兜底",
  },
  "self-relay": {
    short: "模式 2 · 自建中转",
    full: "模式 2 · 自建极简盲中转（TLS 1.3 mTLS）",
  },
  direct: {
    short: "模式 3 · 直连",
    full: "模式 3 · 公网 IPv6/IPv4 直连（TLS 1.3 mTLS）",
  },
};

const PERIOD_LABELS = { day: "每日", week: "每周", month: "每月" };
const GITHUB_ISSUES_NEW_URL = "https://github.com/Gruu6y/magpie-simple-share/issues/new";
const ISSUE_TYPES = {
  bug: { label: "Bug / 故障反馈", prefix: "[Bug] ", ghLabel: "bug" },
  network: { label: "连接 / 配对问题", prefix: "[连接问题] ", ghLabel: "bug" },
  enhancement: { label: "功能建议", prefix: "[建议] ", ghLabel: "enhancement" },
};
const MAX_ISSUE_URL_LEN = 1900;
const ISSUE_TRUNCATED_NOTE = "\n\n(内容较长已截断，请粘贴已复制的完整报告)";

const DEFAULT_SECURITY_CHECKS = [
  { label: "双向公钥钉死（TLS 1.3 mTLS / QUIC）", ok: true, detail: "不信任任何第三方 CA；未批准的公钥在加密握手层直接被拒绝，0 字节触达应用层。" },
  { label: "零虚拟网卡（No TUN）", ok: true, detail: "绝不把对方接入宿主局域网，不触碰系统路由表，与本机代理工具和平共处。" },
  { label: "gateway-key 永不出宿主", ok: true, detail: "接收端不保存宿主任何真实密钥；宿主验明对端公钥后仅在本机回环注入受限 key。" },
  { label: "127.0.0.1 Fail-Closed 验活", ok: true, detail: "每次转发前 1ms 校验 /v1/magpie/limit，防止手工删 key 后退化为无限制权限，无需开放 0.0.0.0。" },
  { label: "严格路径白名单 + 隐私边界", ok: true, detail: "仅放行模型推理与 /v1/models；封死 admin/native/memory/mcp，日志绝不记录提示词正文。" },
  { label: "撤销即时断流 + 严禁偷偷回落", ok: true, detail: "撤销成员立刻掐断进行中的流式连接；选择模式 2/3 时绝不偷偷回落第三方公共中转。" },
];

// ==================== Theme & Token Boot ====================

applyInitialTheme();
followHostTheme();

const token = document.querySelector('meta[name="simple-share-token"]')?.content || "";
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

// One-time reload guard using URL param (zero web storage APIs).
let reloadAttempted = false;
try {
  const url = new URL(location.href);
  if (url.searchParams.has("_ss_reload")) {
    reloadAttempted = true;
    url.searchParams.delete("_ss_reload");
    history.replaceState(null, "", url.href);
  }
} catch { /* ignore */ }

function reloadOnceOnTokenMismatch() {
  if (reloadAttempted) return false;
  reloadAttempted = true;
  try {
    const url = new URL(location.href);
    url.searchParams.set("_ss_reload", "1");
    location.replace(url.href);
    return true;
  } catch {
    return false;
  }
}

// ==================== App Local State (In-Memory Only) ====================

let serverState = null;
const uiState = {
  activeTab: "owned",
  range: "7d",
  expandedMemberId: null,
  viewedMode: null,
  dirtyInputs: new Set(),
  activeInvite: null, // { id, code, mode, expiresAt, ttlSec, shareUrl, cardFilename }
  inviteTtlSec: 300,
  inviteQrOpen: false,
  lastExportedCardHtml: "",
  lastExportedCardFilename: "",
  exportingInviteCard: false,
  handlingInviteHash: false,
  parsedInvite: null, // { code, h, fp, m, id, ep, expiresAt }
  currentApproveId: null,
  currentEditMemberId: null,
  pendingConfirmAction: null,
  streamLogs: new Map(), // shareId -> { loading, html }
  selectedTestModels: new Map(), // shareId -> modelId
  irohInstalling: false,
  inFlightMutations: 0,
  serviceError: "",
  issueType: "bug",
};

let inviteTimer = null;
let pollTimer = null;

// ==================== Pure Helpers ====================

function escHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function fmtTokens(n) {
  const num = Number(n) || 0;
  if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(2)}M`;
  if (num >= 1_000) return `${(num / 1_000).toFixed(1)}k`;
  return String(Math.round(num));
}

function fmtTime(val, emptyFallback = "刚刚") {
  if (val === null || val === undefined || val === "") return emptyFallback;
  const ms = typeof val === "number" ? val : Date.parse(String(val));
  if (!Number.isFinite(ms)) return String(val);
  const diffSec = Math.floor((Date.now() - ms) / 1000);
  if (diffSec < 0) {
    const absMin = Math.ceil(Math.abs(diffSec) / 60);
    return absMin <= 60 ? `${absMin} 分钟后` : new Date(ms).toLocaleString("zh-CN", { hour12: false });
  }
  if (diffSec < 45) return "刚刚";
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)} 分钟前`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)} 小时前`;
  const d = new Date(ms);
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

function defaultResetText(period) {
  if (period === "week") return "每周一 00:00 重置";
  if (period === "month") return "每月 1 日 00:00 重置";
  return "每日 00:00 重置";
}

function toast(msg) {
  const stack = $("#toast-stack");
  if (!stack) return;
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = String(msg ?? "");
  stack.appendChild(el);
  setTimeout(() => el.remove(), 2800);
}

async function copyText(text) {
  const value = String(text ?? "");
  if (!value) return false;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return true;
    }
  } catch { /* fallback below */ }
  try {
    const ta = document.createElement("textarea");
    ta.value = value;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  } catch {
    return false;
  }
}

function parseRelayPort(addr) {
  const raw = String(addr || "").trim();
  const m = raw.match(/:(\d{1,5})(?:\/|$)/);
  const p = m ? Number(m[1]) : 3499;
  return Number.isInteger(p) && p > 0 && p <= 65535 ? p : 3499;
}

function buildDockerCommand(addr, tokenStr) {
  const port = parseRelayPort(addr);
  const tok = String(tokenStr || "").trim();
  const envArg = tok ? ` -e RELAY_TOKEN=${tok}` : "";
  return `docker run -d --restart=always -p ${port}:${port} -e PORT=${port}${envArg} ghcr.io/gruu6y/magpie-simple-share-relay:latest`;
}

// ==================== Standard Compact SVG QR Generator (ISO 18004, Byte Mode, EC Level L, V1-V20) ====================

const QR_ALIGN_POS = [
  [], [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
  [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50], [6, 30, 54], [6, 32, 58], [6, 34, 62],
  [6, 26, 46, 66], [6, 26, 48, 70], [6, 26, 50, 74], [6, 30, 54, 78], [6, 30, 56, 82], [6, 30, 58, 86], [6, 34, 62, 90],
];

// [totalCodewords, ecPerBlock, g1Blocks, g1Data, g2Blocks, g2Data] for EC Level L (V1..V20)
const QR_LEVEL_L = [
  null,
  [26, 7, 1, 19, 0, 0],
  [44, 10, 1, 34, 0, 0],
  [70, 15, 1, 55, 0, 0],
  [100, 20, 1, 80, 0, 0],
  [134, 26, 1, 108, 0, 0],
  [172, 18, 2, 68, 0, 0],
  [196, 20, 2, 78, 0, 0],
  [242, 24, 2, 97, 0, 0],
  [292, 30, 2, 116, 0, 0],
  [346, 18, 2, 68, 2, 69],
  [404, 20, 4, 81, 0, 0],
  [466, 24, 2, 92, 2, 93],
  [532, 26, 4, 107, 0, 0],
  [581, 30, 3, 115, 1, 116],
  [655, 22, 5, 87, 1, 88],
  [733, 24, 5, 98, 1, 99],
  [815, 28, 1, 107, 5, 108],
  [901, 30, 5, 120, 1, 121],
  [991, 28, 3, 113, 4, 114],
  [1085, 28, 3, 107, 5, 108],
];

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
})();

function gfMul(a, b) {
  return a === 0 || b === 0 ? 0 : GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function rsGeneratorPoly(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0);
    const factor = GF_EXP[i];
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], factor);
    }
    poly = next;
  }
  return poly;
}

function rsComputeEcc(data, ecCount) {
  const gen = rsGeneratorPoly(ecCount);
  const rem = new Uint8Array(ecCount);
  for (let i = 0; i < data.length; i++) {
    const factor = data[i] ^ rem[0];
    rem.copyWithin(0, 1);
    rem[ecCount - 1] = 0;
    if (factor !== 0) {
      for (let j = 0; j < ecCount; j++) {
        rem[j] ^= gfMul(gen[j + 1], factor);
      }
    }
  }
  return rem;
}

function bchEncode(val, genPoly, dataShift) {
  let rem = val << dataShift;
  const genWidth = Math.floor(Math.log2(genPoly)) + 1;
  for (let i = dataShift + 5; i >= genWidth - 1; i--) {
    if (rem & (1 << i)) rem ^= genPoly << (i - (genWidth - 1));
  }
  return (val << dataShift) | rem;
}

function createQrMatrix(text) {
  const utf8 = new TextEncoder().encode(text);
  let ver = 1;
  for (; ver <= 20; ver++) {
    const [, , g1b, g1d, g2b, g2d] = QR_LEVEL_L[ver];
    const dataCap = g1b * g1d + g2b * g2d;
    const headerBits = 4 + (ver <= 9 ? 8 : 16);
    if (Math.ceil((headerBits + utf8.length * 8) / 8) <= dataCap) break;
  }
  if (ver > 20) return null;

  const [totalCw, ecPerBlk, g1b, g1d, g2b, g2d] = QR_LEVEL_L[ver];
  const dataCap = g1b * g1d + g2b * g2d;

  // Build bit stream: Byte mode (0100), length, payload, terminator, pad bytes
  const bits = [];
  const pushBits = (val, len) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
  };
  pushBits(0b0100, 4);
  pushBits(utf8.length, ver <= 9 ? 8 : 16);
  for (const b of utf8) pushBits(b, 8);
  const maxBits = dataCap * 8;
  pushBits(0, Math.min(4, maxBits - bits.length));
  while (bits.length % 8 !== 0) bits.push(0);
  const padBytes = [0xec, 0x11];
  for (let p = 0; bits.length < maxBits; p++) pushBits(padBytes[p & 1], 8);

  const dataBytes = new Uint8Array(dataCap);
  for (let i = 0; i < dataCap; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b];
    dataBytes[i] = byte;
  }

  // Split blocks & interleave data + EC codewords
  const dataBlocks = [];
  const ecBlocks = [];
  let offset = 0;
  for (let i = 0; i < g1b; i++) {
    const blk = dataBytes.subarray(offset, offset + g1d);
    offset += g1d;
    dataBlocks.push(blk);
    ecBlocks.push(rsComputeEcc(blk, ecPerBlk));
  }
  for (let i = 0; i < g2b; i++) {
    const blk = dataBytes.subarray(offset, offset + g2d);
    offset += g2d;
    dataBlocks.push(blk);
    ecBlocks.push(rsComputeEcc(blk, ecPerBlk));
  }

  const finalCodewords = [];
  const maxDataLen = Math.max(g1d, g2d);
  for (let col = 0; col < maxDataLen; col++) {
    for (const blk of dataBlocks) if (col < blk.length) finalCodewords.push(blk[col]);
  }
  for (let col = 0; col < ecPerBlk; col++) {
    for (const ec of ecBlocks) finalCodewords.push(ec[col]);
  }

  const size = ver * 4 + 17;
  const grid = Array.from({ length: size }, () => new Uint8Array(size));
  const isFn = Array.from({ length: size }, () => new Uint8Array(size));
  const setFn = (x, y, dark) => {
    if (x < 0 || y < 0 || x >= size || y >= size) return;
    grid[y][x] = dark ? 1 : 0;
    isFn[y][x] = 1;
  };

  // Finder patterns + separators
  const drawFinder = (cx, cy) => {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx;
        const y = cy + dy;
        if (x < 0 || y < 0 || x >= size || y >= size) continue;
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        setFn(x, y, dist !== 4 && (dist === 3 || dist <= 1));
      }
    }
  };
  drawFinder(3, 3);
  drawFinder(size - 4, 3);
  drawFinder(3, size - 4);

  // Alignment patterns
  const centers = QR_ALIGN_POS[ver];
  for (const cy of centers) {
    for (const cx of centers) {
      if (isFn[cy][cx]) continue;
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) {
          const dist = Math.max(Math.abs(dx), Math.abs(dy));
          setFn(cx + dx, cy + dy, dist === 2 || dist === 0);
        }
      }
    }
  }

  // Timing patterns
  for (let i = 8; i < size - 8; i++) {
    if (!isFn[6][i]) setFn(i, 6, i % 2 === 0);
    if (!isFn[i][6]) setFn(6, i, i % 2 === 0);
  }

  // Dark module & reserve format info
  setFn(8, size - 8, true);
  for (let i = 0; i < 9; i++) {
    if (i !== 6) {
      setFn(8, i, false);
      setFn(i, 8, false);
    }
  }
  for (let i = 0; i < 8; i++) {
    setFn(size - 1 - i, 8, false);
    if (i < 7) setFn(8, size - 1 - i, false);
  }

  // Reserve & write Version info for V >= 7
  if (ver >= 7) {
    const vBits = bchEncode(ver, 0x1f25, 12);
    for (let i = 0; i < 18; i++) {
      const bit = Boolean((vBits >>> i) & 1);
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      setFn(a, b, bit);
      setFn(b, a, bit);
    }
  }

  // Place data bits in zig-zag
  let bitIdx = 0;
  const totalBits = totalCw * 8;
  let dir = -1;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let step = 0; step < size; step++) {
      const y = dir === -1 ? size - 1 - step : step;
      for (let colOff = 0; colOff < 2; colOff++) {
        const x = right - colOff;
        if (isFn[y][x]) continue;
        let bit = 0;
        if (bitIdx < totalBits) {
          bit = (finalCodewords[bitIdx >>> 3] >>> (7 - (bitIdx & 7))) & 1;
          bitIdx++;
        }
        grid[y][x] = bit;
      }
    }
    dir = -dir;
  }

  // Choose mask pattern (0..7) minimizing simple penalty
  const maskPreds = [
    (x, y) => (x + y) % 2 === 0,
    (_x, y) => y % 2 === 0,
    (x) => x % 3 === 0,
    (x, y) => (x + y) % 3 === 0,
    (x, y) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0,
    (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
    (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
    (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
  ];

  const writeFormat = (mat, maskId) => {
    const fmt = bchEncode((0b01 << 3) | maskId, 0x537, 10) ^ 0x5412;
    for (let i = 0; i <= 5; i++) mat[8][i] = (fmt >>> (14 - i)) & 1;
    mat[8][7] = (fmt >>> 8) & 1;
    mat[8][8] = (fmt >>> 7) & 1;
    mat[7][8] = (fmt >>> 6) & 1;
    for (let i = 0; i <= 5; i++) mat[5 - i][8] = (fmt >>> i) & 1;

    for (let i = 0; i <= 6; i++) mat[size - 1 - i][8] = (fmt >>> (14 - i)) & 1;
    for (let i = 0; i <= 7; i++) mat[8][size - 1 - i] = (fmt >>> i) & 1;
  };

  let bestMask = 0;
  let bestScore = Infinity;
  let bestMat = null;

  for (let m = 0; m < 8; m++) {
    const pred = maskPreds[m];
    const mat = grid.map((row, y) =>
      row.map((val, x) => (isFn[y][x] ? val : val ^ (pred(x, y) ? 1 : 0)))
    );
    writeFormat(mat, m);

    // Penalty N1 (runs) + N3 (finder-like) + N4 (balance)
    let score = 0;
    let dark = 0;
    for (let y = 0; y < size; y++) {
      let runC = mat[y][0];
      let runL = 1;
      for (let x = 0; x < size; x++) {
        dark += mat[y][x];
        if (x > 0) {
          if (mat[y][x] === runC) runL++;
          else {
            if (runL >= 5) score += 3 + (runL - 5);
            runC = mat[y][x];
            runL = 1;
          }
        }
      }
      if (runL >= 5) score += 3 + (runL - 5);
    }
    for (let x = 0; x < size; x++) {
      let runC = mat[0][x];
      let runL = 1;
      for (let y = 1; y < size; y++) {
        if (mat[y][x] === runC) runL++;
        else {
          if (runL >= 5) score += 3 + (runL - 5);
          runC = mat[y][x];
          runL = 1;
        }
      }
      if (runL >= 5) score += 3 + (runL - 5);
    }
    const pct = (dark * 100) / (size * size);
    score += Math.floor(Math.abs(pct - 50) / 5) * 10;

    if (score < bestScore) {
      bestScore = score;
      bestMask = m;
      bestMat = mat;
    }
  }

  return { size, matrix: bestMat, version: ver, mask: bestMask };
}

function renderQrSvg(svgEl, text) {
  if (!svgEl) return;
  const qr = createQrMatrix(text);
  if (!qr) {
    svgEl.setAttribute("viewBox", "0 0 21 21");
    svgEl.innerHTML = "";
    return;
  }
  const { size, matrix } = qr;
  const pad = 2;
  svgEl.setAttribute("viewBox", `${-pad} ${-pad} ${size + pad * 2} ${size + pad * 2}`);
  // Build compact horizontal run paths for crisp rendering
  const parts = [];
  for (let y = 0; y < size; y++) {
    let x = 0;
    while (x < size) {
      if (matrix[y][x]) {
        const start = x;
        while (x < size && matrix[y][x]) x++;
        parts.push(`M${start},${y}h${x - start}v1h-${x - start}z`);
      } else {
        x++;
      }
    }
  }
  svgEl.innerHTML = `<rect x="${-pad}" y="${-pad}" width="${size + pad * 2}" height="${size + pad * 2}" fill="#ffffff"/><path d="${parts.join("")}" fill="#17150f"/>`;
}

// ==================== API Client ====================

async function api(path, { method = "GET", body, isMutation = false } = {}) {
  if (isMutation) uiState.inFlightMutations++;
  try {
    const reqPath = path.startsWith("/") ? path.slice(1) : path;
    const headers = { [TOKEN_HEADER]: token };
    if (body !== undefined) headers["content-type"] = "application/json";

    const res = await fetch(reqPath, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
    });

    let data = null;
    try {
      data = await res.json();
    } catch { /* non-JSON body */ }

    if (!res.ok) {
      if ((res.status === 401 || res.status === 403) && data?.reload && reloadOnceOnTokenMismatch()) {
        return new Promise(() => {});
      }
      const errMsg = data?.message || data?.error || `请求失败（HTTP ${res.status}）`;
      const err = new Error(errMsg);
      err.code = data?.error || `http_${res.status}`;
      err.status = res.status;
      throw err;
    }
    if (uiState.serviceError) uiState.serviceError = "";
    return data;
  } catch (err) {
    if (err instanceof TypeError || /fetch|network/i.test(String(err?.message || ""))) {
      uiState.serviceError = "无法连接到本地简单分享服务（127.0.0.1），请确认插件服务仍在运行后点击重试。";
    }
    throw err;
  } finally {
    if (isMutation) uiState.inFlightMutations = Math.max(0, uiState.inFlightMutations - 1);
  }
}

async function refreshState({ silent = false } = {}) {
  try {
    const next = await api("/api/state");
    serverState = next;
    if (!uiState.viewedMode) uiState.viewedMode = next.mode || "p2p";
    if (!uiState.expandedMemberId && Array.isArray(next.members) && next.members.length > 0) {
      uiState.expandedMemberId = next.members[0].id;
    }
    renderAll();
    return next;
  } catch (err) {
    if (!silent) renderBanner();
    return null;
  }
}

// ==================== Smart Polling ====================

function hasInteractionConflict() {
  if (document.hidden) return true;
  if (uiState.inFlightMutations > 0) return true;
  if (document.querySelector("dialog[open]")) return true;
  const activeTag = document.activeElement?.tagName;
  if (activeTag === "INPUT" || activeTag === "TEXTAREA" || activeTag === "SELECT") return true;
  return false;
}

function scheduleNextPoll() {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = setTimeout(async () => {
    if (!hasInteractionConflict()) {
      await refreshState({ silent: true });
    }
    scheduleNextPoll();
  }, POLL_INTERVAL_MS);
}

document.addEventListener("visibilitychange", () => {
  if (!document.hidden && !hasInteractionConflict()) {
    refreshState({ silent: true });
  }
});

// ==================== Rendering ====================

function switchTab(tabName) {
  uiState.activeTab = tabName;
  $$(".tab").forEach((t) => {
    const active = t.dataset.tab === tabName;
    t.classList.toggle("is-active", active);
    t.setAttribute("aria-selected", String(active));
  });
  $("#panel-owned").hidden = tabName !== "owned";
  $("#panel-received").hidden = tabName !== "received";
  $("#panel-network").hidden = tabName !== "network";
}

function renderModelPicker(containerEl, selectedIds, warnEl, countEl, availableModels) {
  const modelsList = Array.isArray(availableModels) ? [...availableModels] : [];
  const knownIds = new Set(modelsList.map((m) => m.id));
  for (const id of selectedIds || []) {
    if (!knownIds.has(id)) {
      modelsList.push({ id, label: id, provider: "已保存模型", kind: "api" });
    }
  }

  const apiModels = modelsList.filter((m) => m.kind !== "sub");
  const subModels = modelsList.filter((m) => m.kind === "sub");
  const selectedSet = new Set(selectedIds || []);

  const renderGroup = (title, items) => {
    if (items.length === 0) return "";
    return `
      <div class="model-group-label" style="margin-top:8px;"><span>${escHtml(title)}</span></div>
      <div class="model-check-grid">
        ${items.map((m) => `
          <label class="model-check">
            <input type="checkbox" value="${escHtml(m.id)}" ${selectedSet.has(m.id) ? "checked" : ""} />
            <span>
              <span class="mono" style="display:block; font-size:12px;">${escHtml(m.label || m.id)}</span>
              <span style="font-size:11px; color:var(--muted);">${escHtml(m.provider || "")}</span>
            </span>
          </label>
        `).join("")}
      </div>
    `;
  };

  if (modelsList.length === 0) {
    containerEl.innerHTML = `<div class="tos-warn">未从本机 magpie 读取到可用模型，请确认 magpie 正在运行且已配置至少一个供应商。</div>`;
    if (countEl) countEl.textContent = "0";
    if (warnEl) warnEl.hidden = true;
    return;
  }

  containerEl.innerHTML =
    renderGroup("API 供应商与路由组（条款风险低）", apiModels) +
    renderGroup("个人订阅账号（注意服务条款与并发风控）", subModels);

  const syncWarn = () => {
    const checked = [...containerEl.querySelectorAll("input:checked")].map((i) => i.value);
    if (countEl) countEl.textContent = String(checked.length);
    const hasSub = checked.some((id) => modelsList.find((m) => m.id === id)?.kind === "sub");
    if (warnEl) warnEl.hidden = !hasSub;
  };
  containerEl.querySelectorAll("input").forEach((inp) => inp.addEventListener("change", syncWarn));
  syncWarn();
}

function renderBanner() {
  const banner = $("#service-banner");
  const textEl = $("#service-banner-text");
  const gwPill = $("#gateway-status-pill");
  const s = serverState;

  if (uiState.serviceError) {
    banner.className = "service-banner";
    textEl.textContent = uiState.serviceError;
    banner.hidden = false;
  } else if (s && s.magpieGateway && !s.magpieGateway.ok) {
    banner.className = "service-banner is-warn";
    textEl.textContent = "未检测到本机运行中的 magpie 网关（默认 127.0.0.1:3425），模型列表同步与转发功能将暂不可用。";
    banner.hidden = false;
  } else {
    banner.hidden = true;
  }

  if (s?.magpieGateway) {
    gwPill.hidden = false;
    if (s.magpieGateway.ok) {
      gwPill.className = "badge ok";
      gwPill.textContent = `magpie ${s.magpieGateway.version ? `v${s.magpieGateway.version}` : "已连接"}`;
    } else {
      gwPill.className = "badge warn";
      gwPill.textContent = "magpie 未连接";
    }
  }
}

function syncInputIfNotDirty(id, value) {
  const el = $(`#${id}`);
  if (!el) return;
  if (document.activeElement === el || uiState.dirtyInputs.has(id)) return;
  el.value = value ?? "";
}

function renderAll() {
  renderBanner();
  const s = serverState;
  const footerVer = $("#footer-version");
  if (footerVer) footerVer.textContent = s?.version ? `v${s.version}` : "";
  if (!s) return;

  const mode = s.mode || "p2p";
  const members = Array.isArray(s.members) ? s.members : [];
  const pending = Array.isArray(s.pending) ? s.pending : [];
  const received = Array.isArray(s.received) ? s.received : [];
  const usageByMember = s.usageByMember || {};

  // Tab badges
  $("#badge-owned").textContent = String(members.length);
  const pendingBadge = $("#badge-pending");
  pendingBadge.hidden = pending.length === 0;
  pendingBadge.textContent = `${pending.length} 待处理`;
  $("#badge-received").textContent = String(received.length);
  $("#badge-mode").textContent = MODE_META[mode]?.short || mode;

  // Host strip
  const strip = $("#host-strip");
  const tStatus = s.transportStatus || {};
  const hasTransportErr = Boolean(s.sharingEnabled && tStatus.error);
  strip.classList.toggle("is-off", !s.sharingEnabled);
  strip.classList.toggle("is-err", hasTransportErr);

  $("#toggle-sharing").checked = Boolean(s.sharingEnabled);
  $("#host-status-text").textContent = s.sharingEnabled
    ? "本机分享已开启"
    : "本机分享已暂停（已有成员保留，暂不可调用）";

  const tBadge = $("#host-transport-badge");
  if (!s.sharingEnabled) {
    tBadge.className = "badge";
    tBadge.textContent = "已暂停监听";
  } else if (tStatus.error) {
    tBadge.className = "badge danger";
    tBadge.textContent = tStatus.error;
  } else if (tStatus.listening) {
    tBadge.className = "badge ok";
    tBadge.innerHTML = `<span class="dot-live"></span> ${escHtml(tStatus.linkLabel || MODE_META[mode]?.full || mode)}`;
  } else {
    tBadge.className = "badge warn";
    tBadge.textContent = tStatus.linkLabel || "通道准备中…";
  }

  $("#host-name-text").textContent = s.identity?.hostName || "本机";
  const gwUrl = s.magpieGateway?.url || "http://127.0.0.1:3425";
  $("#host-gateway-addr").textContent = gwUrl.replace(/^https?:\/\//, "");
  $("#host-gateway-meta").textContent = s.magpieGateway?.ok
    ? "（不开放局域网 · Fail-Closed 验活）"
    : "（网关未响应）";

  $("#btn-create-invite").disabled = !s.sharingEnabled;
  $("#toggle-vis-limit").checked = Boolean(s.visibility?.limit);
  $("#toggle-vis-quotas").checked = Boolean(s.visibility?.quotas);

  // Pending approvals
  $("#section-pending").hidden = pending.length === 0;
  $("#pending-count-tag").textContent = String(pending.length);
  $("#pending-list").innerHTML = pending.map((p) => `
    <div class="pending-card">
      <div class="pending-info">
        <div class="pending-title">
          <span>${escHtml(p.name)}</span>
          <span class="badge danger">申请使用</span>
          <span class="sas-mini" title="4 位安全配对码">配对码 ${escHtml(p.sas)}</span>
        </div>
        <div class="pending-sub">
          ${escHtml(fmtTime(p.requestedAt))}申请 · 公钥 <code class="mono">${escHtml(p.clientFp)}</code> · 通道 ${escHtml(MODE_META[p.mode]?.short || p.mode)}
        </div>
      </div>
      <div style="display:flex; gap:8px;">
        <button type="button" class="btn primary sm" data-open-approve="${escHtml(p.id)}">核对配对码并处理</button>
      </div>
    </div>
  `).join("");

  // Members list
  $("#members-count-sub").textContent = `共 ${members.length} 位`;
  $$(".range-pill").forEach((el) => el.classList.toggle("is-active", el.dataset.range === uiState.range));

  if (members.length === 0) {
    $("#member-list-wrap").innerHTML = `
      <div class="empty">
        <strong>还没有分享给任何人</strong>
        点击上方「生成分享邀请」发给对方，对方申请、你核对 4 位配对码同意后会出现在这里。
      </div>
    `;
  } else {
    const rangeLabel = uiState.range === "7d" ? "近 7 天" : uiState.range === "month" ? "本月" : "全部";
    $("#member-list-wrap").innerHTML = `
      <div class="member-list">
        ${members.map((m) => {
          const memberUsage = usageByMember[m.id] || m.usage || {};
          const rows = Array.isArray(memberUsage[uiState.range]) ? memberUsage[uiState.range] : [];
          const totalTok = rows.reduce((sum, r) => sum + (Number(r.inputTokens ?? r.input ?? 0) || 0) + (Number(r.outputTokens ?? r.output ?? 0) || 0), 0);
          const totalCost = rows.reduce((sum, r) => sum + (Number(r.costUsd ?? r.cost ?? 0) || 0), 0);
          const limitTokens = Math.max(1, (Number(m.tokenLimitWan) || 0) * 10000);
          const usedTodayTok = Number(m.usedTodayTokens) || 0;
          const pct = Math.min(100, Math.round((usedTodayTok / limitTokens) * 100));
          const barCls = pct >= 90 ? "is-high" : pct >= 70 ? "is-warn" : "";
          const isExpanded = uiState.expandedMemberId === m.id;
          const mModels = Array.isArray(m.models) ? m.models : [];
          const running = Number(m.running) || 0;

          const statusBadge = !s.sharingEnabled
            ? '<span class="badge">宿主已暂停</span>'
            : m.status === "paused"
              ? '<span class="badge warn">已暂停</span>'
              : running > 0
                ? `<span class="badge ok"><span class="dot-live"></span> 正常 · ${escHtml(running)} 个请求进行中</span>`
                : '<span class="badge ok"><span class="dot-live"></span> 正常</span>';

          return `
            <div class="member-row">
              <div class="member-main">
                <div class="member-identity" data-toggle-expand="${escHtml(m.id)}" title="点击展开或收起按模型明细">
                  <div class="member-name-line">
                    <span style="color:var(--faint); font-size:11px;">${isExpanded ? "▾" : "▸"}</span>
                    <span class="member-name">${escHtml(m.name)}</span>
                    ${statusBadge}
                  </div>
                  <div class="member-meta">
                    <span>${escHtml(fmtTime(m.joinedAt || m.joined, "-"))} 加入</span>
                    <span>最近使用：${escHtml(fmtTime(m.lastUsedAt || m.lastUsed, "尚未调用"))}</span>
                    <span>开放 ${escHtml(mModels.length)} 个模型</span>
                  </div>
                </div>
                <div class="member-usage">
                  <strong>${escHtml(fmtTokens(totalTok))} tokens</strong>
                  <span>约 $${escHtml(totalCost.toFixed(2))}（${escHtml(rangeLabel)}）</span>
                </div>
                <div class="member-quota-col">
                  <div>${escHtml(PERIOD_LABELS[m.period] || m.period || "每日")}上限：${escHtml(m.tokenLimitWan ?? "-")}万 / $${escHtml(m.costLimit ?? "-")}</div>
                  <div class="mini-bar"><div class="mini-bar-fill ${escHtml(barCls)}" style="width:${escHtml(pct)}%"></div></div>
                </div>
                <div class="member-actions">
                  <button type="button" class="btn sm" data-edit-member="${escHtml(m.id)}">模型与额度</button>
                  <button type="button" class="btn sm" data-toggle-pause="${escHtml(m.id)}">${m.status === "paused" ? "恢复分享" : "暂停"}</button>
                  <button type="button" class="btn danger sm" data-remove-member="${escHtml(m.id)}">删除</button>
                </div>
              </div>
              ${isExpanded ? `
                <div class="member-detail">
                  <div class="detail-grid">
                    <div>
                      <table class="usage-table">
                        <thead>
                          <tr>
                            <th>模型</th>
                            <th class="num">消息</th>
                            <th class="num">输入</th>
                            <th class="num">输出</th>
                            <th class="num">估算金额</th>
                          </tr>
                        </thead>
                        <tbody>
                          ${rows.length === 0
                            ? '<tr><td colspan="5" style="color:var(--muted); text-align:center; padding:14px;">该时间段暂无调用记录</td></tr>'
                            : rows.map((r) => {
                              const rIn = Number(r.inputTokens ?? r.input ?? 0) || 0;
                              const rOut = Number(r.outputTokens ?? r.output ?? 0) || 0;
                              const rCost = Number(r.costUsd ?? r.cost ?? 0) || 0;
                              const rTurns = Number(r.turns ?? 0) || 0;
                              return `
                                <tr>
                                  <td class="mono">${escHtml(r.model)}</td>
                                  <td class="num">${escHtml(rTurns)}</td>
                                  <td class="num">${escHtml(fmtTokens(rIn))}</td>
                                  <td class="num">${escHtml(fmtTokens(rOut))}</td>
                                  <td class="num">$${escHtml(rCost.toFixed(2))}</td>
                                </tr>
                              `;
                            }).join("")}
                        </tbody>
                      </table>
                    </div>
                    <div class="detail-meta-box">
                      <dl>
                        <div>
                          <dt>设备 Ed25519 公钥指纹</dt>
                          <dd class="mono" style="font-size:11.5px;">${escHtml(m.clientFp)}</dd>
                        </div>
                        <div>
                          <dt>本机受限 magpie gateway-key（不出本机）</dt>
                          <dd class="mono">${escHtml(m.magpieKeyName || "-")} · 并发 ≤ ${escHtml(m.concurrency ?? 2)} · admin/memory/mcp 已关</dd>
                        </div>
                        <div>
                          <dt>开放的模型</dt>
                          <dd class="mono" style="font-size:11.5px;">${mModels.length > 0 ? mModels.map(escHtml).join(", ") : "无"}</dd>
                        </div>
                      </dl>
                    </div>
                  </div>
                </div>
              ` : ""}
            </div>
          `;
        }).join("")}
      </div>
    `;
  }

  // Receiver waiting card
  if (s.receiverPending) {
    const rp = s.receiverPending;
    $("#receiver-waiting-wrap").innerHTML = `
      <div class="wait-card">
        <div style="flex:1; min-width:240px;">
          <div style="font-weight:600; font-size:15px;">正在等待「${escHtml(rp.hostName)}」同意你的分享申请…</div>
          <p style="margin:6px 0 12px; font-size:13px; color:var(--muted);">
            通道：${escHtml(MODE_META[rp.mode]?.short || rp.mode)} · 申请设备名：${escHtml(rp.deviceName)}。对方可能会向你确认右侧这 <strong>4 位配对码</strong>。
          </p>
          <div style="display:flex; gap:8px; flex-wrap:wrap;">
            <button type="button" class="btn sm" data-withdraw-apply="${escHtml(rp.id)}">撤回申请</button>
          </div>
        </div>
        <div style="text-align:center;">
          <div style="font-size:11.5px; color:var(--muted); margin-bottom:5px;">你的 4 位配对码</div>
          <div class="sas-big">${escHtml(rp.sas)}</div>
        </div>
      </div>
    `;
  } else {
    $("#receiver-waiting-wrap").innerHTML = "";
  }

  // Receiver accepted shares
  if (received.length === 0) {
    $("#received-list").innerHTML = `
      <div class="empty">
        <strong>还没有收到他人分享的模型</strong>
        点击右上角「输入分享邀请…」，粘贴对方发来的 <code class="mono">mshare1:</code> 邀请码或完整分享链接即可申请。
      </div>
    `;
  } else {
    const availMap = new Map((s.availableModels || []).map((m) => [m.id, m]));
    $("#received-list").innerHTML = received.map((r) => {
      const rModels = Array.isArray(r.models) ? r.models : [];
      const usedTok = Number(r.usedTokens) || 0;
      const tokLimitWan = Number(r.tokenLimitWan) || 0;
      const usedCost = Number(r.usedCost) || 0;
      const costLimit = Number(r.costLimit) || 0;
      const pct = tokLimitWan > 0 ? Math.min(100, Math.round((usedTok / (tokLimitWan * 10000)) * 100)) : 0;
      const barCls = pct >= 90 ? "is-high" : pct >= 70 ? "is-warn" : "";

      const statusEl = r.status === "active"
        ? `<span class="badge ok"><span class="dot-live"></span> ${escHtml(r.linkStatus || MODE_META[r.mode]?.short || "已连接")}</span>`
        : r.status === "paused"
          ? '<span class="badge warn">分享者已暂停</span>'
          : r.status === "revoked"
            ? '<span class="badge danger">已被分享者撤销</span>'
            : `<span class="badge">${escHtml(r.linkStatus || "对方电脑离线 / 分享已关闭")}</span>`;

      const selectedTestModel = uiState.selectedTestModels.get(r.id) || rModels[0] || "";
      const logEntry = uiState.streamLogs.get(r.id);

      return `
        <div class="received-card">
          <div class="received-head">
            <div>
              <div class="received-title">
                <span>来自「${escHtml(r.hostName)}」的分享</span>
                ${statusEl}
              </div>
              <div class="received-sub">
                宿主公钥 <code class="mono">${escHtml(r.hostFp)}</code> · 自动映射为本机 <code class="mono">remote-magpie (${escHtml(r.providerId)})</code>
              </div>
            </div>
            <div class="received-actions">
              ${rModels.length > 1 ? `
                <select class="test-model-select" data-select-test-model="${escHtml(r.id)}" aria-label="选择测试模型">
                  ${rModels.map((mid) => `<option value="${escHtml(mid)}" ${mid === selectedTestModel ? "selected" : ""}>${escHtml(mid)}</option>`).join("")}
                </select>
              ` : ""}
              <button type="button" class="btn sm" data-test-stream="${escHtml(r.id)}" ${logEntry?.loading ? "disabled" : ""}>
                ${logEntry?.loading ? "测速中…" : "测试连接与流式输出"}
              </button>
              <button type="button" class="btn danger sm" data-leave-share="${escHtml(r.id)}">退出分享</button>
            </div>
          </div>
          <div class="received-body">
            <div class="bridge-note">
              本机任意 Agent（Claude Code / Codex / OpenCode 等）选择 <code class="mono">${escHtml(r.providerId)}/&lt;模型&gt;</code> 即可直接使用。本机桥接监听 <code class="mono">127.0.0.1:${escHtml(r.bridgePort)}</code>，真实 <code class="mono">gateway-key</code> 仅留在对方电脑。
            </div>

            ${(r.limitVisible === false || (!tokLimitWan && !costLimit))
              ? '<div class="budget-box" style="color:var(--muted); font-size:12.5px;">分享者已关闭额度进度展示（或未公开限额明细），不影响模型正常调用。</div>'
              : `
                <div class="budget-box">
                  <div class="budget-top">
                    <strong>我的${escHtml(PERIOD_LABELS[r.period] || r.period || "当前")}额度进度</strong>
                    <span class="mono" style="font-size:12.5px;">${escHtml(fmtTokens(usedTok))} / ${escHtml(tokLimitWan)}万 tokens · 约 $${escHtml(usedCost.toFixed(2))} / $${escHtml(costLimit)}</span>
                  </div>
                  <div class="mini-bar" style="height:7px; margin-top:8px;"><div class="mini-bar-fill ${escHtml(barCls)}" style="width:${escHtml(pct)}%"></div></div>
                  <div style="font-size:12px; color:var(--muted); margin-top:6px; display:flex; justify-content:space-between; flex-wrap:wrap; gap:6px;">
                    <span>${escHtml(r.resetsText || defaultResetText(r.period))}</span>
                    <span>${escHtml(r.quotasText || "分享者未公开上游共享余量（默认隐私保护）")}</span>
                  </div>
                </div>
              `}

            <div>
              <div style="font-size:13px; font-weight:600;">可用的模型（${escHtml(rModels.length)} 个）</div>
              <div class="model-chips">
                ${rModels.length === 0
                  ? '<span class="chip">暂无可用模型</span>'
                  : rModels.map((id) => {
                      const isSub = availMap.get(id)?.kind === "sub";
                      return `<span class="chip ${isSub ? "is-sub" : ""}">${escHtml(id)}</span>`;
                    }).join("")}
              </div>
            </div>

            ${logEntry?.html ? `<div class="stream-console">${logEntry.html}</div>` : ""}
          </div>
        </div>
      `;
    }).join("");
  }

  // Network tab selection & inputs
  const viewed = uiState.viewedMode || mode;
  $$(".mode-card").forEach((card) => {
    const m = card.dataset.mode;
    const sel = m === viewed;
    card.classList.toggle("is-selected", sel);
    const body = $(`#mode-body-${m}`);
    if (body) body.hidden = !sel;
    const draftBadge = $(`#mode-draft-${m}`);
    if (draftBadge) draftBadge.hidden = !(sel && viewed !== mode);
  });

  // Mode 1: Iroh status
  const iroh = s.irohStatus || {};
  const irohBadge = $("#iroh-state-badge");
  const irohStatusEl = $("#iroh-dl-status");
  const irohBtn = $("#btn-install-iroh");
  const irohTrack = $("#iroh-dl-track");
  const irohFill = $("#iroh-dl-fill");

  if (uiState.irohInstalling) {
    irohBadge.className = "badge warn";
    irohBadge.textContent = "下载校验中…";
    irohStatusEl.textContent = "正在从国内镜像 registry.npmmirror.com 下载并校验 sha512…";
    irohBtn.disabled = true;
    irohBtn.textContent = "下载校验中…";
    irohTrack.hidden = false;
    irohFill.classList.add("is-indeterminate");
  } else if (iroh.supported === false) {
    irohBadge.className = "badge warn";
    irohBadge.textContent = "当前架构不支持模式 1";
    irohStatusEl.textContent =
      iroh.unsupportedReason ||
      "当前系统架构暂无 @number0/iroh 原生包；请使用模式 2 自建盲中转或模式 3 公网直连。";
    irohBtn.disabled = true;
    irohBtn.textContent = "当前架构不支持 P2P 组件";
    irohTrack.hidden = true;
    irohFill.classList.remove("is-indeterminate");
  } else if (iroh.installed && iroh.integrityOk) {
    irohBadge.className = "badge ok";
    irohBadge.textContent = "按需组件 · 已就绪";
    irohStatusEl.textContent = `已安装 ${iroh.platformPkg || "@number0/iroh"}@${iroh.version || "1.2.0"} 并通过 sha512 完整性校验。`;
    irohBtn.disabled = false;
    irohBtn.textContent = "重新校验 / 修复组件";
    irohTrack.hidden = true;
    irohFill.classList.remove("is-indeterminate");
  } else if (iroh.installed && !iroh.integrityOk) {
    irohBadge.className = "badge danger";
    irohBadge.textContent = "校验异常";
    irohStatusEl.textContent = `检测到 ${iroh.platformPkg || "@number0/iroh"} 完整性校验未通过，请点击右侧按钮重新下载校验。`;
    irohBtn.disabled = false;
    irohBtn.textContent = "重新下载并校验";
    irohTrack.hidden = true;
    irohFill.classList.remove("is-indeterminate");
  } else {
    irohBadge.className = "badge";
    irohBadge.textContent = "按需组件 · 未下载";
    irohStatusEl.textContent = "尚未下载 @number0/iroh（仅选择模式 1 时需要）。点击按钮从国内镜像下载并强校验 sha512。";
    irohBtn.disabled = false;
    irohBtn.textContent = "下载并校验 P2P 组件";
    irohTrack.hidden = true;
    irohFill.classList.remove("is-indeterminate");
  }

  // Network form values (preserve dirty/focused user edits)
  const net = s.network || {};
  syncInputIfNotDirty("input-custom-iroh-relay", net.irohRelayUrl || "");
  syncInputIfNotDirty("input-relay-addr", net.relayAddr || "");
  syncInputIfNotDirty("input-relay-token", net.relayToken || "");
  syncInputIfNotDirty("input-direct-host", net.directHost || "");
  syncInputIfNotDirty("input-direct-port", String(net.directPort || 3497));
  syncInputIfNotDirty("input-share-base-url", net.shareBaseUrl || "");

  $("#docker-cmd").textContent = buildDockerCommand(
    $("#input-relay-addr").value || net.relayAddr,
    $("#input-relay-token").value || net.relayToken
  );

  // Identity & security checks
  $("#host-pubkey-fp").textContent = s.identity?.fingerprint || "-";
  const irohEpId = s.identity?.irohEndpointId || "";
  $("#iroh-id-row").hidden = !irohEpId;
  if (irohEpId) $("#host-iroh-id").textContent = irohEpId;

  const checks = Array.isArray(s.securityChecks) && s.securityChecks.length > 0
    ? s.securityChecks
    : DEFAULT_SECURITY_CHECKS;
  $("#security-checks-grid").innerHTML = checks.map((c) => {
    const ok = c.ok !== false;
    return `
      <div class="sec-item ${ok ? "" : "is-fail"}">
        <strong>
          <span style="color:${ok ? "var(--green)" : "var(--red)"};">${ok ? "✓" : "✕"}</span>
          <span>${escHtml(c.label)}</span>
        </strong>
        <p>${escHtml(c.detail)}</p>
      </div>
    `;
  }).join("");
}

// ==================== Host Flows ====================

async function handleToggleSharing(checked) {
  if (!serverState) return;
  if (checked && !serverState.tosAcknowledged) {
    $("#toggle-sharing").checked = false;
    $("#dlg-tos").showModal();
    return;
  }
  try {
    await api("/api/host/toggle", {
      method: "POST",
      body: { enabled: checked },
      isMutation: true,
    });
    await refreshState();
    toast(checked ? "本机分享已开启" : "已暂停对外分享（已有成员配置已保留）");
  } catch (err) {
    $("#toggle-sharing").checked = Boolean(serverState.sharingEnabled);
    toast(`切换失败：${err.message}`);
  }
}

async function confirmTosAndEnable() {
  const btn = $("#btn-confirm-tos");
  btn.disabled = true;
  try {
    await api("/api/host/toggle", {
      method: "POST",
      body: { enabled: true, tosAcknowledged: true },
      isMutation: true,
    });
    $("#dlg-tos").close();
    await refreshState();
    toast("已确认条款并开启本机对外分享");
  } catch (err) {
    toast(`开启失败：${err.message}`);
  } finally {
    btn.disabled = false;
  }
}

function openHostNameDialog() {
  $("#input-host-name").value = serverState?.identity?.hostName || "";
  $("#host-name-error").hidden = true;
  $("#dlg-host-name").showModal();
}

async function saveHostName() {
  const hostName = $("#input-host-name").value.trim();
  const errEl = $("#host-name-error");
  if (!hostName) {
    errEl.textContent = "请输入本机分享名称。";
    errEl.hidden = false;
    return;
  }
  const btn = $("#btn-save-host-name");
  btn.disabled = true;
  try {
    await api("/api/host/name", {
      method: "POST",
      body: { hostName },
      isMutation: true,
    });
    $("#dlg-host-name").close();
    await refreshState();
    toast(`已更新本机名称为「${hostName}」`);
  } catch (err) {
    errEl.textContent = err.message;
    errEl.hidden = false;
  } finally {
    btn.disabled = false;
  }
}

function getSelectedInviteTtlSec() {
  const raw = Number($("#invite-ttl-select")?.value);
  if (Number.isInteger(raw) && raw >= 60 && raw <= 86400) return raw;
  return 300;
}

function formatInviteCountdown(seconds) {
  const left = Math.max(0, Math.floor(seconds));
  const hh = Math.floor(left / 3600);
  const mm = String(Math.floor((left % 3600) / 60)).padStart(2, "0");
  const ss = String(left % 60).padStart(2, "0");
  return hh > 0 ? `${String(hh).padStart(2, "0")}:${mm}:${ss}` : `${mm}:${ss}`;
}

function updateInviteCountdown() {
  const inv = uiState.activeInvite;
  if (!inv) return;
  const expMs = typeof inv.expiresAt === "number"
    ? inv.expiresAt
    : (Date.parse(inv.expiresAt) || (Date.now() + (Number(inv.ttlSec) || 300) * 1000));
  const left = Math.max(0, Math.floor((expMs - Date.now()) / 1000));
  $("#invite-countdown").textContent = left > 0 ? `${formatInviteCountdown(left)} 后过期` : "已过期（请重新生成）";
  const exportBtn = $("#btn-export-invite-card");
  if (exportBtn && !uiState.exportingInviteCard) {
    exportBtn.disabled = left === 0;
  }
}

function showInviteInDialog(invite) {
  uiState.activeInvite = invite;
  uiState.lastExportedCardHtml = "";
  uiState.lastExportedCardFilename = "";
  $("#invite-code-input").value = invite.code || "";
  $("#invite-mode-tag").textContent = MODE_META[invite.mode]?.short || invite.mode || "";
  $("#btn-copy-invite").textContent = "复制邀请码";
  $("#btn-copy-invite-link").textContent = "复制链接";
  $("#invite-card-fallback").hidden = true;

  const ttlSelect = $("#invite-ttl-select");
  const effectiveTtl = Number(invite.ttlSec) || uiState.inviteTtlSec || 300;
  if (ttlSelect && [...ttlSelect.options].some((o) => Number(o.value) === effectiveTtl)) {
    ttlSelect.value = String(effectiveTtl);
    uiState.inviteTtlSec = effectiveTtl;
  }
  const presetBtn = $("#btn-ttl-preset-1800");
  if (presetBtn) {
    presetBtn.hidden = Number(ttlSelect?.value || effectiveTtl) === 1800;
  }

  const shareUrl = typeof invite.shareUrl === "string" ? invite.shareUrl.trim() : "";
  const linkRow = $("#invite-link-row");
  const linkInput = $("#invite-link-input");
  const emptyTip = $("#invite-link-empty-tip");
  if (shareUrl) {
    linkInput.value = shareUrl;
    linkRow.hidden = false;
    emptyTip.hidden = true;
  } else {
    linkInput.value = "";
    linkRow.hidden = true;
    emptyTip.hidden = false;
  }

  renderQrSvg($("#invite-qr-svg"), invite.code || "");
  if (inviteTimer) clearInterval(inviteTimer);
  updateInviteCountdown();
  inviteTimer = setInterval(updateInviteCountdown, 1000);
}

async function createAndShowInvite({ replaceOld = false, ttlSec } = {}) {
  const requestedTtl = Number.isInteger(ttlSec) ? ttlSec : getSelectedInviteTtlSec();
  const oldId = uiState.activeInvite?.id;
  if (replaceOld && oldId) {
    try {
      await api(`/api/host/invites/${encodeURIComponent(oldId)}`, {
        method: "DELETE",
        isMutation: true,
      });
    } catch { /* ignore if already expired/consumed */ }
  }
  const inv = await api("/api/host/invites", {
    method: "POST",
    body: { ttlSec: requestedTtl },
    isMutation: true,
  });
  uiState.inviteTtlSec = Number(inv.ttlSec) || requestedTtl;
  showInviteInDialog(inv);
  return inv;
}

async function changeInviteTtl(nextTtl) {
  const ttlSelect = $("#invite-ttl-select");
  const presetBtn = $("#btn-ttl-preset-1800");
  const regenBtn = $("#btn-regen-invite");
  const prevTtl = uiState.inviteTtlSec || 300;
  const targetTtl = Number.isInteger(nextTtl) && nextTtl >= 60 && nextTtl <= 86400 ? nextTtl : 300;

  if (ttlSelect) {
    ttlSelect.value = String(targetTtl);
    ttlSelect.disabled = true;
  }
  if (presetBtn) presetBtn.disabled = true;
  if (regenBtn) regenBtn.disabled = true;
  try {
    await createAndShowInvite({ replaceOld: true, ttlSec: targetTtl });
    const label = targetTtl === 7200 ? "2 小时" : `${Math.round(targetTtl / 60)} 分钟`;
    toast(`已更新有效期为 ${label} 并重新生成邀请，旧邀请已作废`);
  } catch (err) {
    if (ttlSelect) ttlSelect.value = String(prevTtl);
    if (presetBtn) presetBtn.hidden = prevTtl === 1800;
    toast(`更新有效期失败：${err.message}`);
  } finally {
    if (ttlSelect) ttlSelect.disabled = false;
    if (presetBtn) presetBtn.disabled = false;
    if (regenBtn) regenBtn.disabled = false;
  }
}

function triggerBlobHtmlDownload(filename, html) {
  const safeName = String(filename || "magpie-simple-share-invite.html").trim() || "magpie-simple-share-invite.html";
  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = safeName;
    a.rel = "noopener";
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  }
}

async function exportInviteCard() {
  const inv = uiState.activeInvite;
  if (!inv?.id || uiState.exportingInviteCard) return;
  const btn = $("#btn-export-invite-card");
  const fallbackBox = $("#invite-card-fallback");
  const fallbackText = $("#invite-card-fallback-text");
  uiState.exportingInviteCard = true;
  btn.disabled = true;
  btn.textContent = "正在生成邀请卡…";
  fallbackBox.hidden = true;
  try {
    const res = await api(`/api/host/invites/${encodeURIComponent(inv.id)}/card`);
    const html = typeof res?.html === "string" ? res.html : "";
    const filename = (typeof res?.filename === "string" && res.filename.trim())
      ? res.filename.trim()
      : (inv.cardFilename || "magpie-simple-share-invite.html");
    if (!html) {
      throw new Error("服务端未返回离线邀请卡内容。");
    }
    uiState.lastExportedCardHtml = html;
    uiState.lastExportedCardFilename = filename;

    // Sandboxed iframes without allow-downloads (opaque null origin) block <a download>.
    if (window.origin === "null") {
      fallbackText.textContent = `当前嵌入式沙箱限制直接下载文件，可点击右侧复制 HTML 保存为 ${filename}，或运行 simple-share invite --card 导出。`;
      fallbackBox.hidden = false;
      toast("嵌入式沙箱受限，已生成离线邀请卡 HTML 供复制保存");
      return;
    }

    try {
      triggerBlobHtmlDownload(filename, html);
      toast(`已导出离线邀请卡：${filename}`);
    } catch {
      fallbackText.textContent = `浏览器拦截了文件下载，请点击右侧复制离线邀请卡 HTML 并保存为 ${filename}。`;
      fallbackBox.hidden = false;
      toast("文件下载受限，请点击「复制邀请卡 HTML」手动保存");
    }
  } catch (err) {
    toast(`导出离线邀请卡失败：${err.message}`);
  } finally {
    uiState.exportingInviteCard = false;
    btn.textContent = "导出离线邀请卡（.html）";
    updateInviteCountdown();
  }
}

async function openInviteDialog() {
  const btn = $("#btn-create-invite");
  btn.disabled = true;
  try {
    const ttlSelect = $("#invite-ttl-select");
    if (ttlSelect) ttlSelect.value = "300";
    uiState.inviteTtlSec = 300;
    await createAndShowInvite({ replaceOld: false, ttlSec: 300 });
    uiState.inviteQrOpen = false;
    $("#invite-qr-box").hidden = true;
    $("#btn-toggle-qr").textContent = "展开二维码";
    if (!$("#dlg-invite").open) $("#dlg-invite").showModal();
  } catch (err) {
    toast(`生成邀请失败：${err.message}`);
  } finally {
    btn.disabled = !serverState?.sharingEnabled;
  }
}

async function revokeCurrentInvite() {
  const inv = uiState.activeInvite;
  if (!inv?.id) {
    $("#dlg-invite").close();
    return;
  }
  const btn = $("#btn-revoke-invite");
  btn.disabled = true;
  try {
    await api(`/api/host/invites/${encodeURIComponent(inv.id)}`, {
      method: "DELETE",
      isMutation: true,
    });
    uiState.activeInvite = null;
    uiState.lastExportedCardHtml = "";
    uiState.lastExportedCardFilename = "";
    if (inviteTimer) clearInterval(inviteTimer);
    $("#dlg-invite").close();
    toast("已作废该一次性邀请码");
  } catch (err) {
    toast(`作废失败：${err.message}`);
  } finally {
    btn.disabled = false;
  }
}

function openApproveDialog(pendingId) {
  const p = (serverState?.pending || []).find((x) => x.id === pendingId);
  if (!p) return;
  uiState.currentApproveId = pendingId;
  $("#approve-title").textContent = `${p.name} 申请使用你分享的模型`;
  $("#approve-sas").textContent = p.sas || "----";
  $("#approve-meta").innerHTML = `${escHtml(fmtTime(p.requestedAt))}申请 · 设备公钥 <code class="mono">${escHtml(p.clientFp)}</code> · 接入通道：${escHtml(MODE_META[p.mode]?.full || p.mode)}`;
  $("#approve-note").value = "";
  $("#approve-note").placeholder = `留空则使用「${p.name}」`;
  $("#approve-error").hidden = true;

  const avail = serverState?.availableModels || [];
  const defaultModels = avail.filter((m) => m.kind !== "sub").slice(0, 2).map((m) => m.id);
  renderModelPicker(
    $("#approve-model-picker"),
    defaultModels.length > 0 ? defaultModels : avail.slice(0, 1).map((m) => m.id),
    $("#approve-tos-warn"),
    $("#approve-model-count"),
    avail
  );
  $("#dlg-approve").showModal();
}

async function confirmApprove() {
  const p = (serverState?.pending || []).find((x) => x.id === uiState.currentApproveId);
  if (!p) return;
  const errEl = $("#approve-error");
  const models = [...$("#approve-model-picker").querySelectorAll("input:checked")].map((i) => i.value);
  if (models.length === 0) {
    errEl.textContent = "请至少勾选 1 个允许对方使用的模型。";
    errEl.hidden = false;
    return;
  }
  const period = $("#approve-period").value;
  const costLimit = Math.max(0.5, Number($("#approve-cost").value) || 3);
  const tokenLimitWan = Math.max(1, Number($("#approve-tokens").value) || 100);
  const concurrency = Math.min(20, Math.max(1, Math.round(Number($("#approve-conc").value) || 2)));
  const note = $("#approve-note").value.trim();

  const btn = $("#btn-confirm-approve");
  const rejBtn = $("#btn-reject-apply");
  btn.disabled = true;
  rejBtn.disabled = true;
  errEl.hidden = true;

  try {
    const body = { models, period, costLimit, tokenLimitWan, concurrency };
    if (note) body.note = note;
    await api(`/api/host/pending/${encodeURIComponent(p.id)}/approve`, {
      method: "POST",
      body,
      isMutation: true,
    });
    $("#dlg-approve").close();
    await refreshState();
    toast(`已同意「${note || p.name}」的分享并创建本机受限 gateway-key`);
  } catch (err) {
    errEl.textContent = `审批失败：${err.message}`;
    errEl.hidden = false;
  } finally {
    btn.disabled = false;
    rejBtn.disabled = false;
  }
}

async function rejectApply() {
  const p = (serverState?.pending || []).find((x) => x.id === uiState.currentApproveId);
  if (!p) return;
  const errEl = $("#approve-error");
  const btn = $("#btn-reject-apply");
  btn.disabled = true;
  errEl.hidden = true;
  try {
    await api(`/api/host/pending/${encodeURIComponent(p.id)}/reject`, {
      method: "POST",
      isMutation: true,
    });
    $("#dlg-approve").close();
    await refreshState();
    toast(`已拒绝「${p.name}」的申请，该一次性邀请码已作废`);
  } catch (err) {
    errEl.textContent = `拒绝失败：${err.message}`;
    errEl.hidden = false;
  } finally {
    btn.disabled = false;
  }
}

function openEditMemberDialog(memberId) {
  const m = (serverState?.members || []).find((x) => x.id === memberId);
  if (!m) return;
  uiState.currentEditMemberId = memberId;
  $("#edit-member-title").textContent = `设置模型与额度 · ${m.name}`;
  $("#edit-member-note").value = m.name || "";
  $("#edit-period").value = m.period || "day";
  $("#edit-cost").value = m.costLimit ?? 3;
  $("#edit-tokens").value = m.tokenLimitWan ?? 100;
  $("#edit-conc").value = m.concurrency ?? 2;
  $("#edit-member-error").hidden = true;
  renderModelPicker(
    $("#edit-model-picker"),
    m.models || [],
    $("#edit-tos-warn"),
    $("#edit-model-count"),
    serverState?.availableModels || []
  );
  $("#dlg-edit-member").showModal();
}

async function saveMemberEdit() {
  const m = (serverState?.members || []).find((x) => x.id === uiState.currentEditMemberId);
  if (!m) return;
  const errEl = $("#edit-member-error");
  const models = [...$("#edit-model-picker").querySelectorAll("input:checked")].map((i) => i.value);
  if (models.length === 0) {
    errEl.textContent = "请至少保留 1 个可用模型。";
    errEl.hidden = false;
    return;
  }
  const name = $("#edit-member-note").value.trim() || m.name;
  const period = $("#edit-period").value;
  const costLimit = Math.max(0.5, Number($("#edit-cost").value) || m.costLimit || 3);
  const tokenLimitWan = Math.max(1, Number($("#edit-tokens").value) || m.tokenLimitWan || 100);
  const concurrency = Math.min(20, Math.max(1, Math.round(Number($("#edit-conc").value) || m.concurrency || 2)));

  const btn = $("#btn-save-member");
  btn.disabled = true;
  errEl.hidden = true;
  try {
    await api(`/api/host/members/${encodeURIComponent(m.id)}`, {
      method: "PATCH",
      body: { name, models, period, costLimit, tokenLimitWan, concurrency },
      isMutation: true,
    });
    $("#dlg-edit-member").close();
    await refreshState();
    toast(`已更新「${name}」的模型范围与 magpie gateway-key 限额`);
  } catch (err) {
    errEl.textContent = `保存失败：${err.message}`;
    errEl.hidden = false;
  } finally {
    btn.disabled = false;
  }
}

// ==================== Receiver Flows ====================

function extractInviteCodeFromHash(rawHash) {
  const raw = String(rawHash || "").trim();
  if (!raw || raw === "#") return "";
  const body = raw.startsWith("#") ? raw.slice(1) : raw;
  if (!body) return "";

  let candidate = "";
  if (/^invite=/i.test(body)) {
    candidate = body.slice("invite=".length).split("&")[0];
  } else if (/^mshare1(?::|%3a)/i.test(body)) {
    candidate = body.split("&")[0];
  } else {
    return "";
  }

  let decoded = "";
  try {
    decoded = decodeURIComponent(candidate).trim();
  } catch {
    return "";
  }
  if (!decoded.startsWith("mshare1:")) return "";
  if (!/^mshare1:[A-Za-z0-9_-]+$/.test(decoded)) return "";
  return decoded;
}

function extractInviteCodeFromInput(rawInput) {
  const raw = String(rawInput || "").trim();
  if (!raw) return "";
  if (/^mshare1:[A-Za-z0-9_-]+$/.test(raw)) return raw;
  try {
    const parsedUrl = new URL(raw);
    if (parsedUrl.protocol === "http:" || parsedUrl.protocol === "https:") {
      const fromHash = extractInviteCodeFromHash(parsedUrl.hash);
      if (fromHash) return fromHash;
    }
  } catch { /* not a full URL */ }
  return raw;
}

function clearLocationHash() {
  try {
    history.replaceState(null, "", window.location.pathname + window.location.search);
  } catch {
    try {
      if (window.location.hash) window.location.hash = "";
    } catch { /* ignore in strict opaque sandbox */ }
  }
}

async function handleInviteHashHandoff() {
  if (uiState.handlingInviteHash) return false;
  const code = extractInviteCodeFromHash(window.location.hash);
  if (!code) return false;

  uiState.handlingInviteHash = true;
  try {
    // Immediately clear hash so invite secret does not remain in browser history.
    clearLocationHash();

    $$("dialog[open]").forEach((dlg) => {
      if (dlg.id !== "dlg-paste") dlg.close();
    });

    switchTab("received");
    openPasteDialog();
    $("#paste-code-textarea").value = code;

    // Land directly on Step 2 (host fingerprint + 4 transparency facts + device name).
    // SECURITY INVARIANT: NEVER auto-submit /api/receiver/apply without explicit user confirmation!
    await parseInviteCode();
    return true;
  } finally {
    uiState.handlingInviteHash = false;
  }
}

function openPasteDialog() {
  uiState.parsedInvite = null;
  $("#paste-dlg-title").textContent = "输入分享邀请";
  $("#paste-step-1").hidden = false;
  $("#paste-step-2").hidden = true;
  $("#btn-paste-back").hidden = true;
  $("#btn-parse-invite").hidden = false;
  $("#btn-send-apply").hidden = true;
  $("#paste-error").hidden = true;
  $("#apply-error").hidden = true;
  $("#paste-code-textarea").value = "";
  $("#input-device-name").value = serverState?.identity?.hostName || "";
  if (!$("#dlg-paste").open) $("#dlg-paste").showModal();
}

function backToPasteStep1() {
  $("#paste-dlg-title").textContent = "输入分享邀请";
  $("#paste-step-1").hidden = false;
  $("#paste-step-2").hidden = true;
  $("#btn-paste-back").hidden = true;
  $("#btn-parse-invite").hidden = false;
  $("#btn-send-apply").hidden = true;
  $("#apply-error").hidden = true;
}

async function parseInviteCode() {
  const rawInput = $("#paste-code-textarea").value.trim();
  const errEl = $("#paste-error");
  if (!rawInput) {
    errEl.textContent = "请先粘贴对方发给你的分享邀请码或完整分享链接。";
    errEl.hidden = false;
    return;
  }
  const code = extractInviteCodeFromInput(rawInput);
  const btn = $("#btn-parse-invite");
  btn.disabled = true;
  errEl.hidden = true;
  try {
    const parsed = await api("/api/receiver/parse", {
      method: "POST",
      body: { code },
      isMutation: true,
    });
    uiState.parsedInvite = { code, ...parsed };
    $("#paste-dlg-title").textContent = "确认分享说明并发送申请";
    $("#apply-ask-title").textContent = `「${parsed.h || "对方电脑"}」想把 magpie 模型分享给你`;
    $("#apply-mode-badge").textContent = MODE_META[parsed.m]?.full || parsed.m || "";
    $("#apply-host-fp").textContent = parsed.fp || "";
    const expText = parsed.expiresAt ? `邀请有效期至 ${new Date(parsed.expiresAt).toLocaleTimeString("zh-CN", { hour12: false })}` : "";
    const epText = parsed.ep ? ` · 接入点：${typeof parsed.ep === "string" ? parsed.ep : (parsed.ep.relayAddr || parsed.ep.directHost || parsed.ep.irohEndpointId || "已附带")}` : "";
    $("#apply-invite-meta").textContent = `${expText}${epText}`;

    if (!$("#input-device-name").value.trim()) {
      $("#input-device-name").value = serverState?.identity?.hostName || "我的设备";
    }
    $("#paste-step-1").hidden = true;
    $("#paste-step-2").hidden = false;
    $("#btn-paste-back").hidden = false;
    $("#btn-parse-invite").hidden = true;
    $("#btn-send-apply").hidden = false;
  } catch (err) {
    errEl.textContent = err.message || "邀请码无法解析或已过期，请完整复制后重试。";
    errEl.hidden = false;
  } finally {
    btn.disabled = false;
  }
}

async function sendApply() {
  if (!uiState.parsedInvite) return;
  const deviceName = $("#input-device-name").value.trim() || serverState?.identity?.hostName || "我的设备";
  const errEl = $("#apply-error");
  const btn = $("#btn-send-apply");
  btn.disabled = true;
  errEl.hidden = true;

  try {
    const res = await api("/api/receiver/apply", {
      method: "POST",
      body: { code: uiState.parsedInvite.code, deviceName },
      isMutation: true,
    });
    $("#dlg-paste").close();
    await refreshState();
    const sas = res?.pending?.sas;
    toast(sas ? `申请已发送 · 你的 4 位配对码为 ${sas}` : "申请已发送，请等待对方核对配对码并同意");
  } catch (err) {
    errEl.textContent = `发送申请失败：${err.message}`;
    errEl.hidden = false;
  } finally {
    btn.disabled = false;
  }
}

async function runShareTest(shareId) {
  const r = (serverState?.received || []).find((x) => x.id === shareId);
  if (!r) return;
  const model = uiState.selectedTestModels.get(shareId) || (r.models && r.models[0]) || undefined;

  uiState.streamLogs.set(shareId, {
    loading: true,
    html: `<span class="c-dim">正在建立端到端加密通道并测试模型 ${escHtml(model || "默认模型")}…</span>`,
  });
  renderAll();

  try {
    const res = await api(`/api/receiver/shares/${encodeURIComponent(shareId)}/test`, {
      method: "POST",
      body: model ? { model } : {},
      isMutation: true,
    });
    const lines = [];
    if (Array.isArray(res.steps)) {
      for (const st of res.steps) {
        if (typeof st === "string") {
          lines.push(`<span class="c-ok">✓ ${escHtml(st)}</span>`);
        } else if (st && typeof st === "object") {
          const ok = st.ok !== false;
          lines.push(`<span class="${ok ? "c-ok" : "c-err"}">${ok ? "✓" : "✕"} ${escHtml(st.label || st.name || "")}${st.detail ? `：${escHtml(st.detail)}` : ""}</span>`);
        }
      }
    }
    const metaParts = [];
    if (res.linkType) metaParts.push(res.linkType);
    if (res.rttMs !== undefined && res.rttMs !== null) metaParts.push(`RTT ${res.rttMs}ms`);
    if (res.model) metaParts.push(`模型 ${res.model}`);
    if (metaParts.length > 0) {
      lines.push(`<span class="c-dim">链路与目标：${escHtml(metaParts.join(" · "))}</span>`);
    }
    if (res.preview) {
      lines.push(`&gt; ${escHtml(res.preview)}`);
    }
    if (res.usage) {
      const u = res.usage;
      const tot = Number(u.totalTokens ?? ((Number(u.inputTokens || 0) + Number(u.outputTokens || 0)) || 0));
      lines.push(`<span class="c-ok">✓ 消耗统计：${escHtml(tot)} tokens</span>`);
    } else if (res.ok) {
      lines.push(`<span class="c-ok">✓ 端到端连接与流式推理验证通过</span>`);
    }

    uiState.streamLogs.set(shareId, { loading: false, html: lines.join("\n") });
    await refreshState({ silent: true });
  } catch (err) {
    uiState.streamLogs.set(shareId, {
      loading: false,
      html: `<span class="c-err">✕ 测试失败：${escHtml(err.message)}</span>`,
    });
    renderAll();
  }
}

// ==================== Network & Mode Flows ====================

async function saveNetworkMode(targetMode, networkPayload, feedbackEl) {
  try {
    await api("/api/network/mode", {
      method: "POST",
      body: networkPayload ? { mode: targetMode, network: networkPayload } : { mode: targetMode },
      isMutation: true,
    });
    uiState.viewedMode = targetMode;
    for (const id of ["input-custom-iroh-relay", "input-relay-addr", "input-relay-token", "input-direct-host", "input-direct-port"]) {
      uiState.dirtyInputs.delete(id);
    }
    await refreshState();
    const label = MODE_META[targetMode]?.full || targetMode;
    if (feedbackEl) {
      feedbackEl.innerHTML = `<span style="color:var(--green);">✓ 已保存并应用 ${escHtml(label)}</span>`;
    }
    toast(`已切换至 ${label}`);
  } catch (err) {
    if (feedbackEl) {
      feedbackEl.innerHTML = `<span style="color:var(--red);">✕ ${escHtml(err.message)}</span>`;
    } else {
      toast(`切换模式失败：${err.message}`);
    }
  }
}

async function saveShareBaseUrl(rawValue) {
  const shareBaseUrl = String(rawValue ?? "").trim();
  const saveBtn = $("#btn-save-share-base-url");
  const clearBtn = $("#btn-clear-share-base-url");
  const feedbackEl = $("#share-base-url-result");
  saveBtn.disabled = true;
  clearBtn.disabled = true;
  try {
    const res = await api("/api/host/share-base-url", {
      method: "POST",
      body: { shareBaseUrl },
      isMutation: true,
    });
    const saved = typeof res?.shareBaseUrl === "string" ? res.shareBaseUrl : shareBaseUrl;
    uiState.dirtyInputs.delete("input-share-base-url");
    $("#input-share-base-url").value = saved;
    await refreshState();
    if (feedbackEl) {
      feedbackEl.innerHTML = saved
        ? `<span style="color:var(--green);">✓ 已保存在线邀请页地址</span>`
        : `<span style="color:var(--green);">✓ 已清空在线邀请页地址</span>`;
    }
    toast(saved ? "已保存在线邀请页地址" : "已清空在线邀请页地址");
  } catch (err) {
    if (feedbackEl) {
      feedbackEl.innerHTML = `<span style="color:var(--red);">✕ ${escHtml(err.message)}</span>`;
    }
    toast(`保存失败：${err.message}`);
  } finally {
    saveBtn.disabled = false;
    clearBtn.disabled = false;
  }
}

async function selectModeCard(targetMode) {
  uiState.viewedMode = targetMode;
  renderAll();
  if (targetMode === serverState?.mode) return;

  if (targetMode === "p2p") {
    const irohRelayUrl = $("#input-custom-iroh-relay").value.trim();
    await saveNetworkMode("p2p", { irohRelayUrl });
  } else if (targetMode === "self-relay") {
    const relayAddr = $("#input-relay-addr").value.trim();
    const relayToken = $("#input-relay-token").value.trim();
    if (relayAddr) {
      await saveNetworkMode("self-relay", { relayAddr, relayToken });
    } else {
      toast("请填写自建盲中转地址后点击「保存并启用模式 2」");
    }
  } else if (targetMode === "direct") {
    const directHost = $("#input-direct-host").value.trim();
    const directPort = Number($("#input-direct-port").value) || 3497;
    if (directHost) {
      await saveNetworkMode("direct", { directHost, directPort });
    } else {
      toast("请填写宿主公网地址或 DDNS 后点击「保存并启用模式 3」");
    }
  }
}

async function installIrohComponent() {
  if (uiState.irohInstalling) return;
  uiState.irohInstalling = true;
  renderAll();
  try {
    const res = await api("/api/network/iroh/install", {
      method: "POST",
      isMutation: true,
    });
    await refreshState();
    if (res?.irohStatus?.integrityOk) {
      toast(`模式 1 核心组件（${res.irohStatus.platformPkg || "@number0/iroh"}）校验通过，已就绪`);
    } else {
      toast("组件下载完成，但完整性检查未通过");
    }
  } catch (err) {
    toast(`P2P 组件安装失败：${err.message}`);
  } finally {
    uiState.irohInstalling = false;
    renderAll();
  }
}

async function testRelayConnectivity() {
  const el = $("#relay-test-result");
  const relayAddr = $("#input-relay-addr").value.trim();
  const relayToken = $("#input-relay-token").value.trim();
  if (!relayAddr) {
    el.innerHTML = `<span style="color:var(--red);">请先填写盲中转地址（如 1.2.3.4:3499 或 wss://...）</span>`;
    return;
  }
  el.textContent = `正在测试盲中转 ${relayAddr}…`;
  try {
    const res = await api("/api/network/test-relay", {
      method: "POST",
      body: { relayAddr, relayToken },
      isMutation: true,
    });
    if (res.ok) {
      const blindNote = res.blindVerified ? " · 盲转发握手验证通过" : "";
      el.innerHTML = `<span style="color:var(--green);">✓ 盲管道连通正常（RTT ${escHtml(res.rttMs ?? "-")}ms${escHtml(blindNote)}）</span>`;
    } else {
      el.innerHTML = `<span style="color:var(--red);">✕ 连通失败：${escHtml(res.error || "未知错误")}</span>`;
    }
  } catch (err) {
    el.innerHTML = `<span style="color:var(--red);">✕ 测试失败：${escHtml(err.message)}</span>`;
  }
}

async function testDirectReachability() {
  const el = $("#direct-test-result");
  const directHost = $("#input-direct-host").value.trim();
  const directPort = Number($("#input-direct-port").value) || 3497;
  el.textContent = "正在检测本机公网 IPv6 与入站端口可达性…";
  try {
    const res = await api("/api/network/test-direct", {
      method: "POST",
      body: { directHost, directPort },
      isMutation: true,
    });
    const color = res.ok && res.reachable ? "var(--green)" : "var(--amber)";
    const icon = res.ok && res.reachable ? "✓" : "⚠";
    const addrs = Array.isArray(res.addresses) && res.addresses.length > 0
      ? `（本机地址：${res.addresses.join(", ")}）`
      : "";
    el.innerHTML = `<span style="color:${color};">${icon} ${escHtml(res.message || (res.hasPublicIpv6 ? "已检测到公网 IPv6" : "未检测到公网 IPv6"))}${escHtml(addrs)}</span>`;
  } catch (err) {
    el.innerHTML = `<span style="color:var(--red);">✕ 检测失败：${escHtml(err.message)}</span>`;
  }
}

function openConfirm(title, desc, btnLabel, onOk) {
  $("#confirm-title").textContent = title;
  $("#confirm-desc").textContent = desc;
  $("#btn-confirm-ok").textContent = btnLabel;
  uiState.pendingConfirmAction = onOk;
  $("#dlg-confirm").showModal();
}

// ==================== Issue Reporting (Privacy-Safe) ====================

function sanitizeDiagnosticError(raw) {
  let msg = String(raw || "").trim();
  if (!msg) return "";
  msg = msg
    .replace(/\bsk-magpie-key-[A-Za-z0-9_-]+\b/gi, "[REDACTED_KEY]")
    .replace(/\bmshare1:[A-Za-z0-9_-]+\b/gi, "[REDACTED_INVITE]")
    .replace(/\bed25519:[0-9a-fA-F·:-]+\b/gi, "[REDACTED_FP]")
    .replace(/https?:\/\/[^\s"'<>]+/gi, "[REDACTED_URL]")
    .replace(/wss?:\/\/[^\s"'<>]+/gi, "[REDACTED_URL]")
    .replace(/\[[0-9a-fA-F:]+\](?::\d{1,5})?/g, "[REDACTED_IPV6]")
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b/g, "[REDACTED_IP]")
    .replace(/\b[0-9a-fA-F]{16,}\b/g, "[REDACTED_HEX]")
    .replace(/\s+/g, " ")
    .trim();
  return msg.slice(0, 160);
}

function buildIssueDiagnostics() {
  const s = serverState;
  const env = s?.environment || {};
  const osRuntime = env.platform
    ? `${env.platform}/${env.arch || "unknown"}${env.bunVersion ? ` (Bun ${env.bunVersion})` : ""}`
    : (navigator.platform || "unknown");
  const viewCtx = window.origin === "null" ? "magpie-iframe-sandbox" : "standalone-browser";
  const gw = s?.magpieGateway;
  const gwText = gw
    ? (gw.ok ? `connected${gw.version ? ` (v${gw.version})` : ""}` : "disconnected")
    : "unknown";
  const mode = s?.mode || "unknown";
  const sharing = s ? (s.sharingEnabled ? "enabled" : "paused") : "unknown";
  const listening = s?.transportStatus?.listening ? "yes" : "no";
  const iroh = s?.irohStatus;
  const irohText = !iroh
    ? "unknown"
    : iroh.supported === false
      ? "unsupported"
      : iroh.installed
        ? `${iroh.integrityOk ? "ready" : "corrupted"}${iroh.version ? ` (v${iroh.version})` : ""}`
        : "not-installed";

  const members = Array.isArray(s?.members) ? s.members : [];
  const pending = Array.isArray(s?.pending) ? s.pending : [];
  const received = Array.isArray(s?.received) ? s.received : [];
  const linkCounts = {};
  for (const r of received) {
    const st = String(r?.linkStatus || r?.status || "unknown");
    linkCounts[st] = (linkCounts[st] || 0) + 1;
  }
  const linkSummary = Object.keys(linkCounts).length > 0
    ? ` (${Object.entries(linkCounts).map(([k, v]) => `${k}:${v}`).join(", ")})`
    : "";

  const lines = [
    `- Plugin: magpie-simple-share ${s?.version ? `v${s.version}` : "unknown"}`,
    `- OS/Runtime: ${osRuntime}`,
    `- View: ${viewCtx} | Tab: ${uiState.activeTab}`,
    `- Magpie Gateway: ${gwText}`,
    `- Sharing: ${sharing} | Mode: ${mode} | Listening: ${listening}`,
    `- Iroh: ${irohText}`,
    `- Counts: members=${members.length}, pending=${pending.length}, received=${received.length}${linkSummary}`,
  ];

  const transportErr = sanitizeDiagnosticError(s?.transportStatus?.error);
  if (transportErr) lines.push(`- Transport Error: ${transportErr}`);
  const svcErr = sanitizeDiagnosticError(uiState.serviceError);
  if (svcErr) lines.push(`- Service Error: ${svcErr}`);

  return lines.join("\n");
}

function buildIssueUrlClient({ title, body, labels }) {
  const buildWithBody = (text) => {
    const u = new URL(GITHUB_ISSUES_NEW_URL);
    if (title) u.searchParams.set("title", title);
    if (labels) u.searchParams.set("labels", labels);
    if (text) u.searchParams.set("body", text);
    return u.href;
  };
  let href = buildWithBody(body);
  let truncated = false;
  if (href.length > MAX_ISSUE_URL_LEN) {
    truncated = true;
    let lo = 0;
    let hi = body.length;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (buildWithBody(body.slice(0, mid) + ISSUE_TRUNCATED_NOTE).length <= MAX_ISSUE_URL_LEN) {
        lo = mid;
      } else {
        hi = mid - 1;
      }
    }
    const trimmed = body.slice(0, lo).trimEnd();
    href = buildWithBody(trimmed ? `${trimmed}${ISSUE_TRUNCATED_NOTE}` : ISSUE_TRUNCATED_NOTE.trim());
  }
  return { url: href, truncated };
}

function buildIssuePayload() {
  const typeMeta = ISSUE_TYPES[uiState.issueType] || ISSUE_TYPES.bug;
  const rawTitle = ($("#issue-title")?.value || "").replace(/[\r\n\0]/g, " ").trim().slice(0, 120);
  const title = rawTitle || typeMeta.prefix;
  const desc = ($("#issue-desc")?.value || "").replace(/\0/g, "").trim().slice(0, 3000);
  const includeDiag = $("#issue-include-diag")?.checked !== false;
  const diag = includeDiag ? buildIssueDiagnostics() : "";

  const sections = [
    `## 问题类型\n${typeMeta.label}`,
    `## 问题描述\n${desc || "（请在此补充现象、复现步骤或报错截图）"}`,
  ];
  if (diag) {
    sections.push(`## 环境与运行状态（已脱敏）\n${diag}`);
  }
  const fullMarkdown = sections.join("\n\n");
  const { url: issueUrl, truncated } = buildIssueUrlClient({
    title,
    body: fullMarkdown,
    labels: typeMeta.ghLabel,
  });

  return {
    title,
    body: fullMarkdown,
    labels: typeMeta.ghLabel,
    fullMarkdown,
    issueUrl,
    truncated,
  };
}

function setIssueType(nextType) {
  if (!ISSUE_TYPES[nextType]) return;
  uiState.issueType = nextType;
  $$(".issue-type-pill").forEach((pill) => {
    const active = pill.dataset.issueType === nextType;
    pill.classList.toggle("is-active", active);
    pill.setAttribute("aria-checked", active ? "true" : "false");
  });
}

function openIssueDialog({ defaultType } = {}) {
  if (defaultType && ISSUE_TYPES[defaultType]) {
    setIssueType(defaultType);
  } else {
    setIssueType(uiState.issueType || "bug");
  }
  const fallback = $("#issue-fallback");
  if (fallback) fallback.hidden = true;
  const preview = $("#issue-diag-preview");
  if (preview) preview.textContent = buildIssueDiagnostics();
  const dlg = $("#dlg-issue");
  if (dlg && !dlg.open) dlg.showModal();
}

function showIssueFallback(url, text) {
  const fallback = $("#issue-fallback");
  const fallbackText = $("#issue-fallback-text");
  const urlInput = $("#issue-fallback-url");
  if (fallbackText && text) fallbackText.textContent = text;
  if (urlInput) urlInput.value = url || GITHUB_ISSUES_NEW_URL;
  if (fallback) fallback.hidden = false;
}

async function submitIssueToGitHub() {
  const btn = $("#btn-issue-open");
  const payload = buildIssuePayload();
  const fullCopyText = `# ${payload.title}\n\n${payload.fullMarkdown}`;
  if (payload.truncated) {
    await copyText(fullCopyText);
  }

  const inSandbox = window.origin === "null";
  if (inSandbox) {
    btn.disabled = true;
    try {
      const res = await api("/api/feedback/open", {
        method: "POST",
        body: {
          title: payload.title,
          body: payload.body,
          labels: payload.labels,
        },
      });
      if (res?.ok) {
        toast(
          res.truncated || payload.truncated
            ? "已在浏览器打开 GitHub Issue 页面，完整报告已复制到剪贴板"
            : "已在系统浏览器打开 GitHub Issue 提交页面",
        );
      } else {
        showIssueFallback(
          res?.url || payload.issueUrl,
          "当前环境无法自动打开浏览器，请复制下方 GitHub 链接，或点击「复制反馈内容」。",
        );
        toast("未能直接唤起浏览器，已生成可复制链接");
      }
    } catch (err) {
      showIssueFallback(
        payload.issueUrl,
        `唤起浏览器失败（${err.message}），请复制下方链接在浏览器打开。`,
      );
      toast("未能直接唤起浏览器，已生成可复制链接");
    } finally {
      btn.disabled = false;
    }
    return;
  }

  let opened = null;
  try {
    opened = window.open(payload.issueUrl, "_blank", "noopener,noreferrer");
  } catch {
    opened = null;
  }
  if (opened) {
    toast(
      payload.truncated
        ? "已打开 GitHub Issue 页面，完整报告已复制到剪贴板"
        : "已打开 GitHub Issue 提交页面",
    );
  } else {
    showIssueFallback(
      payload.issueUrl,
      "浏览器拦截了弹窗，请复制下方 GitHub 链接在新标签页打开，或点击「复制反馈内容」。",
    );
    toast("弹窗被拦截，请复制下方链接或反馈内容");
  }
}

// ==================== Event Bindings ====================

function bindEvents() {
  $$(".tab").forEach((t) => t.addEventListener("click", () => switchTab(t.dataset.tab)));
  $("#jump-network-btn").addEventListener("click", () => switchTab("network"));

  $("#btn-theme").addEventListener("click", () => {
    const root = document.documentElement;
    root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
  });

  $("#btn-retry-state").addEventListener("click", () => refreshState());
  $("#btn-open-issue")?.addEventListener("click", () => openIssueDialog());
  $("#btn-footer-issue")?.addEventListener("click", () => openIssueDialog());
  $("#btn-banner-issue")?.addEventListener("click", () => {
    openIssueDialog({ defaultType: uiState.serviceError ? "bug" : "network" });
  });
  $$(".issue-type-pill").forEach((pill) => {
    pill.addEventListener("click", () => setIssueType(pill.dataset.issueType));
  });
  $("#issue-include-diag")?.addEventListener("change", () => {
    const preview = $("#issue-diag-preview");
    if (preview) preview.textContent = buildIssueDiagnostics();
  });
  $("#btn-issue-copy")?.addEventListener("click", async () => {
    const payload = buildIssuePayload();
    const ok = await copyText(`# ${payload.title}\n\n${payload.fullMarkdown}`);
    toast(ok ? "已复制完整反馈内容（已自动脱敏）" : "复制受限，请手动选择复制");
  });
  $("#btn-issue-copy-url")?.addEventListener("click", async () => {
    const ok = await copyText($("#issue-fallback-url")?.value || "");
    toast(ok ? "GitHub Issue 链接已复制到剪贴板" : "复制受限，请手动全选复制链接");
  });
  $("#btn-issue-open")?.addEventListener("click", () => {
    void submitIssueToGitHub();
  });

  $("#toggle-sharing").addEventListener("change", (e) => handleToggleSharing(e.target.checked));
  $("#btn-confirm-tos").addEventListener("click", confirmTosAndEnable);

  $("#btn-edit-host-name").addEventListener("click", openHostNameDialog);
  $("#btn-save-host-name").addEventListener("click", saveHostName);

  $("#toggle-vis-limit").addEventListener("change", async (e) => {
    const val = e.target.checked;
    try {
      await api("/api/host/visibility", { method: "POST", body: { limit: val }, isMutation: true });
      await refreshState();
    } catch (err) {
      e.target.checked = !val;
      toast(`保存设置失败：${err.message}`);
    }
  });

  $("#toggle-vis-quotas").addEventListener("change", async (e) => {
    const val = e.target.checked;
    try {
      await api("/api/host/visibility", { method: "POST", body: { quotas: val }, isMutation: true });
      await refreshState();
    } catch (err) {
      e.target.checked = !val;
      toast(`保存设置失败：${err.message}`);
    }
  });

  $("#btn-create-invite").addEventListener("click", openInviteDialog);
  $("#invite-ttl-select").addEventListener("change", (e) => {
    void changeInviteTtl(Number(e.target.value));
  });
  $("#btn-ttl-preset-1800").addEventListener("click", () => {
    void changeInviteTtl(1800);
  });
  $("#btn-export-invite-card").addEventListener("click", () => {
    void exportInviteCard();
  });
  $("#btn-copy-invite-card-html").addEventListener("click", async () => {
    const ok = await copyText(uiState.lastExportedCardHtml);
    if (ok) {
      toast(`已复制离线邀请卡 HTML，可保存为 ${uiState.lastExportedCardFilename || "invite.html"}`);
    } else {
      toast("复制受限，请尝试在独立浏览器中打开导出或使用 CLI");
    }
  });
  $("#btn-copy-invite-link").addEventListener("click", async () => {
    const ok = await copyText($("#invite-link-input").value);
    if (ok) {
      $("#btn-copy-invite-link").textContent = "已复制 ✓";
      setTimeout(() => { $("#btn-copy-invite-link").textContent = "复制链接"; }, 1600);
      toast("在线邀请链接已复制到剪贴板");
    } else {
      toast("自动复制受限，请手动全选复制输入框中的在线链接");
    }
  });
  $("#btn-jump-share-base-url").addEventListener("click", () => {
    $("#dlg-invite").close();
    switchTab("network");
    const input = $("#input-share-base-url");
    if (input) {
      input.scrollIntoView({ behavior: "smooth", block: "center" });
      input.focus();
    }
  });
  $("#btn-regen-invite").addEventListener("click", async () => {
    try {
      await createAndShowInvite({ replaceOld: true, ttlSec: getSelectedInviteTtlSec() });
      toast("已重新生成一次性邀请码，旧码已作废");
    } catch (err) {
      toast(`重新生成失败：${err.message}`);
    }
  });
  $("#btn-revoke-invite").addEventListener("click", revokeCurrentInvite);

  $("#btn-copy-invite").addEventListener("click", async () => {
    const ok = await copyText($("#invite-code-input").value);
    if (ok) {
      $("#btn-copy-invite").textContent = "已复制 ✓";
      setTimeout(() => { $("#btn-copy-invite").textContent = "复制邀请码"; }, 1600);
      toast("邀请码已复制到剪贴板");
    } else {
      toast("自动复制受限，请手动全选复制输入框中的邀请码");
    }
  });

  $("#btn-toggle-qr").addEventListener("click", () => {
    uiState.inviteQrOpen = !uiState.inviteQrOpen;
    $("#invite-qr-box").hidden = !uiState.inviteQrOpen;
    $("#btn-toggle-qr").textContent = uiState.inviteQrOpen ? "收起二维码" : "展开二维码";
  });

  $("#btn-open-paste").addEventListener("click", openPasteDialog);
  $("#btn-paste-back").addEventListener("click", backToPasteStep1);
  $("#btn-parse-invite").addEventListener("click", parseInviteCode);
  $("#btn-send-apply").addEventListener("click", sendApply);

  $("#btn-confirm-approve").addEventListener("click", confirmApprove);
  $("#btn-reject-apply").addEventListener("click", rejectApply);
  $("#btn-save-member").addEventListener("click", saveMemberEdit);

  $$("[data-close-dlg]").forEach((btn) => {
    btn.addEventListener("click", () => btn.closest("dialog")?.close());
  });

  $$(".range-pill").forEach((pill) => {
    pill.addEventListener("click", async () => {
      const nextRange = pill.dataset.range;
      uiState.range = nextRange;
      renderAll();
      try {
        const res = await api(`/api/host/usage?range=${encodeURIComponent(nextRange)}`);
        if (serverState && res?.usageByMember) {
          serverState.usageByMember = {
            ...(serverState.usageByMember || {}),
            ...res.usageByMember,
          };
          renderAll();
        }
      } catch { /* silent fallback to cached usage */ }
    });
  });

  // Network tab controls
  $$("[data-select-mode]").forEach((head) => {
    const onSelect = () => selectModeCard(head.dataset.selectMode);
    head.addEventListener("click", onSelect);
    head.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        onSelect();
      }
    });
  });

  for (const id of ["input-custom-iroh-relay", "input-relay-addr", "input-relay-token", "input-direct-host", "input-direct-port", "input-share-base-url"]) {
    $(`#${id}`)?.addEventListener("input", () => {
      uiState.dirtyInputs.add(id);
      if (id === "input-relay-addr" || id === "input-relay-token") {
        $("#docker-cmd").textContent = buildDockerCommand(
          $("#input-relay-addr").value,
          $("#input-relay-token").value
        );
      }
    });
  }

  $("#btn-save-share-base-url").addEventListener("click", () => {
    void saveShareBaseUrl($("#input-share-base-url").value);
  });
  $("#btn-clear-share-base-url").addEventListener("click", () => {
    $("#input-share-base-url").value = "";
    void saveShareBaseUrl("");
  });

  window.addEventListener("hashchange", () => {
    void handleInviteHashHandoff();
  });

  $("#btn-install-iroh").addEventListener("click", installIrohComponent);
  $("#btn-save-p2p-relay").addEventListener("click", () => {
    const irohRelayUrl = $("#input-custom-iroh-relay").value.trim();
    saveNetworkMode("p2p", { irohRelayUrl });
  });
  $("#btn-save-self-relay").addEventListener("click", () => {
    const relayAddr = $("#input-relay-addr").value.trim();
    const relayToken = $("#input-relay-token").value.trim();
    if (!relayAddr) {
      $("#relay-test-result").innerHTML = `<span style="color:var(--red);">请先填写自建盲中转地址</span>`;
      return;
    }
    saveNetworkMode("self-relay", { relayAddr, relayToken }, $("#relay-test-result"));
  });
  $("#btn-save-direct").addEventListener("click", () => {
    const directHost = $("#input-direct-host").value.trim();
    const directPort = Number($("#input-direct-port").value) || 3497;
    if (!directHost) {
      $("#direct-test-result").innerHTML = `<span style="color:var(--red);">请先填写宿主公网地址或 DDNS 域名</span>`;
      return;
    }
    saveNetworkMode("direct", { directHost, directPort }, $("#direct-test-result"));
  });

  $("#btn-test-relay").addEventListener("click", testRelayConnectivity);
  $("#btn-test-direct").addEventListener("click", testDirectReachability);

  $("#btn-copy-docker").addEventListener("click", async () => {
    const ok = await copyText($("#docker-cmd").textContent);
    toast(ok ? "已复制自建盲中转 Docker 部署命令" : "复制受限，请手动选择复制");
  });
  $("#btn-copy-fp").addEventListener("click", async () => {
    const ok = await copyText($("#host-pubkey-fp").textContent);
    toast(ok ? "已复制本机 Ed25519 公钥指纹" : "复制受限，请手动选择复制");
  });
  $("#btn-copy-iroh-id").addEventListener("click", async () => {
    const ok = await copyText($("#host-iroh-id").textContent);
    toast(ok ? "已复制 Iroh EndpointId" : "复制受限，请手动选择复制");
  });

  $("#btn-confirm-ok").addEventListener("click", async () => {
    const fn = uiState.pendingConfirmAction;
    uiState.pendingConfirmAction = null;
    $("#dlg-confirm").close();
    if (fn) await fn();
  });

  // Delegated changes for model dropdown in received cards
  document.addEventListener("change", (e) => {
    const sel = e.target.closest("[data-select-test-model]");
    if (sel) {
      uiState.selectedTestModels.set(sel.dataset.selectTestModel, sel.value);
    }
  });

  // Delegated clicks for dynamic lists
  document.addEventListener("click", async (e) => {
    const t = e.target.closest(
      "[data-open-approve], [data-toggle-expand], [data-edit-member], [data-toggle-pause], [data-remove-member], [data-test-stream], [data-leave-share], [data-withdraw-apply]"
    );
    if (!t) return;

    if (t.dataset.openApprove) {
      openApproveDialog(t.dataset.openApprove);
    } else if (t.dataset.toggleExpand) {
      const id = t.dataset.toggleExpand;
      uiState.expandedMemberId = uiState.expandedMemberId === id ? null : id;
      renderAll();
    } else if (t.dataset.editMember) {
      openEditMemberDialog(t.dataset.editMember);
    } else if (t.dataset.togglePause) {
      const m = (serverState?.members || []).find((x) => x.id === t.dataset.togglePause);
      if (!m) return;
      const nextPaused = m.status !== "paused";
      t.disabled = true;
      try {
        await api(`/api/host/members/${encodeURIComponent(m.id)}/pause`, {
          method: "POST",
          body: { paused: nextPaused },
          isMutation: true,
        });
        await refreshState();
        toast(nextPaused ? `已暂停「${m.name}」的分享（额度保留，随时可恢复）` : `已恢复「${m.name}」的分享`);
      } catch (err) {
        toast(`操作失败：${err.message}`);
      } finally {
        t.disabled = false;
      }
    } else if (t.dataset.removeMember) {
      const m = (serverState?.members || []).find((x) => x.id === t.dataset.removeMember);
      if (!m) return;
      openConfirm(
        `删除对「${m.name}」的分享？`,
        `删除后，「${m.name}」将立即无法调用本机模型，正在进行的流式响应会立刻中断，同时销毁本机对应的受限 gateway-key（历史用量统计保留，且不影响其他成员）。之后若再分享需重新生成邀请。`,
        "确认删除并断流",
        async () => {
          try {
            await api(`/api/host/members/${encodeURIComponent(m.id)}`, {
              method: "DELETE",
              isMutation: true,
            });
            await refreshState();
            toast(`已撤销「${m.name}」的分享并销毁受限 key`);
          } catch (err) {
            toast(`删除失败：${err.message}`);
          }
        }
      );
    } else if (t.dataset.testStream) {
      runShareTest(t.dataset.testStream);
    } else if (t.dataset.leaveShare) {
      const r = (serverState?.received || []).find((x) => x.id === t.dataset.leaveShare);
      if (!r) return;
      openConfirm(
        `退出「${r.hostName}」的分享？`,
        `退出后会移除本机自动配置的 remote-magpie（${r.providerId}）并断开加密通道，不影响分享者和其他人。之后若需再次使用，需要对方重新生成邀请码。`,
        "确认退出分享",
        async () => {
          try {
            await api(`/api/receiver/shares/${encodeURIComponent(r.id)}`, {
              method: "DELETE",
              isMutation: true,
            });
            uiState.streamLogs.delete(r.id);
            await refreshState();
            toast(`已退出「${r.hostName}」的分享`);
          } catch (err) {
            toast(`退出失败：${err.message}`);
          }
        }
      );
    } else if (t.dataset.withdrawApply) {
      const pid = t.dataset.withdrawApply;
      t.disabled = true;
      try {
        await api(`/api/receiver/pending/${encodeURIComponent(pid)}`, {
          method: "DELETE",
          isMutation: true,
        });
        await refreshState();
        toast("申请已撤回");
      } catch (err) {
        toast(`撤回失败：${err.message}`);
      } finally {
        t.disabled = false;
      }
    }
  });
}

// ==================== Boot ====================

bindEvents();
refreshState().finally(() => {
  scheduleNextPoll();
  void handleInviteHashHandoff();
});
