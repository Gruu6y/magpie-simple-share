import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";
import zlib from "node:zlib";

export const IROH_VERSION = "1.2.0";
export const DEFAULT_REGISTRIES = Object.freeze([
  "https://registry.npmmirror.com",
  "https://registry.npmjs.org",
]);

export const IROH_INTEGRITY = Object.freeze({
  "@number0/iroh":
    "sha512-pZoVnL+8nK4DQG3owF5UQ/LcIjg7m2Ue1oeEUEhLsNt9RHtEFxiASNSPopOdsRfjRimJ/e6zjQ0k3iYE6N1hZQ==",
  "@number0/iroh-win32-x64-msvc":
    "sha512-3ltCadoaZzrRM9OmPcfwPpqwF/DBXlzhwsOIXITtpFEFfRISgvbqyhmMCaiumpyXxFeGTCfpwvUJ40i+sE0sVQ==",
  "@number0/iroh-win32-arm64-msvc":
    "sha512-2srn9OquRffLD1bQiCDRLr3T1yxmc9xc3k4oLgEMWU+lZnaMONRS2r46cTXN1b/bGsSc82TjGCO/urauXZjQcQ==",
  "@number0/iroh-darwin-arm64":
    "sha512-91oxmPrYiCnU0APp/Ky0mgNOxaIukQDFUvxth32TDq38vJs0lDX9ppAsWrkCA+4A/kJnAt1hc7YhIKcIGD3xOA==",
  "@number0/iroh-linux-x64-gnu":
    "sha512-SkZUe/dqv7J1kY3Af0Cu07ldfdstEDOz6F3yIKwMw/EpabhaE3fvdDbiDQoiMxbwgIiJMspChHRMZeC88Td3QQ==",
  "@number0/iroh-linux-x64-musl":
    "sha512-UnZHStWdFZgylftmX2IHF+VKkrkbEhK+amkOf7A9Z3JPrqkbF5em3UW3uyDK3qfhcc9Ijc3nnYKxym+BkOLPjQ==",
  "@number0/iroh-linux-arm64-gnu":
    "sha512-LEenFEMMWLnlyFy8++cYq+s7/nibFgFzs1kGDk7WvFDyxT3U2z0W0+hjENzDiS1iCtH8+zesdDdFxuQtxjJHYg==",
  "@number0/iroh-linux-arm64-musl":
    "sha512-YgCWpz80VOTJRtAUsTKFgLYtd7tfWwrRCD0uk3/xG4z+AjiY5c49toeDFTJJ/3SF5Q8qmjWGjpcUk6B1E55D4w==",
  "@number0/iroh-linux-arm-gnueabihf":
    "sha512-PTi5YyxjkLluzVec5Q0NJqRUaYcVT76sZ0SaM10HFGlwlTIniYO7DYUGTLs+XcByUBcE7Ph5xkyvoLmB1mOF4A==",
  "@number0/iroh-linux-arm-musleabihf":
    "sha512-IwOPvWOEyX6ZMHjctDaZyWVV2kJSXx57DRN2l5Qg/cEQjY5zWO4IMFvjw075IKrQk+VpU6RrEEI++2w2Gci1dA==",
});

const PLATFORM_PACKAGES = Object.freeze({
  "win32-x64": "@number0/iroh-win32-x64-msvc",
  "win32-arm64": "@number0/iroh-win32-arm64-msvc",
  "darwin-arm64": "@number0/iroh-darwin-arm64",
  "linux-x64": "@number0/iroh-linux-x64-gnu",
  "linux-x64-musl": "@number0/iroh-linux-x64-musl",
  "linux-arm64": "@number0/iroh-linux-arm64-gnu",
  "linux-arm64-musl": "@number0/iroh-linux-arm64-musl",
  "linux-arm": "@number0/iroh-linux-arm-gnueabihf",
  "linux-arm-musl": "@number0/iroh-linux-arm-musleabihf",
});

const MAX_TARBALL_BYTES = 64 * 1024 * 1024;
const installQueues = new Map();

/** Detect Linux C library ("gnu" or "musl"); returns null on non-Linux. */
export function detectLinuxLibc({
  platform = process.platform,
  reportHeader = process.report?.getReport?.()?.header,
  existsSync = fs.existsSync,
  readdirSync = fs.readdirSync,
} = {}) {
  if (platform !== "linux") return null;
  if (reportHeader?.glibcVersionRuntime) return "gnu";
  try {
    if (existsSync("/etc/alpine-release")) return "musl";
    if (existsSync("/lib") && readdirSync("/lib").some((f) => f.startsWith("ld-musl-"))) return "musl";
    if (existsSync("/lib64") && readdirSync("/lib64").some((f) => f.startsWith("ld-musl-"))) return "musl";
  } catch {
    // Ignore probe errors and default to glibc.
  }
  return "gnu";
}

function unsupportedPlatformReason(platform, arch, libc) {
  if (platform === "darwin" && arch === "x64") {
    return "Intel Mac (darwin-x64) 暂不支持模式 1 (@number0/iroh@1.2.0 仅提供 Apple Silicon darwin-arm64 原生组件)；请使用模式 2 自建盲中转或模式 3 公网直连。";
  }
  const label = libc ? `${platform}-${arch}-${libc}` : `${platform}-${arch}`;
  return `当前平台架构 (${label}) 暂无对应的 @number0/iroh@${IROH_VERSION} 原生包；请使用模式 2 自建盲中转或模式 3 公网直连。`;
}

/** Map Node/Bun (platform, arch, libc) to the matching @number0/iroh native package name. */
export function platformPackageName(platform = process.platform, arch = process.arch, { libc } = {}) {
  if (platform === "linux") {
    const resolvedLibc = libc === "musl" || libc === "gnu" ? libc : detectLinuxLibc({ platform });
    if (resolvedLibc === "musl") {
      return PLATFORM_PACKAGES[`linux-${arch}-musl`] ?? null;
    }
  }
  return PLATFORM_PACKAGES[`${platform}-${arch}`] ?? null;
}

function readNullStr(buf) {
  const zero = buf.indexOf(0);
  return buf.subarray(0, zero === -1 ? buf.length : zero).toString("utf8");
}

function parseOctal(buf) {
  const s = readNullStr(buf).trim();
  if (!s) return 0;
  if (!/^[0-7]+$/.test(s)) throw new Error(`Invalid tar octal field: ${JSON.stringify(s)}`);
  return Number.parseInt(s, 8);
}

function parseTarSize(buf) {
  if (buf[0] & 0x80) {
    let val = 0n;
    for (let i = 1; i < buf.length; i++) val = (val << 8n) | BigInt(buf[i]);
    if (val > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("Tar entry size exceeds safe integer");
    return Number(val);
  }
  return parseOctal(buf);
}

function verifyHeaderChecksum(header) {
  const expected = parseOctal(header.subarray(148, 156));
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 0x20 : header[i];
  if (sum !== expected) throw new Error(`Invalid tar header checksum (${sum} !== ${expected})`);
}

function parsePaxRecords(payload) {
  const text = payload.toString("utf8");
  const out = Object.create(null);
  let pos = 0;
  while (pos < text.length) {
    const sp = text.indexOf(" ", pos);
    if (sp === -1) break;
    const len = Number.parseInt(text.slice(pos, sp), 10);
    if (!Number.isFinite(len) || len <= 0) break;
    const rec = text.slice(sp + 1, pos + len).replace(/\n$/, "");
    const eq = rec.indexOf("=");
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    pos += len;
  }
  return out;
}

function sanitizeTarEntryPath(rawPath, destRoot) {
  if (!rawPath || rawPath.includes("\0") || rawPath.includes("\\")) {
    throw new Error(`Unsafe tar entry path: ${JSON.stringify(rawPath)}`);
  }
  if (rawPath.startsWith("/") || /^[A-Za-z]:/.test(rawPath)) {
    throw new Error(`Absolute tar entry path rejected: ${rawPath}`);
  }
  if (rawPath.split("/").includes("..")) {
    throw new Error(`Path traversal rejected in tar entry: ${rawPath}`);
  }
  let rel = rawPath;
  while (rel.startsWith("./")) rel = rel.slice(2);
  if (rel === "" || rel === "." || rel === "package" || rel === "package/") return null;
  if (rel.startsWith("package/")) rel = rel.slice("package/".length);
  if (!rel || rel === ".") return null;
  if (rel.startsWith("/") || /^[A-Za-z]:/.test(rel) || rel.split("/").includes("..")) {
    throw new Error(`Path traversal rejected after prefix strip: ${rawPath}`);
  }
  const resolvedRoot = path.resolve(destRoot);
  const resolvedTarget = path.resolve(resolvedRoot, rel);
  if (resolvedTarget !== resolvedRoot && !resolvedTarget.startsWith(resolvedRoot + path.sep)) {
    throw new Error(`Tar entry escapes destination root: ${rawPath}`);
  }
  return resolvedTarget;
}

/** Decompress and extract an npm .tgz buffer using a strict pure-JS POSIX ustar parser. */
function extractTgzToDir(tgzBuf, destDir) {
  const tar = zlib.gunzipSync(tgzBuf);
  const resolvedRoot = path.resolve(destDir);
  fs.mkdirSync(resolvedRoot, { recursive: true });

  let offset = 0;
  let paxPath = null;
  let paxSize = null;
  let longName = null;

  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    offset += 512;
    if (header.every((b) => b === 0)) break;

    verifyHeaderChecksum(header);
    const typeByte = header[156];
    const type = typeByte === 0 ? "0" : String.fromCharCode(typeByte);
    const mode = parseOctal(header.subarray(100, 108));
    let size = paxSize !== null ? paxSize : parseTarSize(header.subarray(124, 136));
    const name = readNullStr(header.subarray(0, 100));
    const prefix = readNullStr(header.subarray(345, 500));
    const rawPath = paxPath ?? longName ?? (prefix ? `${prefix}/${name}` : name);

    const padded = Math.ceil(size / 512) * 512;
    if (offset + padded > tar.length) throw new Error(`Truncated tar entry: ${rawPath}`);
    const payload = tar.subarray(offset, offset + size);
    offset += padded;

    if (type === "g") continue;
    if (type === "x") {
      const pax = parsePaxRecords(payload);
      if (typeof pax.path === "string") paxPath = pax.path;
      if (typeof pax.size === "string") paxSize = Number.parseInt(pax.size, 10);
      continue;
    }
    if (type === "L") {
      longName = payload.toString("utf8").replace(/\0+$/, "");
      continue;
    }
    paxPath = null;
    paxSize = null;
    longName = null;

    if (type === "1" || type === "2" || type === "K") {
      throw new Error(`Refusing tar link entry: ${rawPath}`);
    }
    if (type !== "0" && type !== "5") continue;

    const target = sanitizeTarEntryPath(rawPath, resolvedRoot);
    if (!target) continue;

    if (type === "5") {
      fs.mkdirSync(target, { recursive: true });
    } else {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, payload, { mode: mode & 0o111 ? 0o755 : 0o644 });
    }
  }
}

function verifySha512(buf, expectedIntegrity, pkgName) {
  const actual = "sha512-" + crypto.createHash("sha512").update(buf).digest("base64");
  const a = Buffer.from(actual, "utf8");
  const b = Buffer.from(String(expectedIntegrity ?? ""), "utf8");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    throw new Error(`sha512 mismatch for ${pkgName}: expected ${expectedIntegrity}, got ${actual}`);
  }
  return actual;
}

function tarballUrl(registry, pkgName) {
  const base = String(registry).replace(/\/+$/, "");
  const shortName = pkgName.includes("/") ? pkgName.split("/")[1] : pkgName;
  return `${base}/${pkgName}/-/${shortName}-${IROH_VERSION}.tgz`;
}

async function downloadVerifiedPackage({ pkgName, expectedIntegrity, registries, onProgress, timeoutMs }) {
  const errors = [];
  for (const registry of registries) {
    const url = tarballUrl(registry, pkgName);
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
      if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);

      const totalHeader = Number(res.headers.get("content-length") || 0);
      const totalBytes = Number.isFinite(totalHeader) && totalHeader > 0 ? totalHeader : null;
      let buf;
      if (res.body && typeof res.body.getReader === "function") {
        const reader = res.body.getReader();
        const chunks = [];
        let receivedBytes = 0;
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          receivedBytes += value.byteLength;
          if (receivedBytes > MAX_TARBALL_BYTES) throw new Error(`Tarball exceeds max size (${MAX_TARBALL_BYTES})`);
          chunks.push(Buffer.from(value));
          onProgress?.({
            stage: "downloading",
            packageName: pkgName,
            registry,
            receivedBytes,
            totalBytes,
            percent: totalBytes ? Math.min(100, Math.round((receivedBytes / totalBytes) * 100)) : null,
          });
        }
        buf = Buffer.concat(chunks);
      } else {
        buf = Buffer.from(await res.arrayBuffer());
        if (buf.length > MAX_TARBALL_BYTES) throw new Error(`Tarball exceeds max size (${MAX_TARBALL_BYTES})`);
      }

      onProgress?.({ stage: "verifying", packageName: pkgName, registry, receivedBytes: buf.length, totalBytes: buf.length, percent: 100 });
      const verifiedHash = verifySha512(buf, expectedIntegrity, pkgName);
      return { buf, registry, integrity: verifiedHash };
    } catch (err) {
      errors.push(`${registry}: ${err?.message ?? String(err)}`);
    }
  }
  throw new Error(`Failed to fetch and verify ${pkgName}@${IROH_VERSION}: ${errors.join("; ")}`);
}

async function atomicReplaceDir(stagePkgDir, finalPkgDir, backupDir) {
  await fsp.mkdir(path.dirname(finalPkgDir), { recursive: true });
  let backedUp = false;
  try {
    await fsp.stat(finalPkgDir);
    await fsp.rename(finalPkgDir, backupDir);
    backedUp = true;
  } catch (err) {
    if (err?.code !== "ENOENT") throw err;
  }
  try {
    await fsp.rename(stagePkgDir, finalPkgDir);
    if (backedUp) await fsp.rm(backupDir, { recursive: true, force: true });
  } catch (err) {
    if (backedUp) {
      await fsp.rename(backupDir, finalPkgDir).catch(() => {});
    }
    throw err;
  }
}

/** Check whether @number0/iroh and its verified native addon are installed under irohDir. */
export function getIrohStatus(irohDir, { platform = process.platform, arch = process.arch, libc, integrityOverrides } = {}) {
  const resolvedLibc = platform === "linux" ? (libc || detectLinuxLibc({ platform })) : null;
  const platformPkg = platformPackageName(platform, arch, { libc: resolvedLibc });
  const unsupportedReason = platformPkg ? null : unsupportedPlatformReason(platform, arch, resolvedLibc);
  const base = {
    installed: false,
    version: null,
    platformPkg,
    supported: Boolean(platformPkg),
    unsupportedReason,
    integrityOk: false,
  };
  if (!irohDir || !platformPkg) return base;

  const root = path.resolve(irohDir);
  const manifestPath = path.join(root, "manifest.json");
  const mainDir = path.join(root, "node_modules", "@number0", "iroh");
  const platSuffix = platformPkg.split("/")[1];
  const platDir = path.join(root, "node_modules", "@number0", platSuffix);

  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch {
    return base;
  }

  let platMainExists = false;
  try {
    const platPkgJson = JSON.parse(fs.readFileSync(path.join(platDir, "package.json"), "utf8"));
    platMainExists = platPkgJson?.main ? fs.existsSync(path.join(platDir, platPkgJson.main)) : true;
  } catch {
    platMainExists = false;
  }

  const hasFiles =
    fs.existsSync(path.join(mainDir, "package.json")) &&
    fs.existsSync(path.join(mainDir, "index.js")) &&
    platMainExists;
  if (!hasFiles || manifest?.version !== IROH_VERSION || manifest?.platformPkg !== platformPkg) {
    return base;
  }

  const expected = { ...IROH_INTEGRITY, ...(integrityOverrides || {}) };
  const mainRec = manifest.packages?.["@number0/iroh"]?.integrity;
  const platRec = manifest.packages?.[platformPkg]?.integrity;
  const hashesMatch =
    Boolean(manifest.integrityVerified) &&
    (manifest.customIntegrity && !integrityOverrides
      ? typeof mainRec === "string" && mainRec.startsWith("sha512-") && typeof platRec === "string" && platRec.startsWith("sha512-")
      : mainRec === expected["@number0/iroh"] && platRec === expected[platformPkg]);

  return {
    installed: Boolean(hashesMatch),
    version: hashesMatch ? manifest.version : null,
    platformPkg,
    supported: true,
    unsupportedReason: null,
    integrityOk: Boolean(hashesMatch),
  };
}

/** Download, sha512-verify, unpack, and atomically install @number0/iroh@1.2.0 into irohDir. */
export async function installIroh(
  irohDir,
  {
    registries = DEFAULT_REGISTRIES,
    onProgress,
    platform = process.platform,
    arch = process.arch,
    libc,
    integrityOverrides,
    force = false,
    timeoutMs = 60_000,
  } = {},
) {
  if (!irohDir || typeof irohDir !== "string") throw new Error("irohDir must be a non-empty path");
  const root = path.resolve(irohDir);
  const run = async () => {
    const resolvedLibc = platform === "linux" ? (libc || detectLinuxLibc({ platform })) : null;
    const platformPkg = platformPackageName(platform, arch, { libc: resolvedLibc });
    if (!platformPkg) {
      throw new Error(unsupportedPlatformReason(platform, arch, resolvedLibc));
    }

    if (!force) {
      const existing = getIrohStatus(root, { platform, arch, libc: resolvedLibc, integrityOverrides });
      if (existing.installed && existing.integrityOk) {
        onProgress?.({ stage: "ready", packageName: "@number0/iroh", percent: 100, alreadyInstalled: true });
        return { ok: true, alreadyInstalled: true, ...existing };
      }
    }

    const regList = Array.isArray(registries) && registries.length > 0 ? registries : DEFAULT_REGISTRIES;
    const expected = { ...IROH_INTEGRITY, ...(integrityOverrides || {}) };
    const packages = ["@number0/iroh", platformPkg];
    const rootExisted = fs.existsSync(root);
    const stagingDir = path.join(root, `.staging-${crypto.randomBytes(6).toString("hex")}`);
    await fsp.mkdir(stagingDir, { recursive: true });

    try {
      const pkgManifest = {};
      for (const pkgName of packages) {
        const { buf, registry, integrity } = await downloadVerifiedPackage({
          pkgName,
          expectedIntegrity: expected[pkgName],
          registries: regList,
          onProgress,
          timeoutMs,
        });
        onProgress?.({ stage: "extracting", packageName: pkgName, registry });
        const shortName = pkgName.split("/")[1];
        const stagePkgDir = path.join(stagingDir, shortName);
        extractTgzToDir(buf, stagePkgDir);
        pkgManifest[pkgName] = { version: IROH_VERSION, integrity, registry };
      }

      onProgress?.({ stage: "installing", packageName: "@number0/iroh" });
      const scopeDir = path.join(root, "node_modules", "@number0");
      for (const pkgName of packages) {
        const shortName = pkgName.split("/")[1];
        await atomicReplaceDir(
          path.join(stagingDir, shortName),
          path.join(scopeDir, shortName),
          path.join(stagingDir, `.backup-${shortName}`),
        );
      }

      const manifest = {
        version: IROH_VERSION,
        platform,
        arch,
        libc: resolvedLibc,
        platformPkg,
        integrityVerified: true,
        customIntegrity: Boolean(integrityOverrides),
        installedAt: new Date().toISOString(),
        packages: pkgManifest,
      };
      const stagedManifest = path.join(stagingDir, "manifest.json");
      await fsp.writeFile(stagedManifest, JSON.stringify(manifest, null, 2) + "\n", "utf8");
      await fsp.rename(stagedManifest, path.join(root, "manifest.json"));

      const status = getIrohStatus(root, { platform, arch, libc: resolvedLibc, integrityOverrides });
      onProgress?.({ stage: "ready", packageName: "@number0/iroh", percent: 100 });
      return { ok: true, alreadyInstalled: false, ...status };
    } catch (err) {
      await fsp.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
      if (!rootExisted) await fsp.rmdir(root).catch(() => {});
      throw err;
    } finally {
      await fsp.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
    }
  };

  const prev = installQueues.get(root) ?? Promise.resolve();
  const next = prev.then(run, run);
  installQueues.set(root, next);
  try {
    return await next;
  } finally {
    if (installQueues.get(root) === next) installQueues.delete(root);
  }
}

/** Load the verified @number0/iroh module installed in irohDir. */
export function loadIrohModule(irohDir, { platform = process.platform, arch = process.arch, libc, integrityOverrides } = {}) {
  const status = getIrohStatus(irohDir, { platform, arch, libc, integrityOverrides });
  if (!status.supported) {
    throw new Error(status.unsupportedReason || `Unsupported platform/arch for @number0/iroh: ${platform}-${arch}`);
  }
  if (!status.installed || !status.integrityOk) {
    throw new Error(`@number0/iroh is not installed or failed integrity check in ${irohDir}`);
  }
  const req = createRequire(pathToFileURL(path.join(path.resolve(irohDir), "_iroh_loader.cjs")).href);
  return req("@number0/iroh");
}
