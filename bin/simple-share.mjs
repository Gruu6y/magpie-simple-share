#!/usr/bin/env bun
import { mkdir, writeFile } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { loadOrCreateIdentity } from "../lib/crypto.mjs";
import { getIrohStatus } from "../lib/iroh-installer.mjs";
import { discoverMagpieGateway, isLoopbackUrl } from "../lib/magpie-cli.mjs";
import { identityPath, irohDir, pluginDataDir, statePath } from "../lib/paths.mjs";
import { createStore, sanitizeStateSnapshot } from "../lib/store.mjs";

const DEFAULT_PORT = 3494;
const TOKEN_HEADER = "x-simple-share-token";
const TOKEN_META_NAME = "simple-share-token";

export class CliError extends Error {
  constructor(message, { code = "cli_error", status = 0 } = {}) {
    super(message);
    this.name = "CliError";
    this.code = code;
    this.status = status;
  }
}

export function parseTokenFromHtml(html) {
  const text = String(html ?? "");
  const tag = new RegExp(`<meta\\b[^>]*name=["']${TOKEN_META_NAME}["'][^>]*>`, "i").exec(text);
  if (!tag) return "";
  const content = /content=["']([^"']*)["']/i.exec(tag[0]);
  return content ? content[1] : "";
}

const BOOLEAN_FLAGS = new Set(["help", "json", "tos"]);
const OPTIONAL_VALUE_FLAGS = new Set(["card"]);
const VALUE_FLAGS = new Set([
  "port",
  "url",
  "token",
  "ttl",
  "models",
  "period",
  "tokens",
  "cost",
  "concurrency",
  "note",
  "name",
  "model",
  "relay",
  "relay-token",
  "iroh-relay",
  "share-base-url",
  "host",
  "direct-port",
]);

export function parseCliArgs(argv) {
  const positional = [];
  const options = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (typeof arg !== "string") continue;
    if (arg === "--") {
      positional.push(...argv.slice(i + 1));
      break;
    }
    if (arg === "-h") {
      options.help = true;
      continue;
    }
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }
    const body = arg.slice(2);
    const eq = body.indexOf("=");
    if (eq >= 0) {
      const k = body.slice(0, eq);
      const v = body.slice(eq + 1);
      if (!BOOLEAN_FLAGS.has(k) && !VALUE_FLAGS.has(k) && !OPTIONAL_VALUE_FLAGS.has(k)) {
        throw new CliError(`Unknown option --${k}`, { code: "unknown_option" });
      }
      options[k] = v;
      continue;
    }
    if (BOOLEAN_FLAGS.has(body)) {
      options[body] = true;
      continue;
    }
    if (OPTIONAL_VALUE_FLAGS.has(body)) {
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("-")) {
        options[body] = next;
        i += 1;
      } else {
        options[body] = true;
      }
      continue;
    }
    if (VALUE_FLAGS.has(body)) {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) {
        throw new CliError(`Option --${body} requires a value`, { code: "invalid_args" });
      }
      options[body] = next;
      i += 1;
      continue;
    }
    throw new CliError(`Unknown option --${body}`, { code: "unknown_option" });
  }
  return { positional, options };
}

function helpText() {
  return [
    "magpie-simple-share — 去中心化零信任模型分享 CLI",
    "",
    "用法:",
    "  magpie-simple-share <command> [args] [options]",
    "",
    "命令:",
    "  status                              查看插件状态（在线时查控制面，离线时读本地存储）",
    "  toggle <on|off> [--tos]             开启或关闭对外分享",
    "  invite [--ttl <秒>] [--card [文件]] 生成邀请码/链接，或导出离线 .html 邀请卡",
    "  invite revoke <id>                  作废指定邀请",
    "  pending                             列出待审批申请及 4 位配对码",
    "  approve <pendingId>                 审批申请（--models a,b --period day --tokens 100 --cost 3 --concurrency 2 --note 备注）",
    "  reject <pendingId>                  拒绝申请并作废邀请",
    "  members                             列出已分享成员及状态",
    "  pause <memberId>                    暂停成员（保留额度，返回 403 share_paused）",
    "  resume <memberId>                   恢复成员",
    "  revoke <memberId>                   撤销成员并立即断流、销毁 gateway-key",
    "  apply <code-or-url> [--name <设备>] 输入 mshare1: 邀请码或完整邀请链接并提交申请",
    "  join <code-or-url> [--name <设备>]  一键加入（解析邀请，按需自动安装 P2P 模块，提交申请并打印 4 位配对码）",
    "  received [test <id>|leave <id>]     查看/测试/退出已加入的分享",
    "  mode [p2p|self-relay|direct]        查看或切换传输模式（支持 --share-base-url）",
    "  doctor                              本地环境、身份、Magpie 网关与安全自检",
    "",
    "通用选项:",
    "  --port <n>                          控制面端口（默认 3494 或 SIMPLE_SHARE_PORT）",
    "  --url <http://127.0.0.1:...>        显式控制面地址（仅允许本机回环 HTTP）",
    "  --json                              输出机器可读 JSON",
    "  --help, -h                          显示帮助",
  ].join("\n");
}

function resolveBaseUrl(options, env) {
  if (options.url) {
    const cleaned = String(options.url).trim().replace(/\/+$/, "");
    if (!isLoopbackUrl(cleaned)) {
      throw new CliError("Control-plane URL must be a loopback http://127.0.0.1 / localhost / [::1] URL", {
        code: "non_loopback_url",
      });
    }
    return cleaned;
  }
  const p = Number(options.port ?? env.SIMPLE_SHARE_PORT ?? DEFAULT_PORT);
  const port = Number.isInteger(p) && p > 0 && p <= 65535 ? p : DEFAULT_PORT;
  return `http://127.0.0.1:${port}`;
}

async function discoverControlPlane(baseUrl, options, fetchImpl) {
  let token = typeof options.token === "string" ? options.token.trim() : "";
  try {
    const healthRes = await fetchImpl(`${baseUrl}/api/health`, { method: "GET" });
    if (!healthRes.ok) return { running: false, token: "" };
    const health = await healthRes.json().catch(() => null);
    if (!health?.ok) return { running: false, token: "" };
    if (!token) {
      const htmlRes = await fetchImpl(`${baseUrl}/`, { method: "GET" });
      if (htmlRes.ok) {
        token = parseTokenFromHtml(await htmlRes.text());
      }
    }
    return { running: true, version: health.version || "", token };
  } catch {
    return { running: false, token: "" };
  }
}

async function apiCall(baseUrl, token, path, { method = "GET", body, fetchImpl = fetch } = {}) {
  const headers = { [TOKEN_HEADER]: token };
  if (body !== undefined) headers["content-type"] = "application/json";
  const res = await fetchImpl(`${baseUrl}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    throw new CliError(data?.message || data?.error || `HTTP ${res.status}`, {
      code: data?.code || data?.error || `http_${res.status}`,
      status: res.status,
    });
  }
  return data;
}

async function readOfflineDiagnostics(env) {
  const dataDir = pluginDataDir(env);
  const idFile = identityPath(env);
  const stFile = statePath(env);
  const identity = await loadOrCreateIdentity(idFile);
  const store = createStore(stFile);
  const raw = await store.load();
  const state = sanitizeStateSnapshot(raw);
  const magpieGateway = await discoverMagpieGateway({ env });
  const irohStatus = getIrohStatus(irohDir(env));
  return { dataDir, identity, state, magpieGateway, irohStatus };
}

function writeOut(data, asJson, humanText, stdout) {
  if (asJson) {
    stdout.write(`${JSON.stringify(data, null, 2)}\n`);
  } else {
    stdout.write(`${humanText}\n`);
  }
}

/**
 * Executes the Simple Share CLI. Accepts injectable stdio/env/fetch for isolated testing.
 */
export async function runCli(
  argv = [],
  { env = process.env, fetchImpl = fetch, stdout = process.stdout, stderr = process.stderr, cwd = process.cwd() } = {},
) {
  const { positional, options } = parseCliArgs(argv);
  const asJson = Boolean(options.json);

  if (options.help || positional.length === 0) {
    if (asJson && positional.length === 0 && !options.help) {
      stdout.write(`${JSON.stringify({ ok: true, help: helpText() }, null, 2)}\n`);
    } else {
      stdout.write(`${helpText()}\n`);
    }
    return 0;
  }

  const cmd = positional[0];
  const baseUrl = resolveBaseUrl(options, env);

  if (cmd === "doctor") {
    const [cp, diag] = await Promise.all([
      discoverControlPlane(baseUrl, options, fetchImpl),
      readOfflineDiagnostics(env),
    ]);
    const report = {
      ok: true,
      controlPlane: {
        running: cp.running,
        url: baseUrl,
        version: cp.version || null,
      },
      dataDir: diag.dataDir,
      identity: {
        fingerprint: diag.identity.fingerprint,
        pubKeyHex: diag.identity.pubKeyHex,
        irohEndpointId: diag.identity.irohEndpointId,
      },
      state: {
        hostName: diag.state.hostName,
        sharingEnabled: diag.state.sharingEnabled,
        mode: diag.state.mode,
        pendingCount: diag.state.pending.length,
        membersCount: diag.state.members.length,
        receivedCount: diag.state.received.length,
      },
      magpieGateway: diag.magpieGateway,
      irohStatus: diag.irohStatus,
      security: {
        noTun: true,
        loopbackOnlyGateway: !diag.magpieGateway.url || isLoopbackUrl(diag.magpieGateway.url),
        failClosedOracleEnabled: true,
        controlPlaneLoopbackOnly: isLoopbackUrl(baseUrl),
      },
    };
    writeOut(
      report,
      asJson,
      [
        `Control Plane: ${cp.running ? `running (${baseUrl})` : `stopped (${baseUrl})`}`,
        `Identity:      ${diag.identity.fingerprint}`,
        `Mode:          ${diag.state.mode} (sharing: ${diag.state.sharingEnabled ? "on" : "off"})`,
        `Magpie GW:     ${diag.magpieGateway.ok ? `${diag.magpieGateway.url} v${diag.magpieGateway.version}` : "offline"}`,
        `Iroh Module:   ${
          diag.irohStatus.supported === false
            ? `unsupported (${diag.irohStatus.unsupportedReason || "no native binary"})`
            : diag.irohStatus.installed
              ? `${diag.irohStatus.platformPkg} (integrity: ${diag.irohStatus.integrityOk})`
              : "not installed (on-demand)"
        }`,
        `Members:       ${diag.state.members.length} | Pending: ${diag.state.pending.length} | Received: ${diag.state.received.length}`,
      ].join("\n"),
      stdout,
    );
    return 0;
  }

  const cp = await discoverControlPlane(baseUrl, options, fetchImpl);

  if (!cp.running) {
    if (cmd === "status" || cmd === "members" || cmd === "pending" || cmd === "received" || (cmd === "mode" && !positional[1])) {
      const diag = await readOfflineDiagnostics(env);
      if (cmd === "status") {
        const payload = {
          running: false,
          url: baseUrl,
          identity: {
            fingerprint: diag.identity.fingerprint,
            hostName: diag.state.hostName,
            irohEndpointId: diag.identity.irohEndpointId,
          },
          sharingEnabled: diag.state.sharingEnabled,
          mode: diag.state.mode,
          pendingCount: diag.state.pending.length,
          membersCount: diag.state.members.length,
          receivedCount: diag.state.received.length,
          magpieGateway: diag.magpieGateway,
          irohStatus: diag.irohStatus,
        };
        writeOut(
          payload,
          asJson,
          `Service: offline (${baseUrl})\nSharing: ${diag.state.sharingEnabled ? "on" : "off"} | Mode: ${diag.state.mode} | Members: ${diag.state.members.length} | Received: ${diag.state.received.length}`,
          stdout,
        );
        return 0;
      }
      if (cmd === "members") {
        writeOut(
          { members: diag.state.members },
          asJson,
          diag.state.members.length === 0
            ? "No members."
            : diag.state.members.map((m) => `${m.id}\t${m.name}\t${m.status}\t${m.magpieKeyName || "-"}`).join("\n"),
          stdout,
        );
        return 0;
      }
      if (cmd === "pending") {
        writeOut(
          { pending: diag.state.pending },
          asJson,
          diag.state.pending.length === 0
            ? "No pending requests."
            : diag.state.pending.map((p) => `${p.id}\t${p.name}\tSAS:${p.sas}\t${p.clientFp}`).join("\n"),
          stdout,
        );
        return 0;
      }
      if (cmd === "received") {
        writeOut(
          { received: diag.state.received },
          asJson,
          diag.state.received.length === 0
            ? "No received shares."
            : diag.state.received.map((r) => `${r.id}\t${r.hostName}\t${r.providerId}\t127.0.0.1:${r.bridgePort}\t${r.status}`).join("\n"),
          stdout,
        );
        return 0;
      }
      if (cmd === "mode") {
        writeOut(
          { mode: diag.state.mode, network: diag.state.network },
          asJson,
          `Mode: ${diag.state.mode}`,
          stdout,
        );
        return 0;
      }
    }
    throw new CliError(`Simple Share service is not running at ${baseUrl}`, {
      code: "service_offline",
    });
  }

  if (!cp.token) {
    throw new CliError("Failed to obtain session token from control plane", {
      code: "missing_token",
    });
  }

  if (cmd === "status") {
    const state = await apiCall(baseUrl, cp.token, "/api/state", { fetchImpl });
    const summary = {
      running: true,
      url: baseUrl,
      version: state.version,
      identity: state.identity,
      sharingEnabled: state.sharingEnabled,
      mode: state.mode,
      transportStatus: state.transportStatus,
      magpieGateway: state.magpieGateway,
      irohStatus: state.irohStatus,
      pendingCount: state.pending?.length ?? 0,
      membersCount: state.members?.length ?? 0,
      receivedCount: state.received?.length ?? 0,
    };
    writeOut(
      summary,
      asJson,
      `Service: running (${baseUrl}) v${state.version}\nSharing: ${state.sharingEnabled ? "on" : "off"} | Mode: ${state.mode} (${state.transportStatus?.listening ? "listening" : "idle"})\nMembers: ${summary.membersCount} | Pending: ${summary.pendingCount} | Received: ${summary.receivedCount}`,
      stdout,
    );
    return 0;
  }

  if (cmd === "toggle") {
    const val = positional[1];
    if (val !== "on" && val !== "off") {
      throw new CliError("Usage: toggle <on|off> [--tos]", { code: "invalid_args" });
    }
    const res = await apiCall(baseUrl, cp.token, "/api/host/toggle", {
      method: "POST",
      body: { enabled: val === "on", ...(options.tos ? { tosAcknowledged: true } : {}) },
      fetchImpl,
    });
    writeOut(res, asJson, `Sharing: ${res.sharingEnabled ? "on" : "off"}`, stdout);
    return 0;
  }

  if (cmd === "invite") {
    if (positional[1] === "revoke") {
      const id = positional[2];
      if (!id) throw new CliError("Usage: invite revoke <inviteId>", { code: "invalid_args" });
      const res = await apiCall(baseUrl, cp.token, `/api/host/invites/${encodeURIComponent(id)}`, {
        method: "DELETE",
        fetchImpl,
      });
      writeOut(res, asJson, `Revoked invite ${id}`, stdout);
      return 0;
    }
    let body;
    if (options.ttl !== undefined) {
      const rawTtl = String(options.ttl).trim();
      if (!/^\d+$/.test(rawTtl)) {
        throw new CliError("Option --ttl must be an integer between 60 and 86400 seconds", {
          code: "invalid_ttl",
        });
      }
      body = { ttlSec: Number(rawTtl) };
    }
    const res = await apiCall(baseUrl, cp.token, "/api/host/invites", {
      method: "POST",
      ...(body ? { body } : {}),
      fetchImpl,
    });
    const outPayload = { ...res };
    const lines = [res.code, `(id: ${res.id}, mode: ${res.mode}, ttl: ${res.ttlSec}s)`];
    if (res.shareUrl) {
      lines.push(`Share URL: ${res.shareUrl}`);
    }
    if (options.card !== undefined) {
      const cardRes = await apiCall(baseUrl, cp.token, `/api/host/invites/${encodeURIComponent(res.id)}/card`, {
        fetchImpl,
      });
      const requestedPath = typeof options.card === "string" ? options.card.trim() : "";
      const defaultName =
        basename(String(cardRes.filename || res.cardFilename || "simple-share-invite.html").replace(/[\r\n\0]/g, "")) ||
        "simple-share-invite.html";
      const outPath = requestedPath ? resolve(cwd, requestedPath) : resolve(cwd, defaultName);
      await mkdir(dirname(outPath), { recursive: true });
      await writeFile(outPath, String(cardRes.html ?? ""), "utf8");
      outPayload.cardPath = outPath;
      outPayload.cardFilename = cardRes.filename || res.cardFilename || defaultName;
      lines.push(`Card: ${outPath}`);
    }
    writeOut(outPayload, asJson, lines.join("\n"), stdout);
    return 0;
  }

  if (cmd === "pending") {
    const state = await apiCall(baseUrl, cp.token, "/api/state", { fetchImpl });
    const list = state.pending || [];
    writeOut(
      { pending: list },
      asJson,
      list.length === 0
        ? "No pending requests."
        : list.map((p) => `${p.id}\t${p.name}\tSAS:${p.sas}\t${p.clientFp}\t${p.mode}`).join("\n"),
      stdout,
    );
    return 0;
  }

  if (cmd === "approve") {
    const id = positional[1];
    if (!id) throw new CliError("Usage: approve <pendingId> [--models m1,m2]", { code: "invalid_args" });
    const state = await apiCall(baseUrl, cp.token, "/api/state", { fetchImpl });
    let models = typeof options.models === "string"
      ? options.models.split(",").map((s) => s.trim()).filter(Boolean)
      : [];
    if (models.length === 0) {
      models = (state.availableModels || []).filter((m) => m.kind !== "sub").slice(0, 2).map((m) => m.id);
      if (models.length === 0 && state.availableModels?.[0]?.id) {
        models = [state.availableModels[0].id];
      }
      if (models.length === 0) models = ["all"];
    }
    const body = {
      models,
      period: options.period || "day",
      tokenLimitWan: options.tokens !== undefined ? Number(options.tokens) : 100,
      costLimit: options.cost !== undefined ? Number(options.cost) : 3,
      concurrency: options.concurrency !== undefined ? Number(options.concurrency) : 2,
      ...(options.note ? { note: options.note } : {}),
    };
    const res = await apiCall(baseUrl, cp.token, `/api/host/pending/${encodeURIComponent(id)}/approve`, {
      method: "POST",
      body,
      fetchImpl,
    });
    writeOut(res, asJson, `Approved ${res.member?.id} (${res.member?.name})`, stdout);
    return 0;
  }

  if (cmd === "reject") {
    const id = positional[1];
    if (!id) throw new CliError("Usage: reject <pendingId>", { code: "invalid_args" });
    const res = await apiCall(baseUrl, cp.token, `/api/host/pending/${encodeURIComponent(id)}/reject`, {
      method: "POST",
      fetchImpl,
    });
    writeOut(res, asJson, `Rejected ${id}`, stdout);
    return 0;
  }

  if (cmd === "members") {
    const state = await apiCall(baseUrl, cp.token, "/api/state", { fetchImpl });
    const list = state.members || [];
    writeOut(
      { members: list },
      asJson,
      list.length === 0
        ? "No members."
        : list.map((m) => `${m.id}\t${m.name}\t${m.status}\trunning:${m.running}\t${m.magpieKeyName}`).join("\n"),
      stdout,
    );
    return 0;
  }

  if (cmd === "pause" || cmd === "resume") {
    const id = positional[1];
    if (!id) throw new CliError(`Usage: ${cmd} <memberId>`, { code: "invalid_args" });
    const res = await apiCall(baseUrl, cp.token, `/api/host/members/${encodeURIComponent(id)}/pause`, {
      method: "POST",
      body: { paused: cmd === "pause" },
      fetchImpl,
    });
    writeOut(res, asJson, `${cmd === "pause" ? "Paused" : "Resumed"} ${id}`, stdout);
    return 0;
  }

  if (cmd === "revoke") {
    const id = positional[1];
    if (!id) throw new CliError("Usage: revoke <memberId>", { code: "invalid_args" });
    const res = await apiCall(baseUrl, cp.token, `/api/host/members/${encodeURIComponent(id)}`, {
      method: "DELETE",
      fetchImpl,
    });
    writeOut(res, asJson, `Revoked ${id}`, stdout);
    return 0;
  }

  if (cmd === "apply") {
    const code = positional[1];
    if (!code) throw new CliError("Usage: apply <inviteCodeOrUrl> [--name <device>]", { code: "invalid_args" });
    const res = await apiCall(baseUrl, cp.token, "/api/receiver/apply", {
      method: "POST",
      body: { code, ...(options.name ? { deviceName: options.name } : {}) },
      fetchImpl,
    });
    const sas = res?.pending?.sas;
    writeOut(
      res,
      asJson,
      sas ? `Applied (pendingId: ${res.pending.id}, SAS: ${sas})` : "Approved immediately",
      stdout,
    );
    return 0;
  }

  if (cmd === "join") {
    const input = positional[1];
    if (!input) throw new CliError("Usage: join <inviteCodeOrUrl> [--name <device>]", { code: "invalid_args" });
    const parsed = await apiCall(baseUrl, cp.token, "/api/receiver/parse", {
      method: "POST",
      body: { code: input },
      fetchImpl,
    });

    let irohAutoInstalled = false;
    let irohStatus = null;
    if (parsed.m === "p2p") {
      const state = await apiCall(baseUrl, cp.token, "/api/state", { fetchImpl });
      irohStatus = state?.irohStatus || null;
      if (irohStatus?.supported === false) {
        throw new CliError(
          `P2P (Mode 1) is unsupported on this platform (${irohStatus.unsupportedReason || "no native binary"}); ask the host for Mode 2 or Mode 3.`,
          { code: "iroh_unsupported" },
        );
      }
      if (!irohStatus?.installed || !irohStatus?.integrityOk) {
        const installRes = await apiCall(baseUrl, cp.token, "/api/network/iroh/install", {
          method: "POST",
          fetchImpl,
        });
        irohStatus = installRes?.irohStatus || irohStatus;
        if (!installRes?.ok) {
          throw new CliError("Failed to install Iroh P2P module", { code: "iroh_install_failed" });
        }
        irohAutoInstalled = true;
      }
    }

    const applied = await apiCall(baseUrl, cp.token, "/api/receiver/apply", {
      method: "POST",
      body: { code: input, ...(options.name ? { deviceName: options.name } : {}) },
      fetchImpl,
    });

    const outPayload = {
      ok: true,
      invite: {
        id: parsed.id,
        hostName: parsed.h,
        hostFp: parsed.fp,
        mode: parsed.m,
        expiresAt: parsed.expiresAt,
      },
      irohAutoInstalled,
      ...(irohStatus ? { irohStatus } : {}),
      ...applied,
    };

    const sas = applied?.pending?.sas;
    const lines = [
      `Host: ${parsed.h} (${parsed.fp})`,
      `Mode: ${parsed.m}${irohAutoInstalled ? " (Iroh module auto-installed)" : ""}`,
    ];
    if (sas) {
      lines.push(`SAS:  ${sas}`);
      lines.push(`Pending ID: ${applied.pending.id}`);
      lines.push("请向分享者核对以上 4 位配对码（SAS），对方批准后即可开始使用。");
    } else {
      lines.push("Status: Approved immediately");
    }
    writeOut(outPayload, asJson, lines.join("\n"), stdout);
    return 0;
  }

  if (cmd === "received") {
    const sub = positional[1];
    if (sub === "test") {
      const id = positional[2];
      if (!id) throw new CliError("Usage: received test <shareId> [--model <m>]", { code: "invalid_args" });
      const res = await apiCall(baseUrl, cp.token, `/api/receiver/shares/${encodeURIComponent(id)}/test`, {
        method: "POST",
        body: options.model ? { model: options.model } : {},
        fetchImpl,
      });
      writeOut(res, asJson, `OK (${res.linkType || "connected"}, RTT ${res.rttMs ?? "-"}ms)`, stdout);
      return 0;
    }
    if (sub === "leave") {
      const id = positional[2];
      if (!id) throw new CliError("Usage: received leave <shareId>", { code: "invalid_args" });
      const res = await apiCall(baseUrl, cp.token, `/api/receiver/shares/${encodeURIComponent(id)}`, {
        method: "DELETE",
        fetchImpl,
      });
      writeOut(res, asJson, `Left share ${id}`, stdout);
      return 0;
    }
    const state = await apiCall(baseUrl, cp.token, "/api/state", { fetchImpl });
    const list = state.received || [];
    writeOut(
      { received: list },
      asJson,
      list.length === 0
        ? "No received shares."
        : list.map((r) => `${r.id}\t${r.hostName}\t${r.providerId}\t127.0.0.1:${r.bridgePort}\t${r.status}`).join("\n"),
      stdout,
    );
    return 0;
  }

  if (cmd === "mode") {
    const nextMode = positional[1];
    if (!nextMode) {
      const state = await apiCall(baseUrl, cp.token, "/api/state", { fetchImpl });
      writeOut(
        { mode: state.mode, network: state.network, transportStatus: state.transportStatus },
        asJson,
        `Mode: ${state.mode}`,
        stdout,
      );
      return 0;
    }
    const network = {};
    if (options.relay !== undefined) network.relayAddr = options.relay;
    if (options["relay-token"] !== undefined) network.relayToken = options["relay-token"];
    if (options["iroh-relay"] !== undefined) network.irohRelayUrl = options["iroh-relay"];
    if (options["share-base-url"] !== undefined) network.shareBaseUrl = options["share-base-url"];
    if (options.host !== undefined) network.directHost = options.host;
    if (options["direct-port"] !== undefined) network.directPort = Number(options["direct-port"]);
    const res = await apiCall(baseUrl, cp.token, "/api/network/mode", {
      method: "POST",
      body: { mode: nextMode, network },
      fetchImpl,
    });
    writeOut(res, asJson, `Mode set to ${res.mode}`, stdout);
    return 0;
  }

  void stderr;
  throw new CliError(`Unknown command: ${cmd}`, { code: "unknown_command" });
}

const isMain =
  import.meta.main ||
  (typeof process.argv[1] === "string" && resolve(process.argv[1]) === fileURLToPath(import.meta.url));

if (isMain) {
  runCli(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err) => {
      const wantJson = process.argv.includes("--json");
      const code = err instanceof CliError ? err.code : "cli_error";
      const message = String(err?.message || err);
      if (wantJson) {
        process.stderr.write(`${JSON.stringify({ error: code, code, message })}\n`);
      } else {
        process.stderr.write(`Error [${code}]: ${message}\n`);
      }
      process.exitCode = 1;
    });
}
