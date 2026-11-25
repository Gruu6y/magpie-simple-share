#!/usr/bin/env sh
# Domestic no-VPN friendly bootstrap for magpie-simple-share (macOS / Linux POSIX sh).
# Idempotent, strict SHA256 verification for Magpie downloads, zero secret upload.
set -eu

PACKAGE_NAME="@gruu6y/page-simple-share"
DEFAULT_REGISTRY="https://registry.npmmirror.com"
OFFICIAL_RELEASE_BASE="https://usemagpie.ai/releases/latest"

INVITE_RAW=""
DEVICE_NAME=""
MIRROR=""
REGISTRY=""
EXPECTED_SHA256=""
PORT="3494"
DO_APPLY="0"
DRY_RUN="0"

usage() {
  cat <<'EOF'
magpie-simple-share 一键引导脚本 (macOS / Linux · 国内免梯子)

用法:
  ./bootstrap.sh [--invite] <mshare1:...|分享链接> [选项]

选项:
  --invite <str>     邀请码 (mshare1:...) 或完整分享链接（支持位置参数）
  --name <str>       申请时展示给分享方的设备昵称（仅 --apply 时使用）
  --mirror <url>     Magpie 安装包国内镜像基地址（也可设 MAGPIE_DOWNLOAD_MIRROR）
  --registry <url>   覆盖插件 npm 镜像源（默认保留自定义源，否则使用 https://registry.npmmirror.com）
  --sha256 <hex>     可选：显式指定 Magpie 安装包期望 SHA256（64 位十六进制）
  --port <int>       简单分享本地控制面端口（默认 3494）
  --apply            直接通过本机 CLI/回环接口提交申请并醒目打印 4 位配对码 (SAS)
  --dry-run          仅打印执行计划，不下载、不安装、不修改本机配置
  --help, -h         显示本帮助
EOF
}

log_step() { printf '[simple-share] %s\n' "$1"; }
log_warn() { printf '[simple-share] 警告: %s\n' "$1" >&2; }
log_err()  { printf '[simple-share] 错误: %s\n' "$1" >&2; }

validate_http_url() {
  case "$1" in
    http://*|https://*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *" "*|*"	"*|*"'"*|*'"'*|*";"*|*"|"*|*"&"*|*"$"*|*"\`"*|*"<"*|*">"*|*"("*|*")"*) return 1 ;;
    *@*) return 1 ;;
  esac
  return 0
}

extract_invite_code() {
  raw="$1"
  # Decode common URL-encoded colon %3A / %3a without invoking untrusted eval
  decoded=$(printf '%s' "$raw" | sed 's/%3[Aa]/:/g')
  found=$(printf '%s' "$decoded" | grep -Eo 'mshare1:[A-Za-z0-9_-]+' | head -n 1 || true)
  case "$found" in
    mshare1:*)
      # Strict full-string character whitelist validation
      rest=${found#mshare1:}
      if [ -n "$rest" ] && printf '%s' "$rest" | grep -Eq '^[A-Za-z0-9_-]+$'; then
        printf '%s' "$found"
        return 0
      fi
      ;;
  esac
  return 1
}

url_encode_invite() {
  # Only mshare1:[A-Za-z0-9_-]+ reaches here; encode ':' -> '%3A'
  printf '%s' "$1" | sed 's/:/%3A/g'
}

detect_invite_mode_local() {
  code="$1"
  b64u=${code#mshare1:}
  b64=$(printf '%s' "$b64u" | tr '_-' '/+')
  rem=$(( ${#b64} % 4 ))
  if [ "$rem" -eq 2 ]; then b64="${b64}=="; elif [ "$rem" -eq 3 ]; then b64="${b64}="; fi
  payload=""
  if command -v base64 >/dev/null 2>&1; then
    payload=$(printf '%s' "$b64" | base64 -d 2>/dev/null || printf '%s' "$b64" | base64 -D 2>/dev/null || true)
  fi
  mode=$(printf '%s' "$payload" | grep -Eo '"m"[[:space:]]*:[[:space:]]*"[a-z0-9-]+"' | head -n 1 | sed 's/.*"m"[[:space:]]*:[[:space:]]*"\([a-z0-9-]*\)".*/\1/' || true)
  printf '%s' "$mode"
}

find_magpie_bin() {
  for env_bin in "${MAGPIE_BIN:-}" "${SIMPLE_SHARE_MAGPIE_BIN:-}"; do
    if [ -n "$env_bin" ] && [ -x "$env_bin" ]; then
      printf '%s' "$env_bin"
      return 0
    fi
  done
  if command -v magpie >/dev/null 2>&1; then
    command -v magpie
    return 0
  fi
  for p in \
    "$HOME/.local/bin/magpie" \
    "/opt/homebrew/bin/magpie" \
    "/usr/local/bin/magpie" \
    "/usr/bin/magpie" \
    "/Applications/magpie.app/Contents/MacOS/magpie" \
    "/Applications/Magpie.app/Contents/MacOS/magpie" \
    "$HOME/Applications/magpie.app/Contents/MacOS/magpie" \
    "$HOME/Applications/Magpie.app/Contents/MacOS/magpie" \
    "$HOME/.magpie/bin/magpie" \
    "$HOME/bin/magpie"; do
    if [ -x "$p" ]; then
      printf '%s' "$p"
      return 0
    fi
  done
  return 1
}

http_get() {
  url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 10 --max-time 30 "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- --timeout=30 "$url"
  else
    return 127
  fi
}

http_download() {
  url="$1"
  out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 15 --max-time 120 -o "$out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$out" --timeout=120 "$url"
  else
    return 127
  fi
}

compute_sha256() {
  file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print tolower($1)}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$file" | awk '{print tolower($NF)}'
  else
    return 1
  fi
}

show_manual_magpie_guidance() {
  reason="$1"
  cat >&2 <<EOF

================================================================
未自动完成 Magpie 安装（国内免梯子手动安装指南）
原因: ${reason}

1. 前往官网下载安装 Magpie: https://usemagpie.ai
2. 若当前网络访问官网受限，可通过国内镜像重试:
   ./bootstrap.sh --mirror https://<你的国内镜像地址> --invite "<邀请码>"
   或联系分享方通过微信直接发送对应系统的 Magpie 安装包。
3. 安装并启动 Magpie 后，可重新运行本脚本，或手动执行:
   magpie plugin registry ${DEFAULT_REGISTRY}
   magpie plugin add ${PACKAGE_NAME}
================================================================
EOF
}

install_magpie_verified() {
  base_url=$(printf '%s' "$1" | sed 's#/*$##')
  override_sha="$2"

  os_raw=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch_raw=$(uname -m)
  case "$os_raw" in
    darwin) os_tag="darwin" ;;
    linux)  os_tag="linux" ;;
    *) show_manual_magpie_guidance "不支持的操作系统: $os_raw"; return 1 ;;
  esac
  case "$arch_raw" in
    x86_64|amd64)  arch_tag="x64" ;;
    arm64|aarch64) arch_tag="arm64" ;;
    *) show_manual_magpie_guidance "不支持的 CPU 架构: $arch_raw"; return 1 ;;
  esac

  asset="magpie-${os_tag}-${arch_tag}"
  artifact_url="${base_url}/${asset}"
  sums_url="${base_url}/SHA256SUMS.txt"

  tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/magpie-bootstrap.XXXXXX")
  cleanup_tmp() { rm -rf "$tmp_dir"; }
  trap cleanup_tmp EXIT HUP INT TERM

  expected=""
  if [ -n "$override_sha" ]; then
    expected=$(printf '%s' "$override_sha" | tr '[:upper:]' '[:lower:]')
    if ! printf '%s' "$expected" | grep -Eq '^[0-9a-f]{64}$'; then
      show_manual_magpie_guidance "--sha256 必须为 64 位十六进制哈希值"
      return 1
    fi
  else
    log_step "正在获取 SHA256 校验清单: $sums_url"
    sums_body=$(http_get "$sums_url" 2>/dev/null || true)
    if [ -z "$sums_body" ]; then
      show_manual_magpie_guidance "无法下载 SHA256 校验清单（拒绝跳过完整性校验）"
      return 1
    fi
    expected=$(printf '%s\n' "$sums_body" | awk -v target="$asset" '
      $1 ~ /^[0-9a-fA-F]{64}$/ {
        f = $2; sub(/^\*/, "", f); sub(/^.*\//, "", f);
        if (f == target) { print tolower($1); exit }
      }
    ')
    if [ -z "$expected" ]; then
      show_manual_magpie_guidance "校验清单中未找到 ${asset} 的 SHA256 记录，拒绝跳过校验"
      return 1
    fi
  fi

  tmp_bin="${tmp_dir}/${asset}"
  log_step "正在下载 Magpie (${asset})..."
  if ! http_download "$artifact_url" "$tmp_bin"; then
    show_manual_magpie_guidance "下载 ${artifact_url} 失败（可能受国内网络限制）"
    return 1
  fi

  actual=$(compute_sha256 "$tmp_bin" || true)
  if [ -z "$actual" ]; then
    show_manual_magpie_guidance "系统缺少 sha256sum / shasum / openssl，无法完成 SHA256 校验"
    return 1
  fi
  if [ "$actual" != "$expected" ]; then
    rm -f "$tmp_bin"
    show_manual_magpie_guidance "SHA256 校验失败！期望 ${expected}，实际 ${actual}，已删除文件并中止"
    return 1
  fi
  log_step "SHA256 校验通过 (${actual})"

  install_dir="$HOME/.local/bin"
  mkdir -p "$install_dir"
  chmod 0755 "$tmp_bin"
  mv "$tmp_bin" "${install_dir}/magpie"
  log_step "Magpie 已安装至: ${install_dir}/magpie"
  printf '%s' "${install_dir}/magpie"
}

wait_for_health() {
  base="$1"
  max_sec="$2"
  i=0
  while [ "$i" -lt "$max_sec" ]; do
    body=$(http_get "${base}/api/health" 2>/dev/null || true)
    case "$body" in
      *'"ok":true'*|*'"ok": true'*) return 0 ;;
    esac
    sleep 1
    i=$(( i + 1 ))
  done
  return 1
}

read_session_token() {
  base="$1"
  html=$(http_get "${base}/" 2>/dev/null || true)
  # Extract token without printing it
  printf '%s' "$html" \
    | tr '\n' ' ' \
    | sed -n 's/.*<meta[^>]*name=["'\'']simple-share-token["'\''][^>]*content=["'\'']\([^"'\'']*\)["'\''].*/\1/p'
}

json_escape_str() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\r\n' '  '
}

show_sas_box() {
  sas="$1"
  pid="$2"
  spaced=$(printf '%s' "$sas" | sed 's/./& /g; s/ $//')
  printf '\n================================================\n'
  printf '  申请已发送！安全配对码 (SAS):  %s\n' "$spaced"
  if [ -n "$pid" ]; then
    printf '  申请单号: %s\n' "$pid"
  fi
  printf '  请通过微信将以上 4 位数字告知分享方核对并同意。\n'
  printf '================================================\n\n'
}

# ==================== Parse Arguments ====================

while [ "$#" -gt 0 ]; do
  case "$1" in
    --invite)
      [ "$#" -ge 2 ] || { log_err "--invite 需要参数值"; exit 1; }
      INVITE_RAW="$2"; shift 2 ;;
    --invite=*)
      INVITE_RAW=${1#--invite=}; shift ;;
    --name)
      [ "$#" -ge 2 ] || { log_err "--name 需要参数值"; exit 1; }
      DEVICE_NAME="$2"; shift 2 ;;
    --name=*)
      DEVICE_NAME=${1#--name=}; shift ;;
    --mirror)
      [ "$#" -ge 2 ] || { log_err "--mirror 需要参数值"; exit 1; }
      MIRROR="$2"; shift 2 ;;
    --mirror=*)
      MIRROR=${1#--mirror=}; shift ;;
    --registry)
      [ "$#" -ge 2 ] || { log_err "--registry 需要参数值"; exit 1; }
      REGISTRY="$2"; shift 2 ;;
    --registry=*)
      REGISTRY=${1#--registry=}; shift ;;
    --sha256)
      [ "$#" -ge 2 ] || { log_err "--sha256 需要参数值"; exit 1; }
      EXPECTED_SHA256="$2"; shift 2 ;;
    --sha256=*)
      EXPECTED_SHA256=${1#--sha256=}; shift ;;
    --port)
      [ "$#" -ge 2 ] || { log_err "--port 需要参数值"; exit 1; }
      PORT="$2"; shift 2 ;;
    --port=*)
      PORT=${1#--port=}; shift ;;
    --apply)
      DO_APPLY="1"; shift ;;
    --dry-run)
      DRY_RUN="1"; shift ;;
    --help|-h)
      usage; exit 0 ;;
    --)
      shift
      if [ "$#" -gt 0 ] && [ -z "$INVITE_RAW" ]; then INVITE_RAW="$1"; fi
      break ;;
    -*)
      log_err "未知选项: $1"; usage >&2; exit 1 ;;
    *)
      if [ -z "$INVITE_RAW" ]; then INVITE_RAW="$1"; else log_err "多余的参数: $1"; exit 1; fi
      shift ;;
  esac
done

# Validate port strictly (1..65535)
if ! printf '%s' "$PORT" | grep -Eq '^[0-9]+$' || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  log_err "端口必须为 1..65535 整数，当前值: $PORT"
  exit 1
fi

# Validate & extract invite code strictly before any interpolation
INVITE_CODE=""
INVITE_MODE=""
if [ -n "$INVITE_RAW" ]; then
  INVITE_CODE=$(extract_invite_code "$INVITE_RAW" || true)
  if [ -z "$INVITE_CODE" ]; then
    log_err "邀请码格式无效：仅允许标准 mshare1:[A-Za-z0-9_-]+ 邀请码或包含该码的分享链接。"
    exit 1
  fi
  INVITE_MODE=$(detect_invite_mode_local "$INVITE_CODE")
fi

EFFECTIVE_MIRROR="${MIRROR:-${MAGPIE_DOWNLOAD_MIRROR:-$OFFICIAL_RELEASE_BASE}}"
if ! validate_http_url "$EFFECTIVE_MIRROR"; then
  log_err "非法的镜像地址: $EFFECTIVE_MIRROR"
  exit 1
fi

if [ -n "$REGISTRY" ] && ! validate_http_url "$REGISTRY"; then
  log_err "非法的 npm 镜像源地址: $REGISTRY"
  exit 1
fi

LOCAL_BASE="http://127.0.0.1:${PORT}"
if [ -n "$INVITE_CODE" ]; then
  HANDOFF_URL="${LOCAL_BASE}/#invite=$(url_encode_invite "$INVITE_CODE")"
else
  HANDOFF_URL="${LOCAL_BASE}/"
fi

# Step 1: Detect Magpie
log_step "步骤 1/4: 检测本机 Magpie..."
MAGPIE_FOUND=$(find_magpie_bin || true)

if [ "$DRY_RUN" = "1" ]; then
  if [ -n "$MAGPIE_FOUND" ]; then
    log_step "[DRY-RUN] 检测到 Magpie: $MAGPIE_FOUND"
  else
    log_step "[DRY-RUN] 未检测到 Magpie，将从镜像下载并强制校验 SHA256"
  fi
  log_step "[DRY-RUN] 下载基地址: $EFFECTIVE_MIRROR (SHA256 强制校验，绝不上传邀请码)"
  log_step "[DRY-RUN] 步骤 2/4: 检查 magpie plugin list --json，缺失时配置国内镜像 ${REGISTRY:-$DEFAULT_REGISTRY} 并安装 $PACKAGE_NAME"
  if [ "$INVITE_MODE" = "p2p" ]; then
    log_step "[DRY-RUN] 步骤 3/4: 等待本机回环 ${LOCAL_BASE}/api/health 就绪，并按需安装 Mode 1 Iroh (npmmirror + sha512)"
  else
    log_step "[DRY-RUN] 步骤 3/4: 等待本机回环 ${LOCAL_BASE}/api/health 就绪"
  fi
  if [ "$DO_APPLY" = "1" ]; then
    log_step "[DRY-RUN] 步骤 4/4: 将通过本机 CLI/回环接口提交申请并展示 4 位安全配对码 (SAS)"
  else
    log_step "[DRY-RUN] 步骤 4/4: 将在默认浏览器打开 ${HANDOFF_URL} （由用户手动确认 4 项透明说明）"
  fi
  exit 0
fi

if [ -z "$MAGPIE_FOUND" ]; then
  log_warn "本机尚未安装 Magpie，尝试按 SHA256 强校验下载安装..."
  MAGPIE_FOUND=$(install_magpie_verified "$EFFECTIVE_MIRROR" "$EXPECTED_SHA256") || exit 1
else
  log_step "已找到 Magpie: $MAGPIE_FOUND"
fi

# Step 2: Check / install plugin with domestic npmmirror
log_step "步骤 2/4: 检查插件 ${PACKAGE_NAME} ..."
PLUGIN_LIST=$("$MAGPIE_FOUND" plugin list --json 2>/dev/null || "$MAGPIE_FOUND" plugin ls 2>/dev/null || true)
if ! printf '%s' "$PLUGIN_LIST" | grep -q 'simple-share'; then
  TARGET_REGISTRY=""
  if [ -n "$REGISTRY" ]; then
    TARGET_REGISTRY="$REGISTRY"
  else
    CUR_REG=$("$MAGPIE_FOUND" plugin registry 2>/dev/null | tr -d '\r\n' || true)
    case "$CUR_REG" in
      ""|*registry.npmjs.org*)
        TARGET_REGISTRY="$DEFAULT_REGISTRY" ;;
      *)
        log_step "保留已有自定义插件源: $CUR_REG" ;;
    esac
  fi

  if [ -n "$TARGET_REGISTRY" ]; then
    log_step "配置国内插件镜像源: $TARGET_REGISTRY"
    "$MAGPIE_FOUND" plugin registry "$TARGET_REGISTRY"
  fi

  log_step "正在安装插件: ${PACKAGE_NAME} ..."
  if ! "$MAGPIE_FOUND" plugin add "$PACKAGE_NAME"; then
    log_err "插件安装失败，请检查网络或手动执行: magpie plugin add ${PACKAGE_NAME}"
    exit 1
  fi
else
  log_step "已安装 simple-share 插件，跳过重复安装。"
fi

# Ensure Magpie service is running
if ! wait_for_health "$LOCAL_BASE" 2; then
  log_step "正在后台启动 Magpie 服务..."
  ("$MAGPIE_FOUND" serve >/dev/null 2>&1 &)
fi

# Step 3: Wait for loopback health & Mode 1 Iroh check
log_step "步骤 3/4: 等待本地控制面就绪 (${LOCAL_BASE}/api/health)..."
if ! wait_for_health "$LOCAL_BASE" 30; then
  log_err "等待 ${LOCAL_BASE}/api/health 超时。请确认 Magpie 已运行且简单分享插件已启用。"
  exit 1
fi

SESSION_TOKEN=$(read_session_token "$LOCAL_BASE" || true)

if [ "$INVITE_MODE" = "p2p" ] && [ -n "$SESSION_TOKEN" ] && command -v curl >/dev/null 2>&1; then
  STATE_JSON=$(curl -fsS -H "x-simple-share-token: ${SESSION_TOKEN}" "${LOCAL_BASE}/api/state" 2>/dev/null || true)
  if printf '%s' "$STATE_JSON" | grep -Eq '"irohStatus"[^{]*\{[^}]*"supported"[[:space:]]*:[[:space:]]*false'; then
    log_warn "当前平台暂不支持模式 1 (Iroh)，请改用模式 2 自建盲中转或模式 3 公网直连。"
  elif ! printf '%s' "$STATE_JSON" | grep -Eq '"irohStatus"[^{]*\{[^}]*"integrityOk"[[:space:]]*:[[:space:]]*true'; then
    log_step "邀请为模式 1 (P2P)，正在从国内镜像下载并校验 @number0/iroh (sha512)..."
    if curl -fsS -X POST -H "x-simple-share-token: ${SESSION_TOKEN}" "${LOCAL_BASE}/api/network/iroh/install" >/dev/null 2>&1; then
      log_step "P2P 组件 (@number0/iroh) 安装与 sha512 校验完成。"
    else
      log_warn "P2P 组件自动安装失败，可在页面「连接与安全」中手动重试。"
    fi
  else
    log_step "模式 1 P2P 组件 (@number0/iroh) 已就绪。"
  fi
fi

# Step 4: Handoff or --apply
if [ "$DO_APPLY" = "1" ]; then
  if [ -z "$INVITE_CODE" ]; then
    log_err "使用 --apply 必须提供有效的邀请码或分享链接。"
    exit 1
  fi
  log_step "步骤 4/4: 正在通过本机服务提交分享申请..."

  RESP_JSON=""
  if command -v magpie-simple-share >/dev/null 2>&1; then
    if [ -n "$DEVICE_NAME" ]; then
      RESP_JSON=$(magpie-simple-share apply "$INVITE_CODE" --port "$PORT" --name "$DEVICE_NAME" --json)
    else
      RESP_JSON=$(magpie-simple-share apply "$INVITE_CODE" --port "$PORT" --json)
    fi
  else
    if [ -z "$SESSION_TOKEN" ] || ! command -v curl >/dev/null 2>&1; then
      log_err "无法自动提交申请，请在浏览器打开: ${HANDOFF_URL}"
      exit 1
    fi
    if [ -n "$DEVICE_NAME" ]; then
      ESC_NAME=$(json_escape_str "$DEVICE_NAME")
      PAYLOAD="{\"code\":\"${INVITE_CODE}\",\"deviceName\":\"${ESC_NAME}\"}"
    else
      PAYLOAD="{\"code\":\"${INVITE_CODE}\"}"
    fi
    RESP_JSON=$(curl -fsS -X POST \
      -H "x-simple-share-token: ${SESSION_TOKEN}" \
      -H "content-type: application/json" \
      -d "$PAYLOAD" \
      "${LOCAL_BASE}/api/receiver/apply")
  fi

  SAS=$(printf '%s' "$RESP_JSON" | grep -Eo '"sas"[[:space:]]*:[[:space:]]*"[0-9]{4}"' | head -n 1 | sed 's/.*"\([0-9]\{4\}\)".*/\1/' || true)
  PID=$(printf '%s' "$RESP_JSON" | grep -Eo '"id"[[:space:]]*:[[:space:]]*"[^"]+"' | head -n 1 | sed 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || true)
  if [ -n "$SAS" ]; then
    show_sas_box "$SAS" "$PID"
  else
    log_step "申请已提交并生效。"
  fi
  exit 0
fi

log_step "步骤 4/4: 正在打开本机简单分享页面（请核对宿主指纹与 4 项透明说明后再手动确认）..."
log_step "地址: ${HANDOFF_URL}"
if command -v open >/dev/null 2>&1; then
  open "$HANDOFF_URL" || true
elif command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$HANDOFF_URL" >/dev/null 2>&1 || true
else
  log_step "未检测到图形浏览器打开命令，请手动在浏览器访问上述地址。"
fi
exit 0
