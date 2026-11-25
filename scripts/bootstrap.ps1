<#
.SYNOPSIS
  Domestic no-VPN friendly bootstrap for magpie-simple-share (Windows PowerShell).
.DESCRIPTION
  Idempotently detects/guides Magpie installation (with mandatory SHA256 verification),
  installs @gruu6y/page-simple-share via domestic npmmirror registry, ensures Mode 1
  Iroh component readiness when needed, and hands off the invite code strictly to
  local 127.0.0.1 control plane. Never sends invite codes to any remote server.
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [Alias('Code')]
  [string]$Invite = '',
  [string]$Name = '',
  [string]$Mirror = '',
  [string]$Registry = '',
  [string]$Sha256 = '',
  [int]$Port = 3494,
  [switch]$Apply,
  [switch]$DryRun,
  [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
  [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
} catch {
  # Ignore non-interactive host encoding errors
}

$PackageName = '@gruu6y/page-simple-share'
$DefaultRegistry = 'https://registry.npmmirror.com'
$OfficialReleaseBase = 'https://usemagpie.ai/releases/latest'

function Show-Usage {
  Write-Host @"
magpie-simple-share 一键引导脚本 (Windows PowerShell · 国内免梯子)

用法:
  .\bootstrap.ps1 [-Invite] <mshare1:...|分享链接> [选项]

选项:
  -Invite <str>     邀请码 (mshare1:...) 或完整分享链接（支持位置参数）
  -Name <str>       申请时展示给分享方的设备昵称（仅 -Apply 时使用）
  -Mirror <url>     Magpie 安装包国内镜像基地址（也可设 MAGPIE_DOWNLOAD_MIRROR）
  -Registry <url>   覆盖插件 npm 镜像源（默认保留自定义源，否则使用 https://registry.npmmirror.com）
  -Sha256 <hex>     可选：显式指定 Magpie 安装包期望 SHA256（64 位十六进制）
  -Port <int>       简单分享本地控制面端口（默认 3494）
  -Apply            直接通过本机接口/CLI 提交申请并醒目打印 4 位配对码 (SAS)
  -DryRun           仅打印执行计划，不下载、不安装、不修改本机配置
  -Help             显示本帮助
"@
}

function Write-Step([string]$Msg) {
  Write-Host "[simple-share] $Msg"
}

function Write-WarnLine([string]$Msg) {
  Write-Host "[simple-share] 警告: $Msg" -ForegroundColor Yellow
}

function Write-ErrLine([string]$Msg) {
  Write-Error "[simple-share] 错误: $Msg"
}

function Test-SafeHttpUrl([string]$Raw) {
  if ([string]::IsNullOrWhiteSpace($Raw)) { return $false }
  $t = $Raw.Trim()
  if ($t -match '[\s\r\n\0''"`$;|&<>()]') { return $false }
  try {
    $u = [Uri]$t
    if ($u.Scheme -ne 'http' -and $u.Scheme -ne 'https') { return $false }
    if (-not [string]::IsNullOrEmpty($u.UserInfo)) { return $false }
    return -not [string]::IsNullOrEmpty($u.Host)
  } catch {
    return $false
  }
}

function Get-JsonProp($Obj, [string]$PropName, $Default = $null) {
  if ($null -eq $Obj -or $Obj -is [ValueType] -or $Obj -is [string]) { return $Default }
  $prop = $Obj.PSObject.Properties[$PropName]
  if ($null -eq $prop) { return $Default }
  return $prop.Value
}

function Extract-InviteCode([string]$Raw) {
  if ([string]::IsNullOrWhiteSpace($Raw)) { return '' }
  $s = $Raw.Trim()
  if ($s -match '\s') { return '' }

  $candidate = ''
  if ($s -match '^https?://') {
    $hashIdx = $s.IndexOf('#')
    if ($hashIdx -lt 0 -or $hashIdx -ge ($s.Length - 1)) { return '' }
    $frag = $s.Substring($hashIdx + 1)
    if ($frag -match '(?:^|&)invite=([^&]*)') {
      $candidate = $Matches[1]
    } else {
      $candidate = $frag
    }
    $candidate = [regex]::Replace($candidate, '%3[Aa]', ':')
  } elseif ($s -match '^mshare1(?::|%3[Aa])') {
    $candidate = [regex]::Replace($s, '%3[Aa]', ':')
  } else {
    return ''
  }

  if ($candidate -notmatch '^mshare1:[A-Za-z0-9_-]+$') { return '' }
  return $candidate
}

function Decode-InviteLocal([string]$Code) {
  if ($Code -notmatch '^mshare1:[A-Za-z0-9_-]+$') { return $null }
  try {
    $b64 = $Code.Substring(8).Replace('-', '+').Replace('_', '/')
    $mod = $b64.Length % 4
    if ($mod -gt 0) { $b64 += ('=' * (4 - $mod)) }
    $bytes = [Convert]::FromBase64String($b64)
    $json = [System.Text.Encoding]::UTF8.GetString($bytes)
    return ($json | ConvertFrom-Json)
  } catch {
    return $null
  }
}

function Find-MagpieBinary {
  foreach ($envKey in @('MAGPIE_BIN', 'SIMPLE_SHARE_MAGPIE_BIN')) {
    $val = [Environment]::GetEnvironmentVariable($envKey)
    if (-not [string]::IsNullOrWhiteSpace($val) -and (Test-Path -LiteralPath $val.Trim())) {
      return $val.Trim()
    }
  }
  $cmd = Get-Command magpie -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($cmd -and $cmd.Source -and (Test-Path -LiteralPath $cmd.Source)) {
    return $cmd.Source
  }
  $candidates = @()
  if ($env:LOCALAPPDATA) {
    $candidates += (Join-Path $env:LOCALAPPDATA 'Programs\magpie\magpie.exe')
  }
  if ($env:USERPROFILE) {
    $candidates += (Join-Path $env:USERPROFILE 'AppData\Local\Programs\magpie\magpie.exe')
    $candidates += (Join-Path $env:USERPROFILE '.magpie\bin\magpie.exe')
  }
  if ($env:ProgramFiles) {
    $candidates += (Join-Path $env:ProgramFiles 'magpie\magpie.exe')
  }
  foreach ($c in $candidates) {
    if ($c -and (Test-Path -LiteralPath $c)) { return $c }
  }
  return ''
}

function Show-ManualMagpieGuidance([string]$Reason) {
  Write-Host ''
  Write-Host '================================================================' -ForegroundColor Yellow
  Write-Host '未自动完成 Magpie 安装（国内免梯子手动安装指南）' -ForegroundColor Yellow
  if ($Reason) { Write-Host "原因: $Reason" }
  Write-Host ''
  Write-Host '1. 官网下载 Magpie Windows 安装包: https://usemagpie.ai'
  Write-Host '2. 若官网访问缓慢，可使用镜像重新运行本脚本:'
  Write-Host '   .\bootstrap.ps1 -Mirror https://<你的国内镜像地址> -Invite "<邀请码>"'
  Write-Host '   或让分享方通过微信直接发送 Magpie 安装包给你离线安装。'
  Write-Host '3. 安装并打开 Magpie 后，重新运行本脚本，或在终端手动执行:'
  Write-Host "   magpie plugin registry $DefaultRegistry"
  Write-Host "   magpie plugin add $PackageName"
  Write-Host '================================================================' -ForegroundColor Yellow
}

function Install-MagpieVerified([string]$BaseUrl, [string]$ExpectedSha256) {
  $arch = if ([Environment]::Is64BitOperatingSystem) {
    if ($env:PROCESSOR_ARCHITECTURE -match 'ARM64') { 'win32-arm64' } else { 'win32-x64' }
  } else {
    'win32-x64'
  }
  $assetName = "magpie-$arch.exe"
  $cleanBase = $BaseUrl.TrimEnd('/')
  $artifactUrl = "$cleanBase/$assetName"
  $sumsUrl = "$cleanBase/SHA256SUMS.txt"

  $tmpDir = Join-Path ([IO.Path]::GetTempPath()) ("magpie-bootstrap-" + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
  $tmpFile = Join-Path $tmpDir $assetName

  try {
    $expected = ''
    if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
      $expected = $ExpectedSha256.Trim().ToLowerInvariant()
      if ($expected -notmatch '^[0-9a-f]{64}$') {
        throw '参数 -Sha256 必须为 64 位十六进制 SHA256 校验值。'
      }
    } else {
      Write-Step "正在获取 SHA256 校验清单: $sumsUrl"
      $sumsResp = Invoke-WebRequest -UseBasicParsing -Uri $sumsUrl -TimeoutSec 20
      foreach ($line in ($sumsResp.Content -split "`r?`n")) {
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$') {
          $hashVal = $Matches[1].ToLowerInvariant()
          $fileRef = [IO.Path]::GetFileName($Matches[2].Trim())
          if ($fileRef -eq $assetName) {
            $expected = $hashVal
            break
          }
        }
      }
      if ([string]::IsNullOrEmpty($expected)) {
        throw "校验清单中未找到 $assetName 的 SHA256 记录，拒绝跳过校验。"
      }
    }

    Write-Step "正在下载 Magpie ($assetName)..."
    Invoke-WebRequest -UseBasicParsing -Uri $artifactUrl -OutFile $tmpFile -TimeoutSec 60

    $actual = (Get-FileHash -LiteralPath $tmpFile -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
      throw "SHA256 校验失败！期望 $expected，实际 $actual，已中止安装。"
    }
    Write-Step "SHA256 校验通过 ($actual)"

    $installDir = Join-Path $env:LOCALAPPDATA 'Programs\magpie'
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    $destBin = Join-Path $installDir 'magpie.exe'
    Move-Item -LiteralPath $tmpFile -Destination $destBin -Force
    Write-Step "Magpie 已安装至: $destBin"
    return $destBin
  } finally {
    if (Test-Path -LiteralPath $tmpDir) {
      Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}

function Get-ControlPlaneToken([string]$BaseUrl) {
  $resp = Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/" -TimeoutSec 5
  $m = [regex]::Match($resp.Content, '<meta\b[^>]*name=["'']simple-share-token["''][^>]*content=["'']([^"'']+)["'']', 'IgnoreCase')
  if ($m.Success) { return $m.Groups[1].Value }
  $m2 = [regex]::Match($resp.Content, '<meta\b[^>]*content=["'']([^"'']+)["''][^>]*name=["'']simple-share-token["'']', 'IgnoreCase')
  if ($m2.Success) { return $m2.Groups[1].Value }
  return ''
}

function Wait-ForHealth([string]$BaseUrl, [int]$MaxSec = 30) {
  for ($i = 0; $i -lt $MaxSec; $i++) {
    try {
      $res = Invoke-RestMethod -Uri "$BaseUrl/api/health" -Method Get -TimeoutSec 2
      if ((Get-JsonProp $res 'ok' $false) -eq $true) { return $true }
    } catch { }
    Start-Sleep -Seconds 1
  }
  return $false
}

function Show-SasBox([string]$Sas, [string]$PendingId) {
  $spaced = ($Sas.ToCharArray() -join ' ')
  Write-Host ''
  Write-Host '================================================' -ForegroundColor Green
  Write-Host "  申请已发送！安全配对码 (SAS):  $spaced" -ForegroundColor Green
  if ($PendingId) { Write-Host "  申请单号: $PendingId" }
  Write-Host '  请通过微信将以上 4 位数字告知分享方核对并同意。'
  Write-Host '================================================' -ForegroundColor Green
  Write-Host ''
}

# ==================== Main ====================

if ($Help) {
  Show-Usage
  exit 0
}

if ($Port -lt 1 -or $Port -gt 65535) {
  Write-ErrLine "端口必须在 1..65535 之间，当前值: $Port"
  exit 1
}

$InviteCode = ''
$InviteMeta = $null
if (-not [string]::IsNullOrWhiteSpace($Invite)) {
  $InviteCode = Extract-InviteCode $Invite
  if ([string]::IsNullOrEmpty($InviteCode)) {
    Write-ErrLine '邀请码格式无效：仅允许标准 mshare1:[A-Za-z0-9_-]+ 邀请码或包含该码的分享链接。'
    exit 1
  }
  $InviteMeta = Decode-InviteLocal $InviteCode
}

$EffectiveMirror = if (-not [string]::IsNullOrWhiteSpace($Mirror)) {
  $Mirror.Trim()
} elseif (-not [string]::IsNullOrWhiteSpace($env:MAGPIE_DOWNLOAD_MIRROR)) {
  $env:MAGPIE_DOWNLOAD_MIRROR.Trim()
} else {
  $OfficialReleaseBase
}
if (-not (Test-SafeHttpUrl $EffectiveMirror)) {
  Write-ErrLine "非法的镜像地址: $EffectiveMirror"
  exit 1
}

if (-not [string]::IsNullOrWhiteSpace($Registry) -and -not (Test-SafeHttpUrl $Registry)) {
  Write-ErrLine "非法的 npm 镜像源地址: $Registry"
  exit 1
}

$LocalBase = "http://127.0.0.1:$Port"
$HandoffUrl = if ($InviteCode) {
  "$LocalBase/#invite=$([Uri]::EscapeDataString($InviteCode))"
} else {
  "$LocalBase/"
}
$InviteMode = [string](Get-JsonProp $InviteMeta 'm' '')

# Step 1: Detect Magpie
Write-Step '步骤 1/4: 检测本机 Magpie...'
$MagpieBin = Find-MagpieBinary
if ($DryRun) {
  Write-Step "[DRY-RUN] 检测到 Magpie: $(if ($MagpieBin) { $MagpieBin } else { '(未安装，将从镜像下载并强制校验 SHA256)' })"
  Write-Step "[DRY-RUN] 下载基地址: $EffectiveMirror (SHA256 强制校验，绝不上传邀请码)"
  Write-Step "[DRY-RUN] 步骤 2/4: 检查 magpie plugin list --json，缺失时配置国内镜像 $(if ($Registry) { $Registry.Trim() } else { $DefaultRegistry }) 并安装 $PackageName"
  Write-Step "[DRY-RUN] 步骤 3/4: 等待本机回环 $LocalBase/api/health 就绪$(if ($InviteMode -eq 'p2p') { '，并检查/按需安装 Mode 1 Iroh (npmmirror + sha512)' } else { '' })"
  if ($Apply) {
    Write-Step "[DRY-RUN] 步骤 4/4: 将通过本机回环提交申请并展示 4 位安全配对码 (SAS)"
  } else {
    Write-Step "[DRY-RUN] 步骤 4/4: 将在默认浏览器打开 $HandoffUrl （由用户手动确认 4 项透明说明）"
  }
  exit 0
}

if (-not $MagpieBin) {
  Write-WarnLine '本机尚未安装 Magpie，尝试按 SHA256 强校验下载安装...'
  try {
    $MagpieBin = Install-MagpieVerified -BaseUrl $EffectiveMirror -ExpectedSha256 $Sha256
  } catch {
    Show-ManualMagpieGuidance $_.Exception.Message
    exit 1
  }
} else {
  Write-Step "已找到 Magpie: $MagpieBin"
}

# Step 2: Check / install @gruu6y/page-simple-share using domestic mirror
Write-Step "步骤 2/4: 检查插件 $PackageName ..."
$pluginListRaw = ''
try {
  $pluginListRaw = (& $MagpieBin plugin list --json 2>$null) -join "`n"
} catch {
  try { $pluginListRaw = (& $MagpieBin plugin ls 2>$null) -join "`n" } catch { $pluginListRaw = '' }
}

if ($pluginListRaw -notmatch 'simple-share') {
  $targetRegistry = ''
  if (-not [string]::IsNullOrWhiteSpace($Registry)) {
    $targetRegistry = $Registry.Trim()
  } else {
    $currentReg = ''
    try { $currentReg = ((& $MagpieBin plugin registry 2>$null) -join '').Trim() } catch { $currentReg = '' }
    if ([string]::IsNullOrWhiteSpace($currentReg) -or $currentReg -match 'registry\.npmjs\.org') {
      $targetRegistry = $DefaultRegistry
    } else {
      Write-Step "保留已有自定义插件源: $currentReg"
    }
  }

  if ($targetRegistry) {
    Write-Step "配置国内插件镜像源: $targetRegistry"
    & $MagpieBin plugin registry $targetRegistry
  }

  Write-Step "正在安装插件: $PackageName ..."
  & $MagpieBin plugin add $PackageName
  if ($LASTEXITCODE -ne 0) {
    Write-ErrLine "插件安装失败，请确认网络后重试或手动执行: magpie plugin add $PackageName"
    exit 1
  }
} else {
  Write-Step '已安装 simple-share 插件，跳过重复安装。'
}

# Ensure Magpie is running
$healthReady = Wait-ForHealth -BaseUrl $LocalBase -MaxSec 2
if (-not $healthReady) {
  Write-Step '正在启动 Magpie 本地服务...'
  Start-Process -FilePath $MagpieBin -ArgumentList 'serve' -WindowStyle Hidden
}

# Step 3: Wait for loopback /api/health and optional Mode 1 Iroh install
Write-Step "步骤 3/4: 等待本地控制面就绪 ($LocalBase/api/health)..."
if (-not (Wait-ForHealth -BaseUrl $LocalBase -MaxSec 30)) {
  Write-ErrLine "等待 $LocalBase/api/health 超时。请打开 Magpie 应用并确认简单分享插件已启用。"
  exit 1
}

$SessionToken = Get-ControlPlaneToken -BaseUrl $LocalBase

if ($InviteMode -eq 'p2p' -and $SessionToken) {
  try {
    $headers = @{ 'x-simple-share-token' = $SessionToken }
    $st = Invoke-RestMethod -Uri "$LocalBase/api/state" -Headers $headers -Method Get -TimeoutSec 5
    $iroh = Get-JsonProp $st 'irohStatus' $null
    $irohSupported = Get-JsonProp $iroh 'supported' $null
    $irohInstalled = Get-JsonProp $iroh 'installed' $false
    $irohIntegrity = Get-JsonProp $iroh 'integrityOk' $false
    if ($irohSupported -eq $false) {
      Write-WarnLine '当前设备架构不支持模式 1 (Iroh)，请改用模式 2 自建中转或模式 3 直连。'
    } elseif (-not ($irohInstalled -eq $true -and $irohIntegrity -eq $true)) {
      Write-Step '邀请为模式 1 (P2P)，正在通过国内镜像按需下载并校验 @number0/iroh (sha512)...'
      $installRes = Invoke-RestMethod -Uri "$LocalBase/api/network/iroh/install" -Headers $headers -Method Post -TimeoutSec 180
      if ((Get-JsonProp $installRes 'ok' $false) -eq $true) {
        Write-Step 'P2P 组件 (@number0/iroh) 安装与 sha512 校验完成。'
      } else {
        Write-WarnLine 'P2P 组件安装未返回成功状态，可在页面「连接与安全」手动重试。'
      }
    } else {
      Write-Step '模式 1 P2P 组件 (@number0/iroh) 已就绪。'
    }
  } catch {
    Write-WarnLine "检查/安装 P2P 组件时出现异常: $($_.Exception.Message)"
  }
}

# Step 4: Handoff to browser OR --apply via local loopback
if ($Apply) {
  if ([string]::IsNullOrEmpty($InviteCode)) {
    Write-ErrLine '使用 -Apply 必须提供有效的邀请码或分享链接。'
    exit 1
  }
  Write-Step '步骤 4/4: 正在通过本机服务提交分享申请...'

  $cliCmd = Get-Command magpie-simple-share -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($cliCmd -and $cliCmd.Source) {
    $cliArgs = @('apply', $InviteCode, '--port', "$Port", '--json')
    if (-not [string]::IsNullOrWhiteSpace($Name)) {
      $cliArgs += @('--name', $Name.Trim())
    }
    $out = (& $cliCmd.Source @cliArgs) -join "`n"
    if ($LASTEXITCODE -ne 0) {
      Write-ErrLine "本机 CLI 提交申请失败: $out"
      exit 1
    }
    $parsed = $out | ConvertFrom-Json
    $pendingObj = Get-JsonProp $parsed 'pending' $null
    $pendingSas = [string](Get-JsonProp $pendingObj 'sas' '')
    $pendingId = [string](Get-JsonProp $pendingObj 'id' '')
    if (-not [string]::IsNullOrEmpty($pendingSas)) {
      Show-SasBox -Sas $pendingSas -PendingId $pendingId
    } else {
      Write-Step '申请已提交并生效。'
    }
    exit 0
  }

  if (-not $SessionToken) {
    Write-ErrLine "无法读取本机控制面会话令牌，请直接在浏览器打开: $HandoffUrl"
    exit 1
  }
  $bodyObj = @{ code = $InviteCode }
  if (-not [string]::IsNullOrWhiteSpace($Name)) {
    $bodyObj.deviceName = $Name.Trim()
  }
  $applyRes = Invoke-RestMethod `
    -Uri "$LocalBase/api/receiver/apply" `
    -Headers @{ 'x-simple-share-token' = $SessionToken; 'Content-Type' = 'application/json; charset=utf-8' } `
    -Method Post `
    -Body ($bodyObj | ConvertTo-Json -Compress) `
    -TimeoutSec 30

  $applyPending = Get-JsonProp $applyRes 'pending' $null
  $applySas = [string](Get-JsonProp $applyPending 'sas' '')
  $applyPendingId = [string](Get-JsonProp $applyPending 'id' '')
  if (-not [string]::IsNullOrEmpty($applySas)) {
    Show-SasBox -Sas $applySas -PendingId $applyPendingId
  } else {
    Write-Step '申请已提交并生效。'
  }
  exit 0
}

Write-Step "步骤 4/4: 正在打开本机简单分享页面（请核对宿主指纹与 4 项透明说明后再手动确认）..."
Write-Step "地址: $HandoffUrl"
Start-Process $HandoffUrl
exit 0
