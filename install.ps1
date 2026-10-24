# Harrier one-command installer for Windows (x64 / x86). In an elevated
# PowerShell (3.0+; Windows 7 / 2008 R2 need WMF 5.1):
#
#   [Net.ServicePointManager]::SecurityProtocol = 3072; & ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://github.com/omidiyanto/harrier/releases/latest/download/install.ps1'))) -Manager 10.0.0.5 -Group windows -WazuhVersion 4.14.9
#
# Downloads Harrier (verified against SHA256SUMS) and, when needed, the official
# Wazuh agent MSI, then runs `harrier setup`. Re-running it is safe: it installs,
# upgrades or does nothing.
param(
    # Wazuh manager address (needed when the agent gets installed).
    [string]$Manager,
    # Wazuh agent group(s), comma separated.
    [string]$Group,
    # Wazuh agent to install/upgrade to: 4.x up to 4.14, not newer than the
    # manager; optional when the agent is already installed.
    [string]$WazuhVersion,
    # Enrollment password, if the manager requires one.
    [string]$RegistrationPassword,
    # Mirror of the Harrier release files (https:// or file://).
    [string]$BaseUrl = 'https://github.com/omidiyanto/harrier/releases/latest/download',
    # Mirror of packages.wazuh.com (same layout).
    [string]$WazuhPackagesUrl = 'https://packages.wazuh.com'
)
$ErrorActionPreference = 'Stop'

# throw, not exit: this script usually runs inside the admin's own session.
function Fail([string]$Message) { throw "harrier install: $Message" }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'run PowerShell as Administrator'
}
if ($WazuhVersion -and $WazuhVersion -notmatch '^4\.([0-9]|1[0-4])\.[0-9]+(-[0-9]+)?$') {
    Fail "unsupported -WazuhVersion ${WazuhVersion}: use a full 4.x version up to 4.14, e.g. 4.14.9 (5.x is untested)"
}
# TLS 1.2 for GitHub and packages.wazuh.com on older Windows/.NET defaults.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072

$x64 = ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64') -or ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64')
$asset = if ($x64) { 'harrier-windows-x86_64.exe' } else { 'harrier-windows-i686.exe' }

$tmp = Join-Path $env:TEMP ('harrier-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $web = New-Object Net.WebClient
    function Get-File([string]$Url, [string]$Path) {
        try { $web.DownloadFile($Url, $Path) } catch { Fail "download failed: $Url ($($_.Exception.Message))" }
    }
    function Get-Sha256([string]$Path) {
        $sha = [Security.Cryptography.SHA256]::Create()
        $stream = [IO.File]::OpenRead($Path)
        try { ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLower() }
        finally { $stream.Dispose() }
    }

    $exe = Join-Path $tmp $asset
    Get-File "$BaseUrl/SHA256SUMS" (Join-Path $tmp 'SHA256SUMS')
    Get-File "$BaseUrl/$asset" $exe
    $sums = Get-Content (Join-Path $tmp 'SHA256SUMS') | Out-String
    if (-not ($sums -match "(?m)^([0-9a-f]{64})\s+\*?$([regex]::Escape($asset))\s*$") -or (Get-Sha256 $exe) -ne $Matches[1]) {
        Fail "$asset does not match SHA256SUMS"
    }

    $setup = @('setup')
    if ($Manager) { $setup += @('--manager', $Manager) }
    if ($Group) { $setup += @('--group', $Group) }
    if ($WazuhVersion) {
        $full = if ($WazuhVersion -match '-') { $WazuhVersion } else { "$WazuhVersion-1" }
        $major = $full.Split('.')[0]
        $msi = Join-Path $tmp "wazuh-agent-$full.msi"
        $url = "$WazuhPackagesUrl/$major.x/windows/wazuh-agent-$full.msi"
        Write-Host "harrier install: downloading $url"
        Get-File $url $msi
        $setup += @('--package', $msi)
    }

    if ($RegistrationPassword) { $env:WAZUH_REGISTRATION_PASSWORD = $RegistrationPassword }
    # harrier logs to stderr; Windows PowerShell 5.1 turns that into errors
    # when output is redirected (GPO, Intune, CI), so judge by exit code only.
    $ErrorActionPreference = 'Continue'
    & $exe @setup
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    Remove-Item Env:WAZUH_REGISTRATION_PASSWORD -ErrorAction SilentlyContinue
    if ($code -ne 0) { Fail "harrier setup failed (exit code $code)" }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
