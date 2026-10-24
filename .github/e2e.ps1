# End-to-end test on a Windows CI runner (see e2e.sh): the one-command
# installer with a real Wazuh agent, the Windows service (start, SCM
# restart), an idempotent re-run, uninstall.
param([string]$Dist, [string]$Version)
# Native stderr must not abort the script (Windows PowerShell 5.1).
$ErrorActionPreference = 'Continue'
function Check($ok, [string]$what) { if (-not $ok) { throw "e2e: $what" } }

try {
    $Dist = (Resolve-Path $Dist).Path
    $sums = Get-ChildItem "$Dist\harrier-*" | ForEach-Object {
        '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
    }
    Set-Content "$Dist\SHA256SUMS" $sums -Encoding Ascii
    $base = ([Uri]$Dist).AbsoluteUri
    $install = [scriptblock]::Create((Get-Content install.ps1 -Raw))

    & $install -Manager 127.0.0.1 -Group default -WazuhVersion $Version -BaseUrl $base
    Check ((Get-Service harrier).Status -eq 'Running') 'harrier service is not running'
    $harrier = "$env:ProgramFiles\Harrier\harrier.exe"
    $name = (& $harrier name | Out-String).Trim()
    $conf = Get-Content "${env:ProgramFiles(x86)}\ossec-agent\ossec.conf" -Raw
    Check ($name -match '-[0-9a-f]{12}-[0-9a-f]{12}$') "unexpected agent name $name"
    Check ($conf.Contains("<agent_name>$name</agent_name>")) "agent_name is not $name"
    Check ($conf.Contains('<label key="harrier_hwid">')) 'harrier_hwid label missing'

    Restart-Service harrier
    Check ((Get-Service harrier).Status -eq 'Running') 'harrier service did not come back'
    $rejected = $false
    try { & $install -WazuhVersion 5.0.0 -BaseUrl $base } catch { $rejected = $true }
    Check $rejected 'Wazuh agent 5.x was accepted'
    & $install -WazuhVersion $Version -BaseUrl $base # same version again: no-op
    Check ((Get-Service harrier).Status -eq 'Running') 'harrier service not running after re-run'
    & $harrier status

    & $harrier uninstall
    Check ($LASTEXITCODE -eq 0) 'harrier uninstall failed'
    $svc = Get-Service harrier -ErrorAction SilentlyContinue
    Check (-not $svc -or $svc.Status -ne 'Running') 'harrier is still running after uninstall'
} catch {
    $msg = ($_ | Out-String) -replace '%', '%25' -replace "`r?`n", '%0A'
    Write-Host "::error title=Windows end-to-end test failed::$msg"
    exit 1
}
