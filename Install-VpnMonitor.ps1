#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs (or removes) the scheduled task that runs Check-VpnTunnel.ps1 every N minutes.

.DESCRIPTION
    - Checks that config.env exists (creates it from config.env.example otherwise, then stops).
    - Restricts config.env permissions to SYSTEM and Administrators (it may contain an SMTP password).
    - Registers the task \VpnMonitor\<TaskName>, run as SYSTEM, without any logged-on session.

    The script runs from the folder it is located in: move the folder to its final location
    (e.g. C:\VpnMonitor) before running the installation.

.EXAMPLE
    .\Install-VpnMonitor.ps1
.EXAMPLE
    .\Install-VpnMonitor.ps1 -IntervalMinutes 5 -RunNow
.EXAMPLE
    .\Install-VpnMonitor.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 1440)]
    [int]$IntervalMinutes = 5,
    [string]$TaskName = 'UAG VPN Monitor',
    [switch]$RunNow,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$TaskPath = '\VpnMonitor\'
$Root = $PSScriptRoot
$Script = Join-Path $Root 'Check-VpnTunnel.ps1'
$Config = Join-Path $Root 'config.env'

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Task '$TaskName' removed (logs\ and state\ folders are kept)."
    return
}

if (-not (Test-Path $Script)) { throw "Not found: $Script" }

if (-not (Test-Path $Config)) {
    Copy-Item (Join-Path $Root 'config.env.example') $Config
    Write-Warning "config.env created from the example: fill it in, then run the installation again."
    return
}

# Files copied from the Internet or a network share may be blocked by Windows.
Get-ChildItem -Path $Root -Filter '*.ps1' | Unblock-File

# config.env: access restricted to SYSTEM (S-1-5-18) and Administrators (S-1-5-32-544).
# SIDs rather than names: works whatever the Windows display language.
& icacls.exe $Config /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls failed on $Config" }

foreach ($dir in 'logs', 'state') {
    New-Item -ItemType Directory -Path (Join-Path $Root $dir) -Force | Out-Null
}

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $Script) `
    -WorkingDirectory $Root
# Without RepetitionDuration, the repetition is unlimited (Windows Server 2016 / Windows 10 and later).
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes ([math]::Max(2, $IntervalMinutes - 1))) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force `
    -Description "TCP/TLS health check of Workspace ONE Tunnel gateways, reported to Zabbix and/or by e-mail. Script: $Script" | Out-Null

Write-Host "Task '$TaskPath$TaskName' installed: every $IntervalMinutes min, as SYSTEM."
Write-Host "Logs: $(Join-Path $Root 'logs')"

if ($RunNow) {
    Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
    Write-Host 'Run started, result in ~30 s:'
    Start-Sleep -Seconds 30
    $info = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath $TaskPath
    Write-Host ("Last result: {0} (0 = OK, 1 = target down, 2 = configuration error)" -f $info.LastTaskResult)
    $log = Get-ChildItem (Join-Path $Root 'logs') -Filter 'vpn-monitor-*.log' | Sort-Object LastWriteTime | Select-Object -Last 1
    if ($log) { Get-Content $log.FullName -Tail 10 }
}
