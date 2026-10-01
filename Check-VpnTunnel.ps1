#Requires -Version 5.1
<#
.SYNOPSIS
    Health check for Workspace ONE Tunnel gateways (UAG): TCP connection (direct or through an HTTP proxy) + TLS handshake.

.DESCRIPTION
    On each run:
      - (if PROXY is set) checks that the proxy answers, then goes through CONNECT for every target;
      - tests every target: TCP then TLS handshake, with RETRIES attempts;
      - ZABBIX_ENABLED=true: writes the results to ZABBIX_FILE (JSON read by the Zabbix agent);
      - MAIL_ENABLED=true  : sends an e-mail on OK -> KO, a reminder every REMINDER_MINUTES while down,
                             on KO -> OK, and when a certificate is about to expire (once a day).

    Configuration : config.env next to the script (environment variables with the same name take precedence).
    Logs          : logs\vpn-monitor-YYYY-MM.log
    Mail state    : state\state.json

    Status values: 1 = OK, 0 = KO, 2 = not tested (proxy unreachable) / proxy not used.
    Exit code: 0 all OK, 1 at least one KO (target, proxy or mail delivery), 2 configuration/unexpected error.

    Works with Windows PowerShell 5.1 and PowerShell 7+, no external module.

.PARAMETER ConfigFile
    Path of the configuration file (default: config.env next to the script).

.PARAMETER ExtraTarget
    Additional target(s) for a one-off test, e.g. 10.255.255.1:443 (simulates an outage).

.PARAMETER DryRun
    Prints the e-mail instead of sending it, does not write the state (unless -StateFile is given) and writes the
    Zabbix JSON to zabbix.dryrun.json (not read by Zabbix) instead of ZABBIX_FILE.

.PARAMETER StateFile
    Path of the mail state file (default: state\state.json next to the script).

.EXAMPLE
    .\Check-VpnTunnel.ps1 -DryRun
.EXAMPLE
    .\Check-VpnTunnel.ps1 -DryRun -ExtraTarget 10.255.255.1:443
#>
[CmdletBinding()]
param(
    [string]$ConfigFile = (Join-Path $PSScriptRoot 'config.env'),
    [string]$ExtraTarget = '',
    [switch]$DryRun,
    [string]$StateFile = (Join-Path $PSScriptRoot 'state\state.json')
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$Invariant = [Globalization.CultureInfo]::InvariantCulture
$LogDir = Join-Path $PSScriptRoot 'logs'
$RunWatch = [Diagnostics.Stopwatch]::StartNew()
$StateFileGiven = $PSBoundParameters.ContainsKey('StateFile')

# --------------------------------------------------------------------------- helpers

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    Add-Content -Path (Join-Path $LogDir ('vpn-monitor-{0}.log' -f (Get-Date -Format 'yyyy-MM'))) -Value $line -Encoding UTF8
}

function Format-Iso([datetime]$Date) {
    $Date.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", $Invariant)
}

function ConvertTo-Utc($Value) {
    # PowerShell 7 automatically turns ISO dates from JSON into [datetime], 5.1 does not.
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    [datetime]::ParseExact([string]$Value, "yyyy-MM-dd'T'HH:mm:ss'Z'", $Invariant,
        [Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal')
}

function Get-InnerMessage($ErrorRecord) {
    $e = $ErrorRecord.Exception
    while ($e.InnerException) { $e = $e.InnerException }
    $e.Message
}

function New-Result([int]$Status, [string]$Detail, [int]$LatencyMs = -1, [string]$TlsVersion = '', $NotAfter = $null) {
    [pscustomobject]@{ Status = $Status; Detail = $Detail; LatencyMs = $LatencyMs; TlsVersion = $TlsVersion; NotAfter = $NotAfter }
}

# --------------------------------------------------------------------------- configuration

function Read-ConfigFile([string]$Path) {
    $cfg = @{}
    if (Test-Path $Path) {
        foreach ($line in Get-Content -Path $Path -Encoding UTF8) {
            $l = $line.Trim()
            if (-not $l -or $l.StartsWith('#') -or -not $l.Contains('=')) { continue }
            $k, $v = $l -split '=', 2
            $cfg[$k.Trim()] = $v.Trim().Trim('"').Trim("'")
        }
    }
    $cfg
}

$FileConfig = Read-ConfigFile $ConfigFile

function Get-Setting([string]$Name, [string]$Default = '') {
    $fromEnv = [Environment]::GetEnvironmentVariable($Name)
    if ($fromEnv -and $fromEnv.Trim()) { return $fromEnv.Trim() }
    if ($FileConfig.ContainsKey($Name) -and $FileConfig[$Name]) { return $FileConfig[$Name] }
    $Default
}

function ConvertTo-Endpoint([string]$Item, [int]$DefaultPort) {
    if ($Item -match '^(?:\[(?<h>[^\]]+)\]|(?<h>[^:]+)):(?<p>\d+)$') {
        $h = $Matches['h']; $p = [int]$Matches['p']
    } else {
        $h = $Item.Trim('[', ']'); $p = $DefaultPort
    }
    [pscustomobject]@{ Host = $h; Port = $p; Key = '{0}:{1}' -f $h, $p }
}

function ConvertTo-Targets([string]$Raw) {
    $list = @()
    foreach ($item in ($Raw -split '[,;\s]+')) {
        if ($item) { $list += ConvertTo-Endpoint $item 443 }
    }
    $list
}

# --------------------------------------------------------------------------- Zabbix export

# Read by the Zabbix agent (vfs.file.contents): atomic write, UTF-8 without BOM.
function Write-ZabbixFile($Data) {
    if (-not $ZabbixEnabled) { return }
    $path = if ($DryRun) { Join-Path (Split-Path -Parent $ZabbixFile) 'zabbix.dryrun.json' } else { $ZabbixFile }
    $dir = Split-Path -Parent $path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $json = $Data | ConvertTo-Json -Depth 5 -Compress
    $tmp = $path + '.tmp'
    [IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding $false))
    for ($i = 1; $i -le 5; $i++) {
        try { Move-Item -Path $tmp -Destination $path -Force; break }
        catch { if ($i -eq 5) { throw } ; Start-Sleep -Milliseconds 300 }   # file currently being read by the agent
    }
    if ($DryRun) { Write-Host "Zabbix JSON (dry-run): $path`n$json" }
}

# Base settings, also needed when the configuration is invalid.
$ZabbixEnabled = (Get-Setting 'ZABBIX_ENABLED' 'true') -eq 'true'
$ZabbixFile = Get-Setting 'ZABBIX_FILE' (Join-Path $PSScriptRoot 'state\zabbix.json')

function Exit-ConfigError([string]$Message) {
    Write-Log $Message 'ERROR'
    try {
        Write-ZabbixFile ([ordered]@{
            timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); probe = [Environment]::MachineName
            duration_ms = [int]$RunWatch.ElapsedMilliseconds; probe_error = $Message
            proxy = [ordered]@{ enabled = 0; address = ''; status = 2; error = '' }; targets = @()
        })
    } catch { Write-Log ('Cannot write the Zabbix file: ' + (Get-InnerMessage $_)) 'ERROR' }
    exit 2
}

# --------------------------------------------------------------------------- network tests

function Connect-Tcp([string]$HostName, [int]$Port, [int]$TimeoutMs) {
    # Returns the connected TcpClient, or throws an exception with a readable message.
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $task = $tcp.ConnectAsync($HostName, $Port)
        if (-not $task.Wait($TimeoutMs)) { throw ('timeout ({0} s)' -f ($TimeoutMs / 1000)) }
        $tcp.ReceiveTimeout = $TimeoutMs     # applies to synchronous reads/writes (CONNECT + handshake)
        $tcp.SendTimeout = $TimeoutMs
        return $tcp
    } catch {
        $tcp.Dispose()
        throw (Get-InnerMessage $_)
    }
}

function Read-ProxyResponse($Stream) {
    # Reads the CONNECT response headers byte by byte, without consuming the start of the TLS stream.
    $sb = New-Object Text.StringBuilder
    while ($sb.Length -lt 16384) {
        $b = $Stream.ReadByte()
        if ($b -lt 0) { break }
        [void]$sb.Append([char]$b)
        if ($sb.Length -ge 4 -and $sb.ToString($sb.Length - 4, 4) -eq "`r`n`r`n") { break }
    }
    $sb.ToString()
}

function Test-TlsEndpoint($Target) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $tcp = $null; $ssl = $null
    try {
        if ($Proxy) {
            try { $tcp = Connect-Tcp $Proxy.Host $Proxy.Port $TimeoutMs }
            catch { return New-Result 0 ('Proxy TCP connect failed: ' + $_.Exception.Message) }
            $stream = $tcp.GetStream()
            $authority = if ($Target.Host.Contains(':')) { '[{0}]:{1}' -f $Target.Host, $Target.Port } else { $Target.Key }
            $request = "CONNECT $authority HTTP/1.1`r`nHost: $authority`r`nProxy-Connection: Keep-Alive`r`n`r`n"
            try {
                $bytes = [Text.Encoding]::ASCII.GetBytes($request)
                $stream.Write($bytes, 0, $bytes.Length)
                $response = Read-ProxyResponse $stream
            } catch {
                # Typically: the proxy is still waiting for the target beyond TIMEOUT (target unreachable).
                return New-Result 0 ('Proxy: no answer to CONNECT within {0} s, target unreachable? ({1})' -f ($TimeoutMs / 1000), (Get-InnerMessage $_))
            }
            $code = if ($response -match '^HTTP/\d(?:\.\d)?\s+(\d{3})') { [int]$Matches[1] } else { 0 }
            if ($code -ne 200) {
                $why = switch ($code) {
                    0       { 'invalid response' }
                    403     { 'CONNECT denied by the proxy (403)' }
                    407     { 'proxy authentication required (407)' }
                    502     { 'target unreachable from the proxy (502)' }
                    503     { 'target or proxy unavailable (503)' }
                    504     { 'timeout between the proxy and the target (504)' }
                    default { "HTTP response $code" }
                }
                return New-Result 0 "Proxy: $why"
            }
        } else {
            try { $tcp = Connect-Tcp $Target.Host $Target.Port $TimeoutMs }
            catch { return New-Result 0 ('TCP connect failed: ' + $_.Exception.Message) }
            $stream = $tcp.GetStream()
        }

        try {
            # The target is an IP address: the certificate is not validated, only service availability is tested.
            $accept = [System.Net.Security.RemoteCertificateValidationCallback] { param($s, $c, $ch, $e) $true }
            $ssl = New-Object System.Net.Security.SslStream($stream, $false, $accept)
            $targetHost = if ($Sni) { $Sni } else { $Target.Host }
            $ssl.AuthenticateAsClient($targetHost, $null, $TlsProtocols, $false)
            $ms = [int]$sw.ElapsedMilliseconds
            $notAfter = $null
            if ($ssl.RemoteCertificate) {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $ssl.RemoteCertificate
                $notAfter = $cert.NotAfter.ToUniversalTime()
            }
            return New-Result 1 ('TLS OK ({0}, {1} ms)' -f $ssl.SslProtocol, $ms) $ms ([string]$ssl.SslProtocol) $notAfter
        } catch {
            return New-Result 0 ('TLS handshake failed: ' + (Get-InnerMessage $_))
        }
    } finally {
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Dispose() }
    }
}

function Add-AttemptCount($Result) {
    $Result.Detail = '{0} (after {1} attempt{2})' -f $Result.Detail, $Retries, $(if ($Retries -gt 1) { 's' } else { '' })
    $Result
}

function Test-TargetWithRetry($Target) {
    $r = $null
    for ($attempt = 1; $attempt -le $Retries; $attempt++) {
        $r = Test-TlsEndpoint $Target
        if ($r.Status -eq 1) { return $r }
        if ($attempt -lt $Retries) { Start-Sleep -Seconds $RetryDelay }
    }
    Add-AttemptCount $r
}

function Test-ProxyWithRetry {
    $r = $null
    for ($attempt = 1; $attempt -le $Retries; $attempt++) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $tcp = Connect-Tcp $Proxy.Host $Proxy.Port $TimeoutMs
            $tcp.Dispose()
            return New-Result 1 ('Proxy OK ({0} ms)' -f $sw.ElapsedMilliseconds) ([int]$sw.ElapsedMilliseconds)
        } catch {
            $r = New-Result 0 ('Proxy TCP connect failed: ' + $_.Exception.Message)
        }
        if ($attempt -lt $Retries) { Start-Sleep -Seconds $RetryDelay }
    }
    Add-AttemptCount $r
}

# --------------------------------------------------------------------------- state (mails)

function Read-State([string]$Path) {
    $state = @{}
    if (-not (Test-Path $Path)) { return $state }
    try {
        $obj = Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($p in $obj.PSObject.Properties) {
            $entry = @{}
            foreach ($q in $p.Value.PSObject.Properties) {
                $entry[$q.Name] = if ($q.Value -is [datetime]) { Format-Iso $q.Value } else { $q.Value }
            }
            $state[$p.Name] = $entry
        }
    } catch {
        Write-Log ('Unreadable state file, reset: ' + (Get-InnerMessage $_)) 'WARN'
    }
    $state
}

function Save-State([string]$Path, [hashtable]$State) {
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $tmp = $Path + '.tmp'
    $State | ConvertTo-Json -Depth 5 | Set-Content -Path $tmp -Encoding UTF8
    Move-Item -Path $tmp -Destination $Path -Force
}

# --------------------------------------------------------------------------- mail

function Send-Alert([string]$Subject, [string]$Body) {
    if ($DryRun) {
        Write-Host ("`n--- [dry-run] e-mail not sent ---`nTo: {0}`nSubject: {1}`n`n{2}`n---" -f ($MailTo -join ', '), $Subject, $Body)
        return $true
    }
    if (-not $MailTo -or -not $SmtpHost) {
        Write-Log 'Incomplete mail configuration (ALERT_EMAIL_TO / SMTP_HOST), e-mail not sent.' 'ERROR'
        return $false
    }
    $msg = New-Object System.Net.Mail.MailMessage
    $smtp = New-Object System.Net.Mail.SmtpClient($SmtpHost, $SmtpPort)
    try {
        $msg.From = $MailFrom
        foreach ($a in $MailTo) { $msg.To.Add($a) }
        $msg.Subject = $Subject
        $msg.Body = $Body
        $msg.SubjectEncoding = [Text.Encoding]::UTF8
        $msg.BodyEncoding = [Text.Encoding]::UTF8
        $smtp.EnableSsl = $SmtpUseTls
        $smtp.Timeout = 30000
        if ($SmtpUser) { $smtp.Credentials = New-Object System.Net.NetworkCredential($SmtpUser, $SmtpPassword) }
        $smtp.Send($msg)
        Write-Log "E-mail sent: $Subject"
        return $true
    } catch {
        Write-Log ('E-mail delivery failed: ' + (Get-InnerMessage $_)) 'ERROR'
        return $false
    } finally {
        $msg.Dispose()
        $smtp.Dispose()
    }
}

function Invoke-MailAlerts($Checks, $Lines) {
    # $Checks: objects { Key; Result } to track (tested targets + proxy). Returns $false if delivery failed.
    $now = [datetime]::UtcNow
    $old = Read-State $StateFile
    # Entries no longer configured are forgotten without alert ("not tested" targets are kept).
    $state = @{}
    foreach ($k in @($old.Keys)) { if ($KnownKeys.ContainsKey($k)) { $state[$k] = $old[$k] } }

    $down = @(); $reminders = @(); $recovered = @(); $certWarnings = @()
    foreach ($c in $Checks) {
        $r = $c.Result
        $prev = if ($state.ContainsKey($c.Key)) { $state[$c.Key] } else { @{} }
        $entry = $prev.Clone()
        $prevStatus = $prev['status']

        if ($r.Status -eq 1) {
            if ($prevStatus -eq 'DOWN') {
                $recovered += [pscustomobject]@{ Key = $c.Key; Detail = $r.Detail; Since = $prev['since'] }
            }
            if ($prevStatus -ne 'UP') { $entry['since'] = Format-Iso $now }
            $entry['status'] = 'UP'
            $entry['detail'] = $r.Detail
            $entry.Remove('last_alert')
            if ($r.NotAfter) {
                $days = [int][math]::Floor(($r.NotAfter - $now).TotalDays)
                $entry['cert_not_after'] = Format-Iso $r.NotAfter
                $lastWarn = $prev['last_cert_warn']
                if ($days -lt $CertWarnDays -and (-not $lastWarn -or ($now - (ConvertTo-Utc $lastWarn)).TotalSeconds -ge 86400)) {
                    $certWarnings += [pscustomobject]@{ Key = $c.Key; Days = $days; NotAfter = $r.NotAfter }
                    $entry['last_cert_warn'] = Format-Iso $now
                }
            }
        } else {
            if ($prevStatus -ne 'DOWN') {
                $down += [pscustomobject]@{ Key = $c.Key; Detail = $r.Detail }
                $entry['status'] = 'DOWN'
                $entry['since'] = Format-Iso $now
                $entry['last_alert'] = Format-Iso $now
            } else {
                $lastAlert = $prev['last_alert']
                if (-not $lastAlert -or ($now - (ConvertTo-Utc $lastAlert)).TotalSeconds -ge $ReminderSec) {
                    $reminders += [pscustomobject]@{ Key = $c.Key; Detail = $r.Detail; Since = $prev['since'] }
                    $entry['last_alert'] = Format-Iso $now
                }
            }
            $entry['detail'] = $r.Detail
        }
        $entry['last_check'] = Format-Iso $now
        $state[$c.Key] = $entry
    }

    # A single e-mail per run, subject based on the most severe event.
    $mailOk = $true
    if ($down -or $reminders -or $recovered -or $certWarnings) {
        if ($down) {
            $subject = '[VPN DOWN] {0} - {1}' -f (($down | ForEach-Object Key) -join ', '), $down[0].Detail
        } elseif ($reminders) {
            $subject = '[VPN DOWN - reminder] ' + (($reminders | ForEach-Object Key) -join ', ')
        } elseif ($recovered) {
            $subject = '[VPN UP] Recovered: ' + (($recovered | ForEach-Object Key) -join ', ')
        } else {
            $subject = '[VPN] Certificate expiring soon: ' + (($certWarnings | ForEach-Object Key) -join ', ')
        }

        $body = @()
        foreach ($d in $down) { $body += "DOWN since $(Format-Iso $now): $($d.Key)`r`n  $($d.Detail)" }
        foreach ($d in $reminders) { $body += "STILL DOWN (since $($d.Since)): $($d.Key)`r`n  $($d.Detail)" }
        foreach ($d in $recovered) { $body += "RECOVERED: $($d.Key) (down since $($d.Since))`r`n  $($d.Detail)" }
        foreach ($d in $certWarnings) { $body += "CERTIFICATE: $($d.Key) expires on $(Format-Iso $d.NotAfter) (in $($d.Days) days)" }
        $body += "Status at $(Format-Iso $now) (probe: $([Environment]::MachineName)):`r`n" + ($Lines -join "`r`n")

        $mailOk = Send-Alert $subject ($body -join "`r`n`r`n")
        if (-not $mailOk) {
            # The alert is not recorded: it will be retried on the next run.
            foreach ($d in $down) { $state[$d.Key]['status'] = 'UP' }
            foreach ($d in $reminders) { $state[$d.Key]['last_alert'] = $state[$d.Key]['since'] }
            foreach ($d in $recovered) { $state[$d.Key]['status'] = 'DOWN'; $state[$d.Key]['since'] = $d.Since }
        }
    }

    if (-not $DryRun -or $StateFileGiven) { Save-State $StateFile $state }
    $mailOk
}

# --------------------------------------------------------------------------- main

try {
    $Targets = @(ConvertTo-Targets ((Get-Setting 'VPN_TARGETS') + ',' + $ExtraTarget))
    $ProxyRaw = Get-Setting 'PROXY'
    $Proxy = if ($ProxyRaw) { ConvertTo-Endpoint ($ProxyRaw -replace '^https?://', '').TrimEnd('/') 8080 } else { $null }
    $TimeoutMs = [int]([double](Get-Setting 'TIMEOUT' '10') * 1000)
    $Retries = [math]::Max(1, [int](Get-Setting 'RETRIES' '3'))
    $RetryDelay = [int](Get-Setting 'RETRY_DELAY' '10')
    $Sni = Get-Setting 'TLS_SNI'
    # TLS 1.3 preferred, TLS 1.2 fallback (Windows Server 2016/2019 do not support TLS 1.3).
    $TlsSetting = Get-Setting 'TLS_PROTOCOLS' 'Tls12, Tls13'
    $TlsNote = ''
    if ($TlsSetting -match 'Tls13' -and -not [enum]::IsDefined([System.Security.Authentication.SslProtocols], 'Tls13')) {
        # .NET Framework older than 4.8 does not know TLS 1.3.
        $TlsSetting = (($TlsSetting -split '[,\s]+') | Where-Object { $_ -and $_ -ne 'Tls13' }) -join ', '
        if (-not $TlsSetting) { $TlsSetting = 'Tls12' }
        $TlsNote = "TLS 1.3 is not available in this .NET version (4.8+ required): using $TlsSetting"
    }
    $TlsProtocols = [System.Security.Authentication.SslProtocols]$TlsSetting
    $CertWarnDays = [int](Get-Setting 'CERT_WARN_DAYS' '14')
    $LogRetentionMonths = [int](Get-Setting 'LOG_RETENTION_MONTHS' '6')
    $MailEnabled = (Get-Setting 'MAIL_ENABLED' 'true') -eq 'true'
    $ReminderSec = [int](Get-Setting 'REMINDER_MINUTES' '60') * 60
    $MailTo = @((Get-Setting 'ALERT_EMAIL_TO') -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $SmtpHost = Get-Setting 'SMTP_HOST'
    $SmtpPort = [int](Get-Setting 'SMTP_PORT' '587')
    $SmtpUseTls = (Get-Setting 'SMTP_USE_TLS' 'true') -eq 'true'
    $SmtpUser = Get-Setting 'SMTP_USER'
    $SmtpPassword = Get-Setting 'SMTP_PASSWORD'
    $MailFrom = Get-Setting 'ALERT_EMAIL_FROM' $(if ($SmtpUser) { $SmtpUser } else { 'vpn-monitor@{0}.local' -f [Environment]::MachineName.ToLower() })
} catch {
    Exit-ConfigError ('Invalid configuration: ' + (Get-InnerMessage $_))
}

if ($Targets.Count -eq 0) { Exit-ConfigError "No target: set VPN_TARGETS in $ConfigFile" }
if ($TlsNote) { Write-Log $TlsNote 'WARN' }
if (-not $MailEnabled -and -not $ZabbixEnabled) { Write-Log 'MAIL_ENABLED and ZABBIX_ENABLED are both false: results will not be reported anywhere.' 'WARN' }
if ($MailEnabled -and $SmtpPort -eq 465) {
    Write-Log 'SMTP_PORT=465 (implicit SSL) is not supported by System.Net.Mail: use 587 (STARTTLS) or 25.' 'WARN'
}

try {
    $lines = @()
    $checks = @()          # tracked for e-mails
    $KnownKeys = @{}       # state entries to keep
    $anyDown = $false

    # 1. Proxy
    $proxyResult = New-Result 2 'Proxy not used (direct connection)'
    if ($Proxy) {
        $proxyKey = 'proxy:' + $Proxy.Key
        $KnownKeys[$proxyKey] = $true
        $proxyResult = Test-ProxyWithRetry
        $line = '{0,-3} {1,-28} {2}' -f $(if ($proxyResult.Status -eq 1) { 'OK' } else { 'KO' }), $proxyKey, $proxyResult.Detail
        $lines += $line
        Write-Log $line $(if ($proxyResult.Status -eq 1) { 'INFO' } else { 'WARN' })
        $checks += [pscustomobject]@{ Key = $proxyKey; Result = $proxyResult }
        if ($proxyResult.Status -ne 1) { $anyDown = $true }
    }

    # 2. Targets
    $zTargets = @()
    $now = [datetime]::UtcNow
    foreach ($t in $Targets) {
        $KnownKeys[$t.Key] = $true
        if ($proxyResult.Status -eq 0) {
            $r = New-Result 2 'Not tested: proxy unreachable'
        } else {
            $r = Test-TargetWithRetry $t
            $checks += [pscustomobject]@{ Key = $t.Key; Result = $r }
        }
        $label = switch ($r.Status) { 1 { 'OK' } 0 { 'KO' } default { '--' } }
        $line = '{0,-3} {1,-28} {2}' -f $label, $t.Key, $r.Detail
        $lines += $line
        Write-Log $line $(if ($r.Status -eq 0) { 'WARN' } else { 'INFO' })
        if ($r.Status -eq 0) { $anyDown = $true }

        $zTargets += [ordered]@{
            target      = $t.Key
            status      = $r.Status
            latency_ms  = $r.LatencyMs
            cert_days   = $(if ($r.NotAfter) { [int][math]::Floor(($r.NotAfter - $now).TotalDays) } else { -1 })
            tls_version = $r.TlsVersion
            error       = $(if ($r.Status -eq 1) { '' } else { $r.Detail })
        }
    }

    # 3. Zabbix
    try {
        Write-ZabbixFile ([ordered]@{
            timestamp   = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            probe       = [Environment]::MachineName
            duration_ms = [int]$RunWatch.ElapsedMilliseconds
            probe_error = ''
            proxy       = [ordered]@{
                enabled = $(if ($Proxy) { 1 } else { 0 })
                address = $(if ($Proxy) { $Proxy.Key } else { '' })
                status  = $proxyResult.Status
                error   = $(if ($proxyResult.Status -eq 0) { $proxyResult.Detail } else { '' })
            }
            targets     = $zTargets
        })
    } catch {
        Write-Log ('Cannot write the Zabbix file: ' + (Get-InnerMessage $_)) 'ERROR'
    }

    # 4. E-mails
    $mailOk = $true
    if ($MailEnabled) { $mailOk = Invoke-MailAlerts $checks $lines }

    # Purge old logs.
    Get-ChildItem -Path $LogDir -Filter 'vpn-monitor-*.log' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddMonths(-$LogRetentionMonths) } |
        Remove-Item -Force -ErrorAction SilentlyContinue

    if ($anyDown -or -not $mailOk) { exit 1 } else { exit 0 }
} catch {
    Write-Log ('Unexpected error: ' + (Get-InnerMessage $_) + ' @ ' + $_.InvocationInfo.PositionMessage) 'ERROR'
    exit 2
}
