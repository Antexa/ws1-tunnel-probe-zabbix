# ws1-tunnel-probe-zabbix

Health check of **Workspace ONE Tunnel** gateways (UAG) **from the Internet**, run from a Windows server. Every 5 minutes, the script goes through the outbound HTTP proxy, opens a TCP connection and performs a TLS handshake on port 443 of each IP. Results are reported:
- to **Zabbix 7.0**, through the Zabbix agent already installed on the server (alerting, recovery and escalations handled by Zabbix);
- and/or by **e-mail**, sent directly by the script.

Each channel is enabled independently in `config.env`. 100% native PowerShell (Windows PowerShell 5.1): **nothing to install**.

| File | Purpose |
|---|---|
| `Check-VpnTunnel.ps1` | the check (one run = one pass over all targets) |
| `Install-VpnMonitor.ps1` | creates (or removes) the Windows scheduled task |
| `config.env.example` | configuration template → `config.env` |
| `zabbix/template_uag_vpn_powershell.yaml` | Zabbix 7.0 template to import |

## How it works

```
Scheduled task (5 min, SYSTEM)
  └─ Check-VpnTunnel.ps1
       ├─ 1. is the proxy reachable? (TCP to PROXY)
       ├─ 2. for each target: CONNECT ip:443 through the proxy → TLS handshake
       ├─ 3. ZABBIX_ENABLED → state\zabbix.json ──► Zabbix agent (vfs.file.contents) ──► Zabbix server
       └─ 4. MAIL_ENABLED   → DOWN / reminder / recovered e-mails (state in state\state.json)
```

| | |
|---|---|
| Check | TCP (direct or `CONNECT` through the proxy), then TLS handshake: TLS 1.3 preferred, TLS 1.2 fallback. The certificate is not validated since the target is an IP address. |
| False positives | 3 attempts, 10 s apart, before a target (or the proxy) is declared down |
| Status values | **1** OK · **0** KO · **2** not tested (the proxy is down, the VPN status is unknown) |
| Logs | `logs\vpn-monitor-YYYY-MM.log`, purged after 6 months |
| Exit code | 0 OK · 1 at least one KO · 2 invalid configuration / error |

**Proxy**: only HTTP proxies supporting the `CONNECT` method, without authentication, are handled (no `.pac`). Errors are explicit:

| Message | Meaning |
|---|---|
| `Proxy TCP connect failed` | the proxy itself is unreachable → targets switch to "not tested" |
| `CONNECT denied by the proxy (403)` | the proxy policy blocks the destination: the UAG IPs must be allowed on port 443 |
| `407` | the proxy requires authentication |
| `502` / `504`, or no answer to `CONNECT` | the proxy cannot reach the target → **VPN down** |

## Requirements

- Windows Server 2016+ with the **Zabbix agent** (1 or 2) installed and attached to a Zabbix host.
- Allowed flows from the server: **to the proxy** (`PROXY`), and through the proxy **CONNECT to the UAG IPs on port 443**. If e-mails are enabled: **SMTP** (25 or 587).

## Installation on the Windows server

1. Copy the folder to `C:\VpnMonitor` (otherwise, adjust the `{$UAG.VPN.FILE}` macro in Zabbix).
2. In an **elevated** PowerShell:
   ```powershell
   cd C:\VpnMonitor
   .\Install-VpnMonitor.ps1          # first run: creates config.env, then stops
   notepad .\config.env              # IPs, PROXY, ZABBIX_ENABLED / MAIL_ENABLED
   ```
3. Test manually:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Check-VpnTunnel.ps1 -DryRun
   powershell -ExecutionPolicy Bypass -File .\Check-VpnTunnel.ps1 -DryRun -ExtraTarget 10.255.255.1:443   # simulates an outage
   ```
   `-DryRun` prints the e-mail instead of sending it, leaves the state untouched and writes the JSON to `state\zabbix.dryrun.json`, which Zabbix does not read. The fake target therefore never reaches Zabbix.
4. Install the scheduled task:
   ```powershell
   .\Install-VpnMonitor.ps1 -RunNow
   ```
   The `\VpnMonitor\UAG VPN Monitor` task runs as **SYSTEM**, every 5 minutes, even when no one is logged on.

Uninstall: `.\Install-VpnMonitor.ps1 -Uninstall`. Change the interval: `.\Install-VpnMonitor.ps1 -IntervalMinutes 10` (also adjust `{$UAG.VPN.NODATA}`).

## Zabbix setup

1. *Data collection → Templates → Import*: `zabbix/template_uag_vpn_powershell.yaml`.
2. Link the **UAG VPN Tunnel by PowerShell probe** template to the Zabbix host of the Windows server.
3. If the folder is not `C:\VpnMonitor`, override the `{$UAG.VPN.FILE}` macro on the host.
4. **Agent in active mode only** (no `Server=` in the agent configuration): change the type of the *UAG VPN: raw probe results* item to **Zabbix agent (active)**. It is the only item to change, all the others depend on it.
5. Check: on that item, click **Test** → the JSON must be displayed. Then *Monitoring → Latest data*: the `VPN <ip:port>` items appear about 1 minute after the first discovery.

### Template content

| Element | Details |
|---|---|
| Master item | `vfs.file.contents[{$UAG.VPN.FILE},UTF-8]` every minute, *Discard unchanged*: a value only arrives when the script actually ran |
| Discovery | one entry per `VPN_TARGETS` target. A removed target switches to "Not tested" (its DOWN problem is closed), is disabled immediately, then deleted after 1 day; when added back, it is re-enabled automatically |
| Per target | status (OK/KO/Not tested), TLS latency (ms), days until certificate expiry, TLS version, error message |
| Probe | last run, duration, configuration error, proxy status and error |

| Trigger | Severity | Fires when |
|---|---|---|
| VPN probe: no results for `{$UAG.VPN.NODATA}` (15m) | High | **the script no longer reports anything**: task stopped or disabled, script failing, server down, agent stopped |
| VPN probe: configuration error | Average | `config.env` is invalid |
| VPN probe: Internet proxy unreachable, VPN tests suspended | High | the proxy does not answer (depends on "no results") |
| VPN `<ip:port>` unreachable from the Internet | Disaster | TCP/CONNECT/TLS failure (depends on the proxy and "no results" triggers) |
| VPN `<ip:port>`: certificate expires in less than `{$UAG.VPN.CERT.WARN}` days | Warning | — |

**Dependencies** prevent alert storms: if the proxy goes down, only its trigger fires, not one per VPN. While a parent trigger is in problem state, Zabbix does not re-evaluate the triggers that depend on it.

### Zabbix notifications

To receive an e-mail, a reminder every hour and a recovery e-mail: *Alerts → Actions → Trigger actions → Create action*.
- Condition: *Template* = `UAG VPN Tunnel by PowerShell probe`.
- Operations: send to the relevant group, *Default operation step duration* = `1h`, steps `1` to `0` (repeated until resolved).
- *Recovery operations*: notify all involved.

If you rely entirely on Zabbix, set `MAIL_ENABLED=false` to avoid duplicate e-mails.

## Script configuration (`config.env`)

| Key | Default | Purpose |
|---|---|---|
| `VPN_TARGETS` | — | `192.0.2.10:443,198.51.100.20:443` — **to monitor a new IP, just add it here** (Zabbix discovers it automatically) |
| `PROXY` | empty | `proxy.example.internal:3128`; empty = direct connection |
| `ZABBIX_ENABLED` | `true` | writes the JSON read by the agent |
| `ZABBIX_FILE` | `state\zabbix.json` | must match `{$UAG.VPN.FILE}` |
| `MAIL_ENABLED` | `true` | e-mails sent directly by the script |
| `ALERT_EMAIL_TO` | — | `ops@example.com,oncall@example.com` |
| `SMTP_HOST` / `SMTP_PORT` | — / `587` | internal relay `:25`, or `smtp.gmail.com:587` (465 not supported) |
| `SMTP_USE_TLS` | `true` | STARTTLS; `false` for a plain internal relay |
| `SMTP_USER` / `SMTP_PASSWORD` | empty | empty = relay without authentication |
| `REMINDER_MINUTES` | `60` | e-mail reminders during an outage |
| `TLS_SNI` | empty | public DNS name of the tunnel, if the UAG requires it |
| `TLS_PROTOCOLS` | `Tls12, Tls13` | TLS 1.3 preferred, TLS 1.2 fallback. `Tls13` = TLS 1.3 only (fails if the server or the UAG cannot do TLS 1.3). TLS 1.3 requires Windows Server 2022+ / Windows 11 and .NET Framework 4.8; on older systems TLS 1.2 is negotiated |
| `TIMEOUT` / `RETRIES` / `RETRY_DELAY` | `10` / `3` / `10` | seconds / count / seconds |
| `CERT_WARN_DAYS` | `14` | e-mail threshold (Zabbix side: `{$UAG.VPN.CERT.WARN}`) |

**Security**: the installation restricts `config.env` to SYSTEM and Administrators. If possible, use an internal SMTP relay without authentication: no password is stored at all.

## Troubleshooting

| Symptom | What to check |
|---|---|
| Master item "not supported" in Zabbix | wrong `{$UAG.VPN.FILE}` path, or file not created yet (run the script once). Also check that no `DenyKey=vfs.file.contents[*]` blocks the item in the agent configuration |
| "No results" trigger | `Get-ScheduledTaskInfo -TaskPath \VpnMonitor\ -TaskName 'UAG VPN Monitor'`, then the log in `logs\` |
| All targets "Not tested" | proxy unreachable: check `PROXY` and the firewall towards the proxy |
| `CONNECT denied by the proxy (403)` | ask for the UAG IPs on port 443 to be allowed on the proxy (some proxies block raw IP destinations) |
| `TLS handshake failed` | set `TLS_SNI`, or check the protocols allowed on the UAG against `TLS_PROTOCOLS` |
| Zabbix shows `Tls12` instead of `Tls13` | the Windows server (before Server 2022) or the UAG does not support TLS 1.3: TLS 1.2 was negotiated |
| E-mail not received | `E-mail delivery failed` in the log: check host, port, TLS and that the relay accepts the server IP |

## Limitations

- Workspace ONE Tunnel also uses UDP (DTLS), which cannot go through an HTTP proxy. The check covers the TCP/TLS 443 part.
- The check goes out through the corporate proxy: it validates access along that proxy's network path, not from any Internet network.
- A device intercepting TLS on the path (proxy with SSL inspection, ISP box) answers in place of the UAG: the handshake succeeds and the target is reported OK.

## License

[MIT](LICENSE)
