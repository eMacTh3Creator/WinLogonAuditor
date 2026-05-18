<h1 align="center">WinLogonAuditor</h1>

<p align="center">
  <a href="https://github.com/eMacTh3Creator/WinLogonAuditor/releases/latest/download/WinLogonAuditor.exe"><b>⬇ Download the .exe</b></a>
  &nbsp;·&nbsp;
  <a href="https://emacth3creator.github.io/WinLogonAuditor/"><b>🌐 Live site &amp; feature tour</b></a>
</p>

<p align="center">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-3b82f6">
  <img alt="PowerShell" src="https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-7c5cff">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows-0a66c2">
  <img alt="Build step" src="https://img.shields.io/badge/build-none%20required-34d399">
  <a href="https://github.com/eMacTh3Creator/WinLogonAuditor/actions"><img alt="Pages" src="https://img.shields.io/github/actions/workflow/status/eMacTh3Creator/WinLogonAuditor/pages.yml?label=pages"></a>
</p>

A clean, fully-functional Windows desktop tool for auditing **logon failures,
successful logons ("approvals"), account lockouts and unexpected logoffs** on a
domain controller or any domain-joined machine.

Built for the exact situation of *"users are getting logged out and I need to
know why, right now"* — full searchable event list, per-user search, flexible
time ranges, a lockout-source tracer and a logout analyzer.

> Single-file PowerShell + WPF app. **No build step, no install, no .NET SDK.**
> Runs on Windows PowerShell 5.1 or PowerShell 7+.

---

## Features

- **Full event list** — one searchable, sortable grid across the Security *and*
  System logs.
- **Decoded, human-readable** — logon types, NTSTATUS/SubStatus failure reasons
  and Kerberos failure codes are translated to plain English (no more
  `0xC000006A` guessing).
- **Server management & DC auto-discovery** — editable target dropdown with a
  saved server list (persisted to `%APPDATA%\WinLogonAuditor\config.json`).
  **Discover DCs** enumerates every domain controller in your domain (using
  your domain credentials, no RSAT required) and auto-selects the **PDC
  emulator** — the single best target for lockout hunting. **Query all DCs**
  fans the query across every controller and merges the results.
- **Search by user** — wildcards supported (`jsmith`, `svc-*`, `*admin*`).
- **Flexible timeframe** — presets (1h / 8h / 24h / 3d / 7d) or a custom
  from/to date range.
- **Category filters** — failed logons (4625), successful logons (4624),
  lockouts (4740), unlocks (4767), logoff/sign-out (4634/4647), RDP
  connect/disconnect (4778/4779), workstation lock/unlock (4800/4801),
  Kerberos (4768/4769/4771), NTLM (4776), explicit credentials (4648),
  reboots/shutdowns (1074/6005/6006/6008/41).
- **Lockout Investigator** — enter a locked username and it traces the **4740
  caller computer** plus the correlated failed logons so you can find the device
  holding the stale credential.
- **Logout Analyzer** — groups logoff/disconnect/lock/lockout/reboot activity by
  user and suggests the **likely cause** (mass reboot, lockout storm, RDP idle
  timeout, screensaver/lock GPO, normal sign-out).
- **Summary dashboard** — counts by category, top users by failures, top source
  hosts/IPs by failures.
- **Remote & local** — query the local box or point at a DC by name; optional
  alternate credentials.
- **Detail pane** — full raw event message for any selected row.
- **CSV export** and **60-second auto-refresh**.
- **Headless CLI mode** for scripting / scheduled triage.

---

## Quick start

**Option A — installable exe (easiest):**

```text
1. Download WinLogonAuditor.exe from the latest release.
2. Right-click it -> Run as administrator.
3. It auto-discovers your DCs and queries them; pick a range, Run Query.
```

**Option B — run the script directly (no download of a binary):**

```text
1. Copy the WinLogonAuditor folder to your DC or a domain-joined admin machine.
2. Right-click  Run-WinLogonAuditor.cmd  ->  Run as administrator
   (administrator / "Event Log Readers" is required to read the Security log).
3. Set "Target" to your DC name (e.g. DC01), pick a time range, click Run Query.
```

> The exe is generated from `src/WinLogonAuditor.ps1` via `build/Build-Exe.ps1`
> and rebuilt automatically on every `v*` tag — the script is the source of truth.

### Investigating the "users keep getting logged out" issue

1. Tick **Alt credentials** (if needed) then click **Discover DCs** — it lists
   every DC and selects the PDC emulator automatically. Or tick **Query all
   DCs** to sweep them all at once.
2. Range = **Last 24 hours**, leave categories at their defaults, **Run Query**.
3. Open the **Logout Analyzer** tab — scan the *Likely cause* column for
   lockout storms, mass reboots or RDP idle-timeout patterns.
4. For any locked user, open **Lockout Investigator**, type the username and
   **Trace lockout source** — it shows the caller computer from event 4740 and
   the last failed-logon source host/IP.

### CLI / scheduled triage

```powershell
.\src\WinLogonAuditor.ps1 -Cli -Target DC01 -User jsmith -Hours 48 -OutFile triage.csv
```

---

## Requirements

| Item | Detail |
|------|--------|
| OS | Windows 10/11 or Windows Server (incl. domain controllers) |
| PowerShell | Windows PowerShell 5.1 **or** PowerShell 7+ |
| Rights | Local admin **or** member of **Event Log Readers** on the target |
| Remote | "Remote Event Log Management" allowed through the firewall on the DC |

No .NET SDK, no compilation, no third-party modules.

---

## Event ID reference

| ID | Meaning | Log |
|----|---------|-----|
| 4624 | Successful logon | Security |
| 4625 | Failed logon | Security |
| 4634 / 4647 | Logoff / user-initiated sign-out | Security |
| 4648 | Logon with explicit credentials | Security |
| 4740 | **Account lockout** (caller computer = source) | Security |
| 4767 | Account unlocked | Security |
| 4768 / 4769 / 4771 | Kerberos TGT / service ticket / pre-auth failed | Security |
| 4776 | NTLM credential validation | Security |
| 4778 / 4779 | Session reconnected / disconnected (RDP) | Security |
| 4800 / 4801 | Workstation locked / unlocked | Security |
| 1074 / 6006 / 6005 | Shutdown-restart / clean stop / boot | System |
| 6008 / 41 | **Unexpected** shutdown / kernel-power crash | System |

---

## Self-test

```powershell
# structural smoke test (no desktop session needed)
powershell.exe -Sta -File .\src\WinLogonAuditor.ps1 -NoShow
```

## Security & privacy

- Read-only. The tool never modifies accounts, GPOs or the event log.
- Exported CSVs may contain usernames/IPs from your environment and are
  `.gitignore`d by default — do not commit them.

## License

MIT — see [LICENSE](LICENSE).
