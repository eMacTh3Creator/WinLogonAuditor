# Changelog

All notable changes to WinLogonAuditor are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.7] - 2026-05-19

### Fixed
- Multi-DC queries still timing out even at cap 5000 / 8-24h: the log
  proved Get-WinEvent never returned (reached "fetching", never
  "fetched"). A single structured query over a 24h window hangs
  server-side on a DC whose Security log is enormous (active logon
  storm), regardless of -MaxEvents. Reinstated newest-first time
  slicing (2h slices <=24h, 6h <=3d, 12h beyond) that STOPS as soon as
  the cap is reached - on a noisy DC the newest slice alone fills the
  cap in one fast call; on quiet DCs a few cheap slices cover the
  window. Each slice is logged ("slice#N: M raw in Xs -> kept").
  (This restores, correctly bounded, the slicing that v1.1.3 removed.)

## [1.1.6] - 2026-05-19

### Fixed
- All DCs still timing out even on an 8h, low-volume query: Get-WinEvent
  never returned within the timeout because the 100,000 per-DC cap
  streams the environment's active failed-logon (4625) storm over RPC
  for every DC. Default "Max events/DC" lowered to 5000 (Get-WinEvent
  returns newest-first and stops at the cap, so this is fast even on a
  busy DC). The unusable 100000 value auto-persisted by earlier builds
  is migrated down to 5000 on config load (still user-adjustable).

### Added
- Pre-fetch log line ("<log>: fetching (cap N, window)...") so a hang
  inside the remote Get-WinEvent call is unambiguous in the run log.

## [1.1.5] - 2026-05-19

### Fixed
- All DCs timing out on broad multi-DC queries (e.g. 24h with Kerberos
  4768/4769 selected). Root cause: the v1.1.0 cap raise to 100k events
  combined with calling $Evt.FormatDescription() for every event - that
  per-event provider rendering dominates at scale. The detail text is
  now reconstructed from the already-parsed EventData (effectively
  free); the slow call is gone. Raising the timeout didn't help because
  the cost scaled with event volume, not wall time.

### Added
- Per-DC timing in the run log: raw events fetched and fetch seconds vs
  convert seconds per log, so fetch-bound vs process-bound is obvious.

## [1.1.4] - 2026-05-19

### Added
- Partial-failure warning banner: when some DCs return but others
  fail or time out, an amber banner now lists them ("Incomplete: 1
  DC(s) failed/skipped ... eDC2: RPC server unavailable") so an
  incomplete lockout sweep is never mistaken for a clean one.

### Changed
- Run logs now live in their own folder: %TEMP%\WinLogonAuditor\logs\
  (still the 10 most recent). Old logs written directly in %TEMP% are
  cleaned up automatically on first run.

## [1.1.3] - 2026-05-19

### Fixed
- Performance regression: queries over windows > 24h (e.g. Last 3 days)
  timed out even with a high per-DC timeout. v1.1.0's hourly chunking
  turned one query into ~24 remote Get-WinEvent calls per day per DC;
  the per-call RPC overhead dominated. Reverted to a single server-side
  filtered query per log (StartTime/EndTime + Id done on the DC,
  -MaxEvents bounds the result) - the fast path used pre-1.1. Long
  ranges complete in seconds again.

### Added
- Hover tooltips on every option (target, Discover/Servers, Query all
  DCs, user, range, dates, max events, timeout, alt credentials, Run,
  Export, Excludes, Auto-refresh, Watch, quick filter, Lockout
  Investigator fields) and on each event-category checkbox, explaining
  what it does with examples.

### Removed
- F6 internal hourly chunking (caused the regression above; the cap +
  server-side time filter already bound long-window queries).

## [1.1.2] - 2026-05-19

### Added
- Per-run logging to %TEMP%\WinLogonAuditor_yyyyMMdd_HHmmss.log (the 10
  most recent runs are kept). Captures startup/env, query parameters,
  per-DC start/done/timeout/error, worker phase markers, and full
  exception type + message + script stack trace. Error dialogs and the
  status bar now show the log path.

### Fixed
- "Argument types do not match" on multi-DC ("Query all DCs") queries in
  the packaged exe. Root cause: applying the array operator directly to a
  System.Collections.Generic.List ( @($list) ) is unreliable under the
  PS2EXE runtime. The result list is now materialised with .ToArray() /
  pipeline collection, and the exclude pass is skipped entirely when no
  exclude patterns are configured.

## [1.1.1] - 2026-05-19

### Fixed
- "Query failed: Argument types do not match" when running a multi-DC
  query in the packaged exe. The per-DC cap was signalled via a [ref]
  parameter marshalled into the child query runspaces, which is
  unreliable under the PS2EXE runtime; the cap is now derived from the
  returned row count instead (no [ref]). Worker/UI errors now also
  include the failing script line to make any future issue diagnosable.

## [1.1.0] - 2026-05-19

### Added
- Configurable max-events cap (default 100k, per DC) replacing the old
  effective ~2k truncation; "Max events/DC" toolbar field + config key;
  amber warning banner and "CAP HIT" status when the cap is reached.
- Exclude lists (Users / Sources / DCs) with wildcards, persisted to
  config.json; "Excludes..." editor and right-click "Mute this user /
  source host / source IP" on any grid row; "N excluded" in the status
  bar; excluded rows dropped from grid, summary and export.
- Full lockout-source correlation in the Lockout Investigator: live
  query of 4740 + preceding 4771/4625/4776 over a configurable Lookback
  (default 60 min) across the selected target/all-DCs, source IPs
  resolved to DNS hostnames, ranked offending-source grid + verdict.
- Watch mode: continuous polling for new lockouts of a watched-user
  list with tray toast notifications and an append-only
  %APPDATA%\WinLogonAuditor\LockoutHunt_yyyyMMdd.csv history.
- Chunked retrieval for windows > 24h (hourly slices, newest first).
- Application icon (title bar, taskbar, exe) and GitHub/site branding.
- New CLI flags: -MaxEvents, -ExcludeUsers, -ExcludeSources,
  -WatchMode, -WatchUsers.

### Changed
- CSV export now uses an event-aware normalized schema; SourceIP and
  FailureCode/FailureReason are populated for 4771/4625 (previously
  blank). Export filename gets a _filtered suffix when excludes apply.
- ::ffff: IPv6-mapped prefix stripped from all IP fields.
- config.json schema extended additively (old files keep working).

### Fixed
- Time-range presets now retrieve the full window up to the cap
  instead of only the most recent ~2,000 events.

## [1.0.6] - 2026-05-18

### Added
- Lockout source attribution. Event 4740 frequently has no Caller
  Computer Name for NTLM/network lockouts (a Windows logging behaviour,
  not a tool fault). Each such 4740 is now correlated to the matching
  4625/4776/4771 for the same user within 5 minutes, and its row is
  rewritten to "Locked via IP <x> | Type <n> | <auth pkg> | proc <p>
  (from event NNNN, Ns before)" with the source IP/host filled in.
- 4625 rows now show logon type, authentication package and process;
  4776 rows surface the NTLM Source Workstation (often the real
  machine when 4740 is blank).
- Best-effort reverse DNS so a bare source IP resolves to a hostname.
- Lockout Investigator now prints a one-line VERDICT: lock count, the
  top offending source host/IP and how to act, with a hint to enable
  4625/4776 when they aren't in the data.

## [1.0.5] - 2026-05-18

### Fixed
- A slow/busy domain controller (typically the PDC emulator) no longer
  hangs the whole sweep. DCs are now queried **in parallel**, each in its
  own runspace, with a configurable **per-DC timeout** (default 45s, new
  "Timeout/DC" box). Any DC that exceeds the timeout is stopped and
  skipped with a noted error so the remaining DCs still return. Progress
  now reflects completions ("eDC1 done (2/4) - 1,234 events so far").

## [1.0.4] - 2026-05-18

### Changed
- No automatic query on launch. The app opens instantly to a "set your
  filters and click Run Query" state so you can choose the time range
  (e.g. last 1-6 hours), user and categories before anything runs.

### Added
- Full-screen progress overlay while a query runs: large title, a
  determinate progress bar, live per-server status ("Querying TDC1
  (server 2 of 4)..."), a matching status-bar bar, and a Cancel button
  to abort a long sweep.

### Fixed
- Packaged build broke under Windows PowerShell 5.1 due to non-ASCII
  characters in the script; source is now ASCII-only.

## [1.0.3] - 2026-05-18

### Changed
- Releases now ship a version-stamped `WinLogonAuditor-X.Y.Z.exe` as the
  primary asset so browsers stop saving `WinLogonAuditor (2).exe` duplicates
  and the version is visible on disk. A stable `WinLogonAuditor.exe` alias is
  still published so existing `/releases/latest/download/` links keep working;
  the site button now hands out the versioned file automatically.

## [1.0.2] - 2026-05-18

### Changed
- UI no longer freezes (stuck hourglass) when querying. Domain-controller
  discovery and **all** result aggregation (summary tabs + Logout Analyzer)
  now run on the background thread instead of the UI thread; the per-user
  analysis was rewritten from an O(users x events) rescan to a single
  hashtable pass. Live per-DC progress is shown in the status bar, and the
  default max-events-per-DC was lowered to 2000 for snappier multi-DC sweeps.

## [1.0.1] - 2026-05-18

### Fixed
- Crash on Run Query in the packaged .exe ("The property 'Cursor' cannot be
  found on this object"): window/control references are now explicitly
  script-scoped for the PS2EXE runtime, the busy cursor is non-fatal, and
  all query paths are wrapped so an unexpected error is shown in the status
  bar / a dismissible dialog instead of terminating the app.

## [1.0.0] - 2026-05-18

### Added
- Initial release: PowerShell + WPF single-file logon/lockout/logoff
  auditing tool (no build step, no .NET SDK required).
- Query engine over the Security and System event logs, local or remote,
  with decoders for logon types, NTSTATUS/SubStatus and Kerberos codes.
- Searchable event grid with quick filter, user wildcard search and
  flexible time ranges (1h–7d presets or custom from/to).
- Lockout Investigator (traces event 4740 caller computer + correlated
  failures) and Logout Analyzer (per-user grouping with likely-cause).
- Summary dashboard, CSV export, 60-second auto-refresh, headless CLI mode.
- Server management with saved server list and one-click domain controller
  auto-discovery; auto-selects the PDC emulator.
- "Query all DCs" fan-out across every controller, on by default.
- GitHub Pages landing page and Pages deploy workflow.
- PS2EXE packaging (`build/Build-Exe.ps1`) and tag-driven release
  workflow producing a standalone `WinLogonAuditor.exe`.

[Unreleased]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.1.7...HEAD
[1.1.7]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.1.6...v1.1.7
[1.1.6]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.1.5...v1.1.6
[1.1.5]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.1.4...v1.1.5
[1.1.4]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.1.3...v1.1.4
[1.1.3]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.0.6...v1.1.0
[1.0.6]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/eMacTh3Creator/WinLogonAuditor/releases/tag/v1.0.0

