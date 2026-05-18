# Changelog

All notable changes to WinLogonAuditor are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.0.4...HEAD
[1.0.4]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/eMacTh3Creator/WinLogonAuditor/releases/tag/v1.0.0

