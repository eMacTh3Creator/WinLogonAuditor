# Changelog

All notable changes to WinLogonAuditor are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/eMacTh3Creator/WinLogonAuditor/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/eMacTh3Creator/WinLogonAuditor/releases/tag/v1.0.0
