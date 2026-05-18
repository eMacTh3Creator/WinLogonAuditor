<#
.SYNOPSIS
    Builds WinLogonAuditor.exe from src\WinLogonAuditor.ps1 using PS2EXE.

.DESCRIPTION
    The .ps1 remains the single source of truth; this script just packages it
    into a double-clickable, GUI (no console) STA executable with version info.
    Run locally, or let .github\workflows\release.yml build it on a tag.

.PARAMETER Version
    Version stamped into the exe (default 1.0.0).

.PARAMETER OutDir
    Output folder (default: <repo>\dist).

.EXAMPLE
    pwsh -File build\Build-Exe.ps1 -Version 1.0.0
#>
[CmdletBinding()]
param(
    [string]$Version = '1.0.0',
    [string]$OutDir
)

$ErrorActionPreference = 'Stop'
$repo   = Split-Path $PSScriptRoot -Parent
$src    = Join-Path $repo 'src\WinLogonAuditor.ps1'
if (-not $OutDir) { $OutDir = Join-Path $repo 'dist' }
# Primary artifact is version-stamped so browsers don't save "(2)" copies.
$out    = Join-Path $OutDir "WinLogonAuditor-$Version.exe"
# Stable alias keeps /releases/latest/download/WinLogonAuditor.exe working.
$alias  = Join-Path $OutDir 'WinLogonAuditor.exe'

if (-not (Test-Path $src)) { throw "Source not found: $src" }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

Write-Host "Ensuring PS2EXE is available..." -ForegroundColor Cyan
if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    try { Get-PackageProvider -Name NuGet -ForceBootstrap -ErrorAction Stop | Out-Null } catch {}
    Install-Module -Name ps2exe -Scope CurrentUser -Force -AllowClobber
}
Import-Module ps2exe -Force

Write-Host "Packaging $src -> $out (v$Version)" -ForegroundColor Cyan
Invoke-PS2EXE `
    -InputFile  $src `
    -OutputFile $out `
    -noConsole `
    -STA `
    -title       'WinLogonAuditor' `
    -product     'WinLogonAuditor' `
    -description 'Windows logon / lockout / logoff auditing tool' `
    -company     'WinLogonAuditor (MIT)' `
    -copyright   "(c) $(Get-Date -Format yyyy) WinLogonAuditor contributors" `
    -version     $Version `
    -requireAdmin

if (-not (Test-Path $out)) { throw 'Build failed: exe was not produced.' }
Copy-Item $out $alias -Force
$fi = Get-Item $out
Write-Host ("OK: {0}  ({1:N0} bytes)" -f $fi.FullName, $fi.Length) -ForegroundColor Green
Write-Host ("Alias: {0}" -f $alias) -ForegroundColor Green
