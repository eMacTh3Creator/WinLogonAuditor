<#
.SYNOPSIS
    One-command release: roll the CHANGELOG, commit, tag and push.

.DESCRIPTION
    Moves everything under "## [Unreleased]" into a new dated version
    section, rebuilds the CHANGELOG reference links, commits, creates an
    annotated vX.Y.Z tag and pushes. The push triggers
    .github/workflows/release.yml, which builds WinLogonAuditor.exe and
    publishes the GitHub Release (using this version's CHANGELOG notes).

.PARAMETER Bump
    patch (default), minor or major - bumps the latest vX.Y.Z git tag.

.PARAMETER Version
    Explicit version (e.g. 1.2.0). Overrides -Bump.

.PARAMETER AllowEmptyNotes
    Proceed even if the Unreleased section has no entries.

.EXAMPLE
    pwsh -File build\New-Release.ps1 -Bump minor

.EXAMPLE
    pwsh -File build\New-Release.ps1 -Version 1.2.0
#>
[CmdletBinding()]
param(
    [ValidateSet('patch','minor','major')]
    [string]$Bump = 'patch',
    [string]$Version,
    [switch]$AllowEmptyNotes
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Set-Location $repo
$clPath = Join-Path $repo 'CHANGELOG.md'
if (-not (Test-Path $clPath)) { throw "CHANGELOG.md not found." }

# Clean tree required (CHANGELOG-only changes are fine if already staged).
if (git status --porcelain) {
    throw "Working tree is not clean. Commit or stash changes before releasing."
}

git fetch --tags --quiet 2>$null

# Resolve new version
if ($Version) {
    if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Version must be X.Y.Z" }
    $new = $Version
} else {
    $tags = (git tag --list 'v*' | ForEach-Object { $_ -replace '^v','' } |
             Where-Object { $_ -match '^\d+\.\d+\.\d+$' } |
             Sort-Object { [version]$_ })
    $cur = if ($tags) { [version]$tags[-1] } else { [version]'0.0.0' }
    switch ($Bump) {
        'major' { $new = "{0}.0.0" -f ($cur.Major + 1) }
        'minor' { $new = "{0}.{1}.0" -f $cur.Major, ($cur.Minor + 1) }
        'patch' { $new = "{0}.{1}.{2}" -f $cur.Major, $cur.Minor, ($cur.Build + 1) }
    }
}
$tag = "v$new"
if (git tag --list $tag) { throw "Tag $tag already exists." }

$date = Get-Date -Format 'yyyy-MM-dd'
$raw  = Get-Content $clPath -Raw

# Extract the Unreleased block (between '## [Unreleased]' and the next '## [')
$m = [regex]::Match($raw, '(?s)##\s*\[Unreleased\]\s*(.*?)(?=\r?\n##\s*\[|\r?\n\[Unreleased\]:)')
if (-not $m.Success) { throw "Could not locate the '## [Unreleased]' section." }
$notes = $m.Groups[1].Value.Trim()
if (-not $notes -and -not $AllowEmptyNotes) {
    throw "The [Unreleased] section is empty. Add notes, or pass -AllowEmptyNotes."
}

# Body above the reference-link footer
$footerIdx = [regex]::Match($raw, '(?m)^\[Unreleased\]:\s')
$body   = if ($footerIdx.Success) { $raw.Substring(0, $footerIdx.Index).TrimEnd() } else { $raw.TrimEnd() }

# Splice in the new section WITHOUT swallowing existing version sections:
# keep the preamble, reset Unreleased, insert the dated section, then keep
# every prior version section unchanged.
$uMatch = [regex]::Match($body, '##\s*\[Unreleased\]')
if (-not $uMatch.Success) { throw "No '## [Unreleased]' heading in CHANGELOG body." }
$pre      = $body.Substring(0, $uMatch.Index).TrimEnd()
$afterUl  = $body.Substring($uMatch.Index + $uMatch.Length)
$nextVer  = [regex]::Match($afterUl, '(?m)^##\s*\[\d+\.\d+\.\d+\]')
$rest     = if ($nextVer.Success) { $afterUl.Substring($nextVer.Index).TrimEnd() } else { '' }
$body     = ($pre + "`n`n## [Unreleased]`n`n## [$new] - $date`n`n$notes" +
             $(if ($rest) { "`n`n$rest" } else { '' })).Trim()

# Rebuild reference links from every version heading present (force array so
# single-element indexing doesn't fall back to string-char indexing)
$versions = @([regex]::Matches($body, '(?m)^##\s*\[(\d+\.\d+\.\d+)\]') |
            ForEach-Object { $_.Groups[1].Value })
$base = 'https://github.com/eMacTh3Creator/WinLogonAuditor'
$links = @()
$links += "[Unreleased]: $base/compare/v$($versions[0])...HEAD"
for ($i = 0; $i -lt $versions.Count; $i++) {
    if ($i -lt $versions.Count - 1) {
        $links += "[$($versions[$i])]: $base/compare/v$($versions[$i+1])...v$($versions[$i])"
    } else {
        $links += "[$($versions[$i])]: $base/releases/tag/v$($versions[$i])"
    }
}
$final = ($body.TrimEnd() + "`n`n" + ($links -join "`n") + "`n")
Set-Content -Path $clPath -Value $final -Encoding UTF8

Write-Host "Releasing $tag (notes from CHANGELOG [Unreleased]):" -ForegroundColor Cyan
Write-Host ($notes ? $notes : '(no notes)') -ForegroundColor DarkGray

git add CHANGELOG.md
git commit -q -m "Release $tag"
git tag -a $tag -m "WinLogonAuditor $tag"
git push -q origin HEAD
git push -q origin $tag

Write-Host "Pushed $tag. The release workflow is building the exe:" -ForegroundColor Green
Write-Host "$base/actions" -ForegroundColor Green
