<#
.SYNOPSIS
    Generates the WinLogonAuditor logo: assets\winlogonauditor.png (256px)
    and a multi-size assets\winlogonauditor.ico (PNG-encoded entries).
    Re-run only when you want to change the artwork; outputs are committed.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$repo = Split-Path $PSScriptRoot -Parent
$assets = Join-Path $repo 'assets'
New-Item -ItemType Directory -Path $assets -Force | Out-Null

function New-Logo {
    param([int]$S)
    $bmp = New-Object System.Drawing.Bitmap($S, $S)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([System.Drawing.Color]::Transparent)
    $u = $S / 256.0

    # Rounded dark tile
    $rad = [int](46 * $u)
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $rad * 2
    $path.AddArc(0, 0, $d, $d, 180, 90)
    $path.AddArc($S - $d, 0, $d, $d, 270, 90)
    $path.AddArc($S - $d, $S - $d, $d, $d, 0, 90)
    $path.AddArc(0, $S - $d, $d, $d, 90, 90)
    $path.CloseFigure()
    $bg = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        (New-Object System.Drawing.Point(0,0)),
        (New-Object System.Drawing.Point($S,$S)),
        [System.Drawing.Color]::FromArgb(255,39,39,57),
        [System.Drawing.Color]::FromArgb(255,30,30,46))
    $g.FillPath($bg, $path)

    # Shield
    $cx = $S / 2.0
    $sw = 132 * $u; $top = 50 * $u; $bot = 212 * $u
    $sh = New-Object System.Drawing.Drawing2D.GraphicsPath
    [System.Drawing.PointF[]]$shPts = @(
        (New-Object System.Drawing.PointF([single]$cx, [single]$top)),
        (New-Object System.Drawing.PointF([single]($cx + $sw/2), [single]($top + 26*$u))),
        (New-Object System.Drawing.PointF([single]($cx + $sw/2), [single]($top + 92*$u))),
        (New-Object System.Drawing.PointF([single]$cx, [single]$bot)),
        (New-Object System.Drawing.PointF([single]($cx - $sw/2), [single]($top + 92*$u))),
        (New-Object System.Drawing.PointF([single]($cx - $sw/2), [single]($top + 26*$u)))
    )
    $sh.AddLines($shPts)
    $sh.CloseFigure()
    $shB = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        (New-Object System.Drawing.Point(0,[int]$top)),
        (New-Object System.Drawing.Point($S,[int]$bot)),
        [System.Drawing.Color]::FromArgb(255,124,92,255),
        [System.Drawing.Color]::FromArgb(255,59,130,246))
    $g.FillPath($shB, $sh)

    # Keyhole (white)
    $wb = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $kr = 26 * $u
    $g.FillEllipse($wb, [single]($cx - $kr), [single](104*$u), [single]($kr*2), [single]($kr*2))
    [System.Drawing.PointF[]]$khPts = @(
        (New-Object System.Drawing.PointF([single]($cx - 12*$u), [single](150*$u))),
        (New-Object System.Drawing.PointF([single]($cx + 12*$u), [single](150*$u))),
        (New-Object System.Drawing.PointF([single]($cx + 20*$u), [single](188*$u))),
        (New-Object System.Drawing.PointF([single]($cx - 20*$u), [single](188*$u)))
    )
    $g.FillPolygon($wb, $khPts)
    $g.Dispose()
    return $bmp
}

# PNG (256)
$png = Join-Path $assets 'winlogonauditor.png'
$b256 = New-Logo 256
$b256.Save($png, [System.Drawing.Imaging.ImageFormat]::Png)

# Multi-size ICO with PNG-compressed entries
$sizes = 16,24,32,48,64,128,256
$blobs = @()
foreach ($sz in $sizes) {
    $b = New-Logo $sz
    $ms = New-Object System.IO.MemoryStream
    $b.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $blobs += ,@{ Size=$sz; Bytes=$ms.ToArray() }
    $ms.Dispose(); $b.Dispose()
}
$ico = Join-Path $assets 'winlogonauditor.ico'
$fs = [System.IO.File]::Create($ico)
$bw = New-Object System.IO.BinaryWriter($fs)
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$blobs.Count)
$offset = 6 + 16 * $blobs.Count
foreach ($e in $blobs) {
    $dim = if ($e.Size -ge 256) { 0 } else { $e.Size }
    $bw.Write([byte]$dim); $bw.Write([byte]$dim)
    $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32)
    $bw.Write([uint32]$e.Bytes.Length); $bw.Write([uint32]$offset)
    $offset += $e.Bytes.Length
}
foreach ($e in $blobs) { $bw.Write($e.Bytes) }
$bw.Flush(); $bw.Dispose(); $fs.Dispose()
$b256.Dispose()

# Base64 of the ICO for embedding into the script (title-bar/taskbar icon)
$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($ico))
Set-Content -Path (Join-Path $assets 'icon.b64') -Value $b64 -Encoding ASCII
Write-Host ("PNG: {0}" -f $png)
Write-Host ("ICO: {0} ({1} sizes, {2:N0} bytes)" -f $ico, $blobs.Count, (Get-Item $ico).Length)
Write-Host ("b64 length: {0}" -f $b64.Length)
