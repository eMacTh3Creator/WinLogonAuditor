<#
.SYNOPSIS
    WinLogonAuditor - A Windows logon / lockout / logoff auditing tool with a WPF GUI.

.DESCRIPTION
    Queries the Windows Security and System event logs (locally or on a remote
    domain controller) for logon failures, successful logons ("approvals"),
    account lockouts, logoffs/disconnects, Kerberos/NTLM events and unexpected
    reboots. Provides a searchable grid, a lockout-source investigator, a
    "why was the user logged out" analyzer and a summary dashboard.

.PARAMETER Target
    Computer to query. Defaults to the local machine. Point this at your DC.

.PARAMETER Cli
    Run headless: query with the given parameters and write CSV to -OutFile.

.PARAMETER User
    Username filter (wildcards allowed) for -Cli mode.

.PARAMETER Hours
    Look-back window in hours for -Cli mode (default 24).

.PARAMETER OutFile
    CSV output path for -Cli mode.

.EXAMPLE
    .\WinLogonAuditor.ps1

.EXAMPLE
    .\WinLogonAuditor.ps1 -Target DC01 -Cli -User jsmith -Hours 48 -OutFile out.csv

.NOTES
    Project: WinLogonAuditor   License: MIT
    Requires: Windows PowerShell 5.1+ or PowerShell 7+, "Event Log Readers"
              membership (or admin) on the target for remote queries.
#>
[CmdletBinding()]
param(
    [string]$Target = $env:COMPUTERNAME,
    [switch]$Cli,
    [string]$User = '*',
    [int]$Hours = 24,
    [string]$OutFile = "WinLogonAuditor_$(Get-Date -Format yyyyMMdd_HHmmss).csv",
    [int]$MaxEvents = 0,
    [string[]]$ExcludeUsers = @(),
    [string[]]$ExcludeSources = @(),
    [switch]$WatchMode,
    [string[]]$WatchUsers = @(),
    [switch]$NoShow
)

#region --------------------------------------------------------------- Decoders

$Script:LogonTypeMap = @{
    '0'  = 'System'
    '2'  = 'Interactive (console)'
    '3'  = 'Network (share/SMB)'
    '4'  = 'Batch (scheduled task)'
    '5'  = 'Service'
    '7'  = 'Unlock (workstation)'
    '8'  = 'NetworkCleartext'
    '9'  = 'NewCredentials (runas /netonly)'
    '10' = 'RemoteInteractive (RDP)'
    '11' = 'CachedInteractive (cached creds)'
    '12' = 'CachedRemoteInteractive'
    '13' = 'CachedUnlock'
}

# NTSTATUS / SubStatus codes seen on 4625 / 4776
$Script:StatusMap = @{
    '0xC0000064' = 'User name does not exist'
    '0xC000006A' = 'Wrong password'
    '0xC000006D' = 'Bad user name or password'
    '0xC000006E' = 'Account restriction (blank pwd / policy)'
    '0xC000006F' = 'Logon outside permitted hours'
    '0xC0000070' = 'Workstation restriction (not allowed to log on here)'
    '0xC0000071' = 'Password expired'
    '0xC0000072' = 'Account disabled'
    '0xC0000073' = 'No mapping between account names and SIDs'
    '0xC000005E' = 'No logon servers available'
    '0xC0000133' = 'Clocks out of sync between DC and client'
    '0xC0000193' = 'Account expired'
    '0xC0000224' = 'User must change password at next logon'
    '0xC0000234' = 'Account locked out'
    '0xC0000371' = 'Local account store does not contain secret'
    '0xC00002EE' = 'Unexpected error during logon'
    '0xC000015B' = 'User not granted requested logon type here'
    '0x0'        = 'OK / no error'
}

# Kerberos failure codes (4768 Result Code / 4771 Failure Code)
$Script:KerbMap = @{
    '0x6'  = 'Client (user) not found in Kerberos database'
    '0x7'  = 'Server not found in Kerberos database'
    '0xC'  = 'Policy: workstation restriction'
    '0x12' = 'Account disabled / expired / locked / logon-hours violation'
    '0x17' = 'Password has expired'
    '0x18' = 'Pre-auth failed: bad password'
    '0x20' = 'Ticket expired'
    '0x25' = 'Clock skew too great'
}

$Script:CategoryMap = @{
    4624 = 'Successful Logon'
    4625 = 'FAILED Logon'
    4634 = 'Logoff'
    4647 = 'User-Initiated Logoff'
    4648 = 'Explicit-Credential Logon'
    4672 = 'Special Privileges Assigned'
    4740 = 'ACCOUNT LOCKOUT'
    4767 = 'Account Unlocked'
    4768 = 'Kerberos TGT Requested'
    4769 = 'Kerberos Service Ticket'
    4771 = 'Kerberos Pre-Auth FAILED'
    4776 = 'NTLM Credential Validation'
    4778 = 'Session Reconnected (RDP/console)'
    4779 = 'Session Disconnected'
    4800 = 'Workstation Locked'
    4801 = 'Workstation Unlocked'
    4802 = 'Screensaver Invoked'
    4803 = 'Screensaver Dismissed'
    1074 = 'System Shutdown/Restart Initiated'
    6005 = 'Event Log Started (boot)'
    6006 = 'Event Log Stopped (clean shutdown)'
    6008 = 'UNEXPECTED Shutdown'
    41   = 'Kernel-Power: UNEXPECTED reboot/crash'
}

# Which log each event id lives in
$Script:SecurityIds = 4624,4625,4634,4647,4648,4672,4740,4767,4768,4769,4771,4776,4778,4779,4800,4801,4802,4803
$Script:SystemIds   = 1074,6005,6006,6008,41

# Friendly category groups used by the UI checkboxes
$Script:Groups = [ordered]@{
    'Failed logons (4625)'                 = @(4625)
    'Successful logons / approvals (4624)' = @(4624)
    'Account lockouts (4740)'              = @(4740)
    'Account unlocked (4767)'              = @(4767)
    'Logoff / sign-out (4634,4647)'        = @(4634,4647)
    'RDP connect/disconnect (4778,4779)'   = @(4778,4779)
    'Workstation lock/unlock (4800,4801)'  = @(4800,4801)
    'Kerberos (4768,4769,4771)'            = @(4768,4769,4771)
    'NTLM validation (4776)'               = @(4776)
    'Explicit credentials (4648)'          = @(4648)
    'Reboots / shutdowns (1074,6008,41)'   = @(1074,6005,6006,6008,41)
}

# Tooltip text per category checkbox (keyed by the same label).
$Script:GroupTips = @{
    'Failed logons (4625)'                 = 'Bad logon attempts (wrong password, disabled, expired, etc.). The #1 signal for lockout hunting - shows the source IP/host and the failure reason.'
    'Successful logons / approvals (4624)' = 'Successful sign-ins. Useful for "who logged in / from where", but very high volume on a DC - leave off unless you need it.'
    'Account lockouts (4740)'              = 'The lockout event itself (logged on the DC). The app auto-correlates each to the bad attempt that caused it. Keep this ON for lockout investigations.'
    'Account unlocked (4767)'              = 'An admin or process unlocked an account. Pairs with 4740 to see lock/unlock cycles.'
    'Logoff / sign-out (4634,4647)'        = 'Sessions ending - normal sign-out / disconnect. Used by the Logout Analyzer to spot mass drop-offs.'
    'RDP connect/disconnect (4778,4779)'   = 'Remote Desktop session reconnect/disconnect. Repeated disconnects often mean an idle/session-limit GPO or network drops.'
    'Workstation lock/unlock (4800,4801)'  = 'Screen lock/unlock on a machine. Frequent locks usually mean a screensaver/lock GPO, not a problem.'
    'Kerberos (4768,4769,4771)'            = 'Kerberos TGT/service-ticket requests and pre-auth failures (4771 = bad password via Kerberos). Key for tracing lockouts from domain-joined Windows clients.'
    'NTLM validation (4776)'               = 'NTLM credential checks on the DC. 4776 carries the Source Workstation name - often the only thing that identifies the device when 4740 is blank. Enable for lockout tracing.'
    'Explicit credentials (4648)'          = 'A logon made with explicit credentials (runas, mapped drive with /user, scheduled task). Common culprit for stale-password lockouts.'
    'Reboots / shutdowns (1074,6008,41)'   = 'System log: planned restart (1074), unexpected shutdown (6008) and kernel-power crash (41). Explains "everyone got logged off at once".'
}

function Get-DecodedStatus {
    param($code)
    if ([string]::IsNullOrWhiteSpace($code)) { return '' }
    $c = $code.Trim()
    if ($c -notmatch '^0x') { try { $c = ('0x{0:X}' -f [Convert]::ToInt64($c)) } catch {} }
    $c = $c.ToUpper().Replace('0X','0x')
    if ($Script:StatusMap.ContainsKey($c)) { return "$c - $($Script:StatusMap[$c])" }
    return $c
}

function Get-DecodedKerb {
    param($code)
    if ([string]::IsNullOrWhiteSpace($code)) { return '' }
    $c = $code.Trim().ToUpper().Replace('0X','0x')
    if ($Script:KerbMap.ContainsKey($c)) { return "$c - $($Script:KerbMap[$c])" }
    return $c
}

function Get-DecodedLogonType {
    param($lt)
    if ([string]::IsNullOrWhiteSpace($lt)) { return '' }
    if ($Script:LogonTypeMap.ContainsKey("$lt")) { return "$lt - $($Script:LogonTypeMap["$lt"])" }
    return "$lt"
}

#endregion

#region ----------------------------------------------------------- Query engine

# Turn raw EventLogRecord objects into flat, decoded rows.
function ConvertTo-AuditRow {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Evt)

    $data = @{}
    try {
        [xml]$x = $Evt.ToXml()
        foreach ($d in $x.Event.EventData.Data) {
            if ($d.Name) { $data[$d.Name] = [string]$d.'#text' }
        }
    } catch {}

    $id  = [int]$Evt.Id
    $cat = if ($Script:CategoryMap.ContainsKey($id)) { $Script:CategoryMap[$id] } else { "Event $id" }

    # Result classification
    $result = 'Info'
    switch ($id) {
        4625 { $result = 'Failure' }
        4771 { $result = 'Failure' }
        4740 { $result = 'Lockout' }
        6008 { $result = 'Failure' }
        41   { $result = 'Failure' }
        4624 { $result = 'Success' }
        4767 { $result = 'Success' }
        4776 { $result = if ($data['Status'] -and $data['Status'] -ne '0x0') { 'Failure' } else { 'Success' } }
        4768 { $result = if ($data['Status'] -and $data['Status'] -ne '0x0') { 'Failure' } else { 'Success' } }
        default { $result = 'Info' }
    }

    # User: prefer TargetUserName, fall back to specific fields per id
    $user = $data['TargetUserName']
    if (-not $user) { $user = $data['SubjectUserName'] }
    if ($id -eq 4776) { $user = $data['TargetUserName'] }
    if ($id -eq 4740) { $user = $data['TargetUserName'] }
    if (-not $user) { $user = '' }

    $domain = $data['TargetDomainName']
    if (-not $domain) { $domain = $data['SubjectDomainName'] }

    # Source host / IP
    $srcHost = $data['WorkstationName']
    if (-not $srcHost) { $srcHost = $data['Workstation'] }
    if ($id -eq 4740) { $srcHost = $data['CallerComputerName'] }
    $srcIp = "$($data['IpAddress'])" -replace '^::ffff:',''
    if ($srcIp -in @('-','::1','127.0.0.1')) { $srcIp = "$srcIp (local)" }

    # Extra auth context (key for "what is locking the account")
    $authPkg  = $data['AuthenticationPackageName']
    $logonProc= $data['LogonProcessName']
    $proc     = $data['ProcessName']
    if (-not $proc) { $proc = $data['CallerProcessName'] }

    # 4776 (NTLM validation on the DC) carries the *source workstation* name,
    # which is frequently the real machine when 4740 has no caller computer.
    if ($id -eq 4776) {
        $wks = $data['Workstation']
        if ($wks -and $wks -ne '-' -and -not $srcHost) { $srcHost = $wks }
        if (-not $user) { $user = $data['TargetUserName'] }
    }

    # Reason / decoded detail
    $reason = ''
    switch ($id) {
        4625 {
            $st  = Get-DecodedStatus $data['Status']
            $sub = Get-DecodedStatus $data['SubStatus']
            $why = if ($sub -and $sub -ne '0x0') { $sub } else { $st }
            $bits = @($why)
            $lt = Get-DecodedLogonType $data['LogonType']; if ($lt) { $bits += "Type $lt" }
            if ($authPkg) { $bits += $authPkg }
            if ($proc -and $proc -ne '-') { $bits += "proc $proc" }
            $reason = ($bits -join '  |  ')
        }
        4771 {
            $kc = $data['Status']; if (-not $kc) { $kc = $data['Failure'] }; if (-not $kc) { $kc = $data['FailureCode'] }
            $reason = Get-DecodedKerb $kc
        }
        4768 { if ($data['Status'] -and $data['Status'] -ne '0x0') { $reason = Get-DecodedKerb $data['Status'] } }
        4776 {
            $w = $data['Workstation']
            if ($data['Status'] -and $data['Status'] -ne '0x0') {
                $reason = "NTLM FAILED ($(Get-DecodedStatus $data['Status']))"
            } else { $reason = 'NTLM validated' }
            if ($w -and $w -ne '-') { $reason += "  |  from workstation $w" }
        }
        4740 {
            $cc = $data['CallerComputerName']
            $reason = if ($cc -and $cc -ne '-') { "Locked by: $cc" }
                      else { 'Locked out - caller not in 4740 (NTLM/network); see correlated source' }
        }
        4634 { $reason = Get-DecodedLogonType $data['LogonType'] }
        4647 { $reason = 'User initiated sign-out' }
    }

    $logonType = Get-DecodedLogonType $data['LogonType']

    # Normalized failure code/reason per event id (for the CSV export)
    $failCode = ''; $failReason = ''
    switch ($id) {
        4625 {
            $failCode = if ($data['SubStatus'] -and $data['SubStatus'] -ne '0x0') { $data['SubStatus'] } else { $data['Status'] }
            $failReason = Get-DecodedStatus $failCode
        }
        4771 { $failCode = $data['Status']; if (-not $failCode) { $failCode = $data['Failure'] }; $failReason = Get-DecodedKerb $failCode }
        4768 { $failCode = $data['Status']; $failReason = Get-DecodedKerb $failCode }
        4776 { $failCode = $data['Status']; $failReason = Get-DecodedStatus $failCode }
    }
    $callerComp = $data['CallerComputerName']
    if ($id -eq 4740 -and -not $callerComp) { $callerComp = $data['TargetDomainName'] }

    [pscustomobject]@{
        Time        = $Evt.TimeCreated
        TimeStr     = $Evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        EventId     = $id
        Result      = $result
        Category    = $cat
        User        = $user
        Domain      = $domain
        SourceHost  = $srcHost
        SourceIP    = $srcIp
        LogonType   = $logonType
        Reason      = $reason
        FailureCode = "$failCode"
        FailureReason = "$failReason"
        LoggedOn    = $Evt.MachineName
        Process     = $proc
        AuthPkg     = $authPkg
        LogonProc   = $logonProc
        CallerComp  = $callerComp
        Message     = ($Evt.FormatDescription())
    }
}

# The heavy lifting. Returns an array of audit rows. Used by GUI (in a runspace)
# and by -Cli mode (directly). Self-contained on purpose.
function Invoke-AuditQuery {
    param(
        [string]$ComputerName,
        [int[]]$EventIds,
        [datetime]$Start,
        [datetime]$End,
        [string]$UserFilter = '*',
        [int]$MaxEvents = 100000,
        [pscredential]$Credential
    )
    if ($MaxEvents -le 0) { $MaxEvents = 100000 }

    $secIds = @($EventIds | Where-Object { $_ -in $Script:SecurityIds })
    $sysIds = @($EventIds | Where-Object { $_ -in $Script:SystemIds  })
    $rows   = New-Object System.Collections.Generic.List[object]
    $isLocal = $ComputerName -in @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')

    # One server-side filtered query per log. Get-WinEvent's FilterHashtable
    # does the StartTime/EndTime/Id filtering on the DC and -MaxEvents bounds
    # the result, so a single call is far faster than many time slices
    # (per-call RPC overhead made >24h windows time out).
    $logs = @()
    if ($secIds.Count) { $logs += ,@('Security', $secIds) }
    if ($sysIds.Count) { $logs += ,@('System',   $sysIds) }

    foreach ($lg in $logs) {
        $remaining = $MaxEvents - $rows.Count
        if ($remaining -le 0) { break }
        $filter = @{ LogName=$lg[0]; Id=$lg[1]; StartTime=$Start; EndTime=$End }
        $params = @{ FilterHashtable=$filter; MaxEvents=$remaining; ErrorAction='Stop' }
        if (-not $isLocal)                  { $params['ComputerName'] = $ComputerName }
        if ($Credential -and -not $isLocal) { $params['Credential']  = $Credential }
        try {
            $raw = Get-WinEvent @params
        } catch [System.Diagnostics.Eventing.Reader.EventLogException] {
            throw "Cannot read '$($lg[0])' on '$ComputerName': $($_.Exception.Message). " +
                  "Ensure the account is in 'Event Log Readers' / local admin and that " +
                  "Remote Event Log Management is allowed through the firewall."
        } catch {
            if ("$($_.Exception.Message)" -match 'No events were found') { continue }
            throw $_
        }
        foreach ($e in $raw) {
            $row = ConvertTo-AuditRow -Evt $e
            if ($UserFilter -and $UserFilter -ne '*') {
                if ($row.User -notlike $UserFilter) { continue }
            }
            $rows.Add($row)
        }
    }
    return ($rows | Sort-Object Time -Descending)
}

#endregion

#region ------------------------------------------------ Config & DC discovery

$Script:ConfigDir  = Join-Path $env:APPDATA 'WinLogonAuditor'
$Script:ConfigPath = Join-Path $Script:ConfigDir 'config.json'

function New-ExcludesObject {
    param($Src)
    $u = @(); $s = @(); $d = @()
    if ($Src) {
        if ($Src.Users)   { $u = @($Src.Users) }
        if ($Src.Sources) { $s = @($Src.Sources) }
        if ($Src.DCs)     { $d = @($Src.DCs) }
    }
    [pscustomobject]@{ Users = $u; Sources = $s; DCs = $d }
}

function Get-AuditConfig {
    # Additive defaults - old config.json files keep working.
    $def = [pscustomobject]@{
        Servers = @(); LastTarget = ''; QueryAllDcs = $true
        MaxEventsPerCategory = 100000; LookbackMinutes = 60
        WatchInterval = 30; WatchUsers = @()
        Excludes = (New-ExcludesObject $null)
    }
    try {
        if (Test-Path $Script:ConfigPath) {
            $c = Get-Content $Script:ConfigPath -Raw | ConvertFrom-Json
            if (-not $c.Servers)                 { $c | Add-Member Servers @() -Force }
            if ($null -eq $c.LastTarget)         { $c | Add-Member LastTarget '' -Force }
            if ($null -eq $c.QueryAllDcs)        { $c | Add-Member QueryAllDcs $false -Force }
            if (-not $c.MaxEventsPerCategory)    { $c | Add-Member MaxEventsPerCategory 100000 -Force }
            if (-not $c.LookbackMinutes)         { $c | Add-Member LookbackMinutes 60 -Force }
            if (-not $c.WatchInterval)           { $c | Add-Member WatchInterval 30 -Force }
            if ($null -eq $c.WatchUsers)         { $c | Add-Member WatchUsers @() -Force }
            $c | Add-Member Excludes (New-ExcludesObject $c.Excludes) -Force
            return $c
        }
    } catch {}
    return $def
}

function Save-AuditConfig {
    param($Config)
    try {
        if (-not (Test-Path $Script:ConfigDir)) { New-Item -ItemType Directory -Path $Script:ConfigDir -Force | Out-Null }
        $Config | ConvertTo-Json -Depth 6 | Set-Content -Path $Script:ConfigPath -Encoding UTF8
    } catch {}
}

# Wildcard-aware match of a value against a list of patterns (case-insensitive).
function Test-MatchAny {
    param([string]$Value, $Patterns)
    if (-not $Value -or -not $Patterns) { return $false }
    foreach ($p in @($Patterns)) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        if ($Value -like $p) { return $true }
    }
    return $false
}

# True when a row should be hidden by the exclude lists.
function Test-RowExcluded {
    param($Row, $Excludes)
    if (-not $Excludes) { return $false }
    if (Test-MatchAny $Row.User       $Excludes.Users)   { return $true }
    if (Test-MatchAny $Row.SourceHost $Excludes.Sources) { return $true }
    if (Test-MatchAny $Row.SourceIP   $Excludes.Sources) { return $true }
    if (Test-MatchAny $Row.LoggedOn   $Excludes.DCs)     { return $true }
    return $false
}

#endregion

#region ----------------------------------------------------------- Run logging

$Script:AppVersion = '1.1.4'
$Script:LogDir = Join-Path $env:TEMP 'WinLogonAuditor\logs'
try { if (-not (Test-Path $Script:LogDir)) { New-Item -ItemType Directory -Path $Script:LogDir -Force | Out-Null } } catch {}
$Script:RunLog = Join-Path $Script:LogDir ("WinLogonAuditor_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    try {
        if (-not (Test-Path $Script:LogDir)) { New-Item -ItemType Directory -Path $Script:LogDir -Force | Out-Null }
        $line = "[{0}] [{1}] {2}`r`n" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
        [System.IO.File]::AppendAllText($Script:RunLog, $line)
    } catch {}
}

# Keep only the 10 most recent run logs in the log folder.
function Limit-RunLogs {
    try {
        Get-ChildItem -Path $Script:LogDir -Filter 'WinLogonAuditor_*.log' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -Skip 10 |
            ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }
        # One-time migration: clear old logs that were written directly in %TEMP%.
        Get-ChildItem -Path $env:TEMP -Filter 'WinLogonAuditor_*.log' -ErrorAction SilentlyContinue |
            ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }
    } catch {}
}

Write-Log ("WinLogonAuditor v{0} starting | OS {1} | PS {2} | user {3}\{4} | mode {5}" -f `
    $Script:AppVersion, [Environment]::OSVersion.Version, $PSVersionTable.PSVersion,
    $env:USERDOMAIN, $env:USERNAME, $(if ($Cli) { 'CLI' } elseif ($NoShow) { 'SelfTest' } else { 'GUI' }))
Limit-RunLogs

# Enumerate domain controllers for the current (or a specified) domain.
# Works on any domain-joined machine without RSAT. Optional alternate
# credentials let you point at another domain / use different rights.
function Get-DomainControllerList {
    param(
        [string]$DomainName,
        [pscredential]$Credential
    )
    foreach ($asm in 'System.DirectoryServices','System.DirectoryServices.ActiveDirectory') {
        try { Add-Type -AssemblyName $asm -ErrorAction Stop } catch {}
    }
    $result = [ordered]@{ DCs = @(); Pdc = $null; Domain = $DomainName; Error = $null }
    try {
        if ($Credential) {
            $dom = if ($DomainName) { $DomainName } else { $env:USERDNSDOMAIN }
            $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(
                'Domain', $dom, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
        } elseif ($DomainName) {
            $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $DomainName)
            $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
        } else {
            $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        $result.Domain = $d.Name
        $result.DCs    = @($d.DomainControllers | ForEach-Object { $_.Name } | Sort-Object)
        try { $result.Pdc = $d.PdcRoleOwner.Name } catch {}
    } catch {
        $result.Error = $_.Exception.Message
    }
    return [pscustomobject]$result
}

#endregion

#region ------------------------------------------------------- Shared helpers

# Event-aware normalized CSV schema (Feature 5). One stable column set;
# each column is filled from the right field for that event id, IPv6
# ::ffff: prefix already stripped upstream, empty (not null) when n/a.
function ConvertTo-ExportRow {
    param($Row)
    [pscustomobject][ordered]@{
        TimeStr       = $Row.TimeStr
        EventId       = $Row.EventId
        Result        = $Row.Result
        Category      = $Row.Category
        User          = $Row.User
        Domain        = $Row.Domain
        SourceHost    = $Row.SourceHost
        SourceIP      = ($Row.SourceIP -replace '^::ffff:','')
        CallerComputer= $Row.CallerComp
        LogonType     = $Row.LogonType
        FailureCode   = $Row.FailureCode
        FailureReason = $Row.FailureReason
        Reason        = $Row.Reason
        LoggedOn      = $Row.LoggedOn
    }
}

function Export-AuditCsv {
    param($Rows, [string]$Path)
    @($Rows | ForEach-Object { ConvertTo-ExportRow $_ }) |
        Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

# Feature 3/4 core: for a user, pull lockouts + the preceding NTLM/Kerberos
# failure trail across the given targets, resolve source IPs (cached), and
# return flat trail rows. $DnsCache is a hashtable reused across calls.
function Invoke-LockoutTrace {
    param(
        [string[]]$Targets,
        [string]$User,
        [int]$LookbackMinutes = 60,
        [pscredential]$Credential,
        [hashtable]$DnsCache = @{}
    )
    $end   = Get-Date
    $start = $end.AddMinutes(-([math]::Max(1,$LookbackMinutes)))
    $trail = New-Object System.Collections.Generic.List[object]
    foreach ($tgt in @($Targets)) {
        try {
            $r = Invoke-AuditQuery -ComputerName $tgt -EventIds 4740,4771,4625,4768,4776 `
                    -Start $start -End $end -UserFilter "*$User*" -MaxEvents 50000 -Credential $Credential
        } catch { continue }
        foreach ($x in @($r)) {
            $ip = "$($x.SourceIP)" -replace '^::ffff:',''
            $hostName = $x.SourceHost
            if (-not $hostName -and $ip -match '^\d{1,3}(\.\d{1,3}){3}$') {
                if (-not $DnsCache.ContainsKey($ip)) {
                    $h = $null
                    try { $h = [System.Net.Dns]::GetHostEntry($ip).HostName } catch {}
                    $DnsCache[$ip] = $h
                }
                if ($DnsCache[$ip]) { $hostName = $DnsCache[$ip] }
            }
            $trail.Add([pscustomobject]@{
                LockoutTime  = if ($x.EventId -eq 4740) { $x.TimeStr } else { '' }
                Time         = $x.Time
                FailureTime  = $x.TimeStr
                EventId      = $x.EventId
                Kind         = $x.Category
                User         = $x.User
                ClientIP     = $ip
                ClientHost   = $hostName
                FailureCode  = $x.FailureCode
                FailureReason= if ($x.FailureReason) { $x.FailureReason } else { $x.Reason }
                DcLogged     = $x.LoggedOn
            })
        }
    }
    return @($trail | Sort-Object Time -Descending)
}

#endregion

#region --------------------------------------------------------------- CLI mode

if ($Cli) {
    $cfg0   = Get-AuditConfig
    $maxN0  = if ($MaxEvents -gt 0) { $MaxEvents } else { [int]$cfg0.MaxEventsPerCategory }
    $exU    = @($ExcludeUsers)   + @($cfg0.Excludes.Users)
    $exS    = @($ExcludeSources) + @($cfg0.Excludes.Sources)
    $exObj  = [pscustomobject]@{ Users=$exU; Sources=$exS; DCs=@($cfg0.Excludes.DCs) }

    if ($WatchMode) {
        $wu = if ($WatchUsers) { $WatchUsers } else { @($cfg0.WatchUsers) }
        $iv = [int]$cfg0.WatchInterval; if ($iv -lt 5) { $iv = 30 }
        $hist = Join-Path $Script:ConfigDir ("LockoutHunt_{0}.csv" -f (Get-Date -Format yyyyMMdd))
        Write-Host "WinLogonAuditor WATCH - target $Target - users [$($wu -join ', ')] - every ${iv}s. Ctrl+C to stop." -ForegroundColor Cyan
        $seen = @{}; $dns = @{}
        while ($true) {
            foreach ($u in @($wu)) {
                $tr = Invoke-LockoutTrace -Targets @($Target) -User $u -LookbackMinutes $cfg0.LookbackMinutes -DnsCache $dns
                $newLocks = @($tr | Where-Object { $_.EventId -eq 4740 -and -not $seen.ContainsKey("$($_.FailureTime)|$($_.User)") })
                foreach ($lk in $newLocks) {
                    $seen["$($lk.FailureTime)|$($lk.User)"] = $true
                    $tr | Export-Csv -Path $hist -NoTypeInformation -Encoding UTF8 -Append
                    Write-Host ("[{0}] LOCKOUT {1} - see {2}" -f $lk.FailureTime, $lk.User, $hist) -ForegroundColor Yellow
                }
            }
            Start-Sleep -Seconds $iv
        }
        return
    }

    Write-Host "WinLogonAuditor (CLI) - target: $Target  user: $User  window: ${Hours}h  max: $maxN0" -ForegroundColor Cyan
    $allIds = $Script:SecurityIds + $Script:SystemIds
    $res = Invoke-AuditQuery -ComputerName $Target -EventIds $allIds `
              -Start (Get-Date).AddHours(-$Hours) -End (Get-Date) -UserFilter $User -MaxEvents $maxN0
    $kept = @($res | Where-Object { -not (Test-RowExcluded $_ $exObj) })
    $dropped = $res.Count - $kept.Count
    $outPath = if ($dropped -gt 0) { [IO.Path]::ChangeExtension($OutFile,$null).TrimEnd('.') + '_filtered.csv' } else { $OutFile }
    Export-AuditCsv -Rows $kept -Path $outPath
    Write-Host ("{0} events written to {1} ({2} excluded)" -f $kept.Count, $outPath, $dropped) -ForegroundColor Green
    $kept | Group-Object Category | Sort-Object Count -Descending |
        Select-Object Count,Name | Format-Table -AutoSize
    return
}

#endregion

#region ----------------------------------------------------------------- WPF UI

# Relaunch in STA if needed (WPF requires single-threaded apartment).
# Skipped when packaged as an .exe (PS2EXE already runs STA and there is no
# .ps1 to relaunch) - guarded by the $PSCommandPath check.
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA' -and
    $PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) {
    $exe = (Get-Process -Id $PID).Path
    & $exe -NoProfile -ExecutionPolicy Bypass -Sta -File $PSCommandPath @PSBoundParameters
    return
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms, System.Drawing

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="WinLogonAuditor - Logon / Lockout / Logoff Auditing" Height="820" Width="1380"
        WindowStartupLocation="CenterScreen" Background="#FF1E1E2E">
  <Window.Resources>
    <Style TargetType="TextBlock"><Setter Property="Foreground" Value="#FFE6E6E6"/><Setter Property="VerticalAlignment" Value="Center"/></Style>
    <Style TargetType="Label"><Setter Property="Foreground" Value="#FFE6E6E6"/></Style>
    <Style TargetType="CheckBox"><Setter Property="Foreground" Value="#FFE6E6E6"/><Setter Property="Margin" Value="6,3"/></Style>
    <Style TargetType="Button">
      <Setter Property="Background" Value="#FF3B82F6"/><Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderThickness" Value="0"/><Setter Property="Padding" Value="12,6"/>
      <Setter Property="Margin" Value="4,0"/><Setter Property="Cursor" Value="Hand"/>
    </Style>
    <Style TargetType="TabItem">
      <Setter Property="Background" Value="#FF2A2A3C"/><Setter Property="Foreground" Value="#FFE6E6E6"/>
      <Setter Property="Padding" Value="14,6"/>
    </Style>
  </Window.Resources>
  <Grid Margin="10">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/><RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Query bar -->
    <Border Grid.Row="0" Background="#FF272739" CornerRadius="6" Padding="10" Margin="0,0,0,8">
      <WrapPanel>
        <TextBlock Text="Target (DC/host):" Margin="0,0,6,0"/>
        <ComboBox x:Name="CmbTarget" Width="190" IsEditable="True" Margin="0,0,4,0"
                  ToolTip="The server to query (a domain controller or any host). Type a name/FQDN or pick a saved one, e.g. eDC1.ad.salus.edu. Ignored when 'Query all DCs' is ticked."/>
        <Button x:Name="BtnDiscover" Content="Discover DCs" Background="#FF6B7280"
                ToolTip="Find every domain controller in the domain and add them to the list, auto-selecting the PDC emulator (the best single target for lockouts). Tick 'Alt credentials' first if your logon can't read the DCs."/>
        <Button x:Name="BtnManage" Content="Servers..." Background="#FF6B7280" Margin="0,0,12,0"
                ToolTip="Add or remove servers in your saved target list (stored in config.json)."/>
        <CheckBox x:Name="ChkAllDc" Content="Query all DCs"
                  ToolTip="Query every discovered domain controller in parallel and merge the results. Best for lockouts (4740 lands on whichever DC processed it). Slower than a single target."/>
        <TextBlock Text="User (wildcards ok):" Margin="0,0,6,0"/>
        <TextBox x:Name="TxtUser" Width="150" Text="*" Margin="0,0,14,0"
                 ToolTip="Filter by account name. * = all users. Wildcards allowed, e.g. jsmith  svc-*  *admin*"/>
        <TextBlock Text="Range:" Margin="0,0,6,0"/>
        <ComboBox x:Name="CmbRange" Width="150" Margin="0,0,8,0"
                  ToolTip="How far back to look. Shorter ranges are much faster on busy DCs - use Last 1-8 hours for live incidents; pick 'Custom range' to set exact From/To dates.">
          <ComboBoxItem Content="Last 1 hour"/>
          <ComboBoxItem Content="Last 8 hours"/>
          <ComboBoxItem Content="Last 24 hours" IsSelected="True"/>
          <ComboBoxItem Content="Last 3 days"/>
          <ComboBoxItem Content="Last 7 days"/>
          <ComboBoxItem Content="Custom range"/>
        </ComboBox>
        <DatePicker x:Name="DtFrom" Width="120" Margin="0,0,4,0" IsEnabled="False"
                    ToolTip="Start date (enabled when Range = Custom range)."/>
        <DatePicker x:Name="DtTo" Width="120" Margin="0,0,14,0" IsEnabled="False"
                    ToolTip="End date, inclusive (enabled when Range = Custom range)."/>
        <TextBlock Text="Max events/DC:" Margin="0,0,6,0"/>
        <TextBox x:Name="TxtMax" Width="75" Text="100000" Margin="0,0,10,0"
                 ToolTip="Maximum events returned per DC (applied per controller, not in aggregate). If hit, an amber banner shows and you get the most recent N within the window. Lower it (e.g. 20000) for faster sweeps; raise it if you see 'CAP HIT'."/>
        <TextBlock Text="Timeout/DC (s):" Margin="0,0,6,0"/>
        <TextBox x:Name="TxtTimeout" Width="50" Text="45" Margin="0,0,14,0"
                 ToolTip="Give up on a single DC after this many seconds and skip it so the others still return. Raise it (e.g. 120-300) for a busy PDC over a long range; a short Range is usually a better fix."/>
        <CheckBox x:Name="ChkCred" Content="Alt credentials"
                  ToolTip="Prompt for a different domain account to read the logs / discover DCs (use when your current logon lacks 'Event Log Readers' on the DCs)."/>
        <Button x:Name="BtnQuery" Content="Run Query"
                ToolTip="Run the query now with the settings above. Nothing is queried until you click this."/>
        <Button x:Name="BtnExport" Content="Export CSV" Background="#FF6B7280"
                ToolTip="Save the current results to a CSV (event-aware columns incl. FailureCode/Reason). Filename gets a _filtered suffix when exclude lists are active."/>
        <Button x:Name="BtnExcludes" Content="Excludes..." Background="#FF6B7280"
                ToolTip="Edit the noise filters: Users / Sources / DCs (wildcards ok, e.g. solarwinds  *$  10.5.121.*). Excluded rows are dropped from the grid, summary and export. Tip: right-click a row to mute it instantly."/>
        <CheckBox x:Name="ChkAuto" Content="Auto-refresh 60s"
                  ToolTip="Re-run the same query automatically every 60 seconds (handy for an active incident). Turn off for long multi-DC sweeps."/>
        <CheckBox x:Name="ChkWatch" Content="Watch"
                  ToolTip="Continuously poll for NEW lockouts of your watched users (config.json WatchUsers, or the Lockout Investigator username), pop a tray toast naming the likely source, and append %TEMP%\..\LockoutHunt_yyyyMMdd.csv - works in the background."/>
      </WrapPanel>
    </Border>

    <!-- Category filters + warning banner -->
    <Border Grid.Row="1" Background="#FF272739" CornerRadius="6" Padding="8" Margin="0,0,0,8">
      <StackPanel>
        <WrapPanel x:Name="PnlCats"/>
        <Border x:Name="WarnBanner" Visibility="Collapsed" Background="#FF7A3B12"
                CornerRadius="4" Padding="8,5" Margin="0,8,0,0">
          <TextBlock x:Name="TxtWarn" Foreground="#FFFFD9A8" TextWrapping="Wrap"/>
        </Border>
      </StackPanel>
    </Border>

    <!-- Tabs -->
    <TabControl Grid.Row="2" Background="#FF1E1E2E" BorderBrush="#FF3A3A4C">
      <TabItem Header="Events">
        <Grid>
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
          <DockPanel Grid.Row="0" Margin="0,4">
            <TextBlock Text="Quick filter:" DockPanel.Dock="Left" Margin="2,0,6,0"/>
            <TextBox x:Name="TxtFilter"
                     ToolTip="Instantly narrows the rows already loaded (no re-query). Matches user, source host/IP, category, reason, event ID or DC. Example: type 0xC000006A or 4740 or a hostname."/>
          </DockPanel>
          <DataGrid x:Name="Grid" Grid.Row="1" AutoGenerateColumns="False" IsReadOnly="True"
                    Background="#FF1E1E2E" Foreground="#FFE6E6E6" GridLinesVisibility="Horizontal"
                    RowBackground="#FF252536" AlternatingRowBackground="#FF2A2A3C"
                    HeadersVisibility="Column" SelectionMode="Single" EnableRowVirtualization="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Time" Binding="{Binding TimeStr}" Width="140"/>
              <DataGridTextColumn Header="ID" Binding="{Binding EventId}" Width="55"/>
              <DataGridTextColumn Header="Result" Binding="{Binding Result}" Width="70"/>
              <DataGridTextColumn Header="Category" Binding="{Binding Category}" Width="190"/>
              <DataGridTextColumn Header="User" Binding="{Binding User}" Width="140"/>
              <DataGridTextColumn Header="Domain" Binding="{Binding Domain}" Width="100"/>
              <DataGridTextColumn Header="Source Host" Binding="{Binding SourceHost}" Width="130"/>
              <DataGridTextColumn Header="Source IP" Binding="{Binding SourceIP}" Width="120"/>
              <DataGridTextColumn Header="Logon Type" Binding="{Binding LogonType}" Width="170"/>
              <DataGridTextColumn Header="Reason / Detail" Binding="{Binding Reason}" Width="260"/>
              <DataGridTextColumn Header="Logged On" Binding="{Binding LoggedOn}" Width="120"/>
            </DataGrid.Columns>
          </DataGrid>
          <Border Grid.Row="2" Background="#FF272739" CornerRadius="4" Margin="0,6,0,0" Padding="8" MaxHeight="150">
            <ScrollViewer VerticalScrollBarVisibility="Auto">
              <TextBlock x:Name="TxtDetail" TextWrapping="Wrap" FontFamily="Consolas" Text="Select a row to see the full event message."/>
            </ScrollViewer>
          </Border>
        </Grid>
      </TabItem>

      <TabItem Header="Lockout Investigator">
        <Grid Margin="6">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/><RowDefinition Height="160"/><RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <StackPanel Orientation="Horizontal" Grid.Row="0" Margin="0,0,0,8">
            <TextBlock Text="Locked user:" Margin="0,0,6,0"/>
            <TextBox x:Name="TxtLockUser" Width="170" Margin="0,0,10,0"
                     ToolTip="The locked account to investigate, e.g. jsmith (partial match ok). This is also the user Watch mode monitors if WatchUsers isn't set in config.json."/>
            <TextBlock Text="Lookback (min):" Margin="0,0,6,0"/>
            <TextBox x:Name="TxtLookback" Width="60" Text="60" Margin="0,0,10,0"
                     ToolTip="How many minutes before now to scan for the lockout trail (4740 + preceding 4771/4625/4776). 60 is usually enough; widen if the lockout was a while ago."/>
            <Button x:Name="BtnLockGo" Content="Trace lockout source"
                    ToolTip="Live-query the selected target / all DCs for this user's lockouts and the bad-password attempts that preceded them, resolve source IPs to hostnames, and rank the offending devices with a plain-English verdict."/>
            <TextBlock Text="(queries the selected target/all-DCs live)" Margin="12,0,0,0" Foreground="#FF8A8FB0"/>
          </StackPanel>
          <Border Grid.Row="1" Background="#FF272739" CornerRadius="4" Padding="8" Margin="0,0,0,8">
            <TextBlock x:Name="TxtLockInfo" Foreground="#FFFFC857" TextWrapping="Wrap"
                       Text="Enter a locked username and click Trace. Pulls 4740 + the preceding 4771/4625/4776 trail, resolves source IPs to hostnames, and ranks the offending sources."/>
          </Border>
          <TextBlock Grid.Row="2" Text="Offending sources (ranked):" Margin="0,0,0,4" FontWeight="SemiBold"/>
          <DataGrid x:Name="GridLockSrc" Grid.Row="3" AutoGenerateColumns="False" IsReadOnly="True"
                    Background="#FF1E1E2E" Foreground="#FFE6E6E6" RowBackground="#FF252536"
                    AlternatingRowBackground="#FF2A2A3C" HeadersVisibility="Column">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Source (host / IP)" Binding="{Binding Src}" Width="320"/>
              <DataGridTextColumn Header="Bad attempts" Binding="{Binding Count}" Width="110"/>
              <DataGridTextColumn Header="Lockouts" Binding="{Binding Locks}" Width="90"/>
              <DataGridTextColumn Header="Typical failure" Binding="{Binding Why}" Width="320"/>
              <DataGridTextColumn Header="Last seen" Binding="{Binding LastStr}" Width="150"/>
            </DataGrid.Columns>
          </DataGrid>
          <DataGrid x:Name="GridLock" Grid.Row="4" Margin="0,8,0,0" AutoGenerateColumns="False" IsReadOnly="True"
                    Background="#FF1E1E2E" Foreground="#FFE6E6E6" RowBackground="#FF252536"
                    AlternatingRowBackground="#FF2A2A3C" HeadersVisibility="Column">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Time" Binding="{Binding FailureTime}" Width="140"/>
              <DataGridTextColumn Header="ID" Binding="{Binding EventId}" Width="55"/>
              <DataGridTextColumn Header="Kind" Binding="{Binding Kind}" Width="190"/>
              <DataGridTextColumn Header="User" Binding="{Binding User}" Width="130"/>
              <DataGridTextColumn Header="Client Host" Binding="{Binding ClientHost}" Width="170"/>
              <DataGridTextColumn Header="Client IP" Binding="{Binding ClientIP}" Width="120"/>
              <DataGridTextColumn Header="Code" Binding="{Binding FailureCode}" Width="80"/>
              <DataGridTextColumn Header="Failure reason" Binding="{Binding FailureReason}" Width="260"/>
              <DataGridTextColumn Header="DC" Binding="{Binding DcLogged}" Width="120"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>

      <TabItem Header="Logout Analyzer">
        <Grid Margin="6">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <TextBlock Grid.Row="0" Margin="0,0,0,8" TextWrapping="Wrap" Foreground="#FFB8C0FF"
            Text="Why were users logged off? This view pulls logoffs, RDP disconnects, workstation locks, account lockouts and unexpected reboots/shutdowns in the selected window and groups them by user so you can spot a pattern (mass reboot, GPO, lockout storm, RDP idle timeout)."/>
          <DataGrid x:Name="GridOut" Grid.Row="1" AutoGenerateColumns="False" IsReadOnly="True"
                    Background="#FF1E1E2E" Foreground="#FFE6E6E6" RowBackground="#FF252536"
                    AlternatingRowBackground="#FF2A2A3C" HeadersVisibility="Column">
            <DataGrid.Columns>
              <DataGridTextColumn Header="User" Binding="{Binding User}" Width="170"/>
              <DataGridTextColumn Header="Logoffs" Binding="{Binding Logoffs}" Width="80"/>
              <DataGridTextColumn Header="RDP Disc." Binding="{Binding RdpDisc}" Width="90"/>
              <DataGridTextColumn Header="Locks" Binding="{Binding Locks}" Width="80"/>
              <DataGridTextColumn Header="Lockouts" Binding="{Binding Lockouts}" Width="90"/>
              <DataGridTextColumn Header="Last Event" Binding="{Binding LastStr}" Width="150"/>
              <DataGridTextColumn Header="Likely cause" Binding="{Binding Likely}" Width="420"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>

      <TabItem Header="Summary">
        <Grid Margin="6">
          <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
          <GroupBox Header="By category" Grid.Column="0" Foreground="#FFE6E6E6" Margin="2">
            <DataGrid x:Name="GridSumCat" AutoGenerateColumns="False" IsReadOnly="True" Background="#FF1E1E2E" Foreground="#FFE6E6E6" RowBackground="#FF252536">
              <DataGrid.Columns>
                <DataGridTextColumn Header="Category" Binding="{Binding Name}" Width="*"/>
                <DataGridTextColumn Header="Count" Binding="{Binding Count}" Width="70"/>
              </DataGrid.Columns>
            </DataGrid>
          </GroupBox>
          <GroupBox Header="Top users by failures" Grid.Column="1" Foreground="#FFE6E6E6" Margin="2">
            <DataGrid x:Name="GridSumUser" AutoGenerateColumns="False" IsReadOnly="True" Background="#FF1E1E2E" Foreground="#FFE6E6E6" RowBackground="#FF252536">
              <DataGrid.Columns>
                <DataGridTextColumn Header="User" Binding="{Binding Name}" Width="*"/>
                <DataGridTextColumn Header="Failures" Binding="{Binding Count}" Width="80"/>
              </DataGrid.Columns>
            </DataGrid>
          </GroupBox>
          <GroupBox Header="Top source hosts/IPs by failures" Grid.Column="2" Foreground="#FFE6E6E6" Margin="2">
            <DataGrid x:Name="GridSumSrc" AutoGenerateColumns="False" IsReadOnly="True" Background="#FF1E1E2E" Foreground="#FFE6E6E6" RowBackground="#FF252536">
              <DataGrid.Columns>
                <DataGridTextColumn Header="Source" Binding="{Binding Name}" Width="*"/>
                <DataGridTextColumn Header="Failures" Binding="{Binding Count}" Width="80"/>
              </DataGrid.Columns>
            </DataGrid>
          </GroupBox>
        </Grid>
      </TabItem>
    </TabControl>

    <!-- Progress overlay: covers the tab area while a query runs -->
    <Border x:Name="PnlProgress" Grid.Row="2" Visibility="Collapsed" Panel.ZIndex="10"
            Background="#F21E1E2E">
      <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center" Width="540">
        <TextBlock x:Name="TxtProgBig" Text="Working..." FontSize="21" FontWeight="SemiBold"
                   HorizontalAlignment="Center" Margin="0,0,0,16"/>
        <ProgressBar x:Name="PrgOverlay" Height="24" Minimum="0" Maximum="100" Value="0"
                     Foreground="#FF3B82F6" Background="#FF2A2A3C" BorderThickness="0"/>
        <TextBlock x:Name="TxtProgSub" Text="" Foreground="#FFB8C0FF"
                   HorizontalAlignment="Center" Margin="0,12,0,0" TextWrapping="Wrap"/>
        <Button x:Name="BtnCancel" Content="Cancel" Width="100" Margin="0,20,0,0"
                HorizontalAlignment="Center" Background="#FF6B7280"/>
      </StackPanel>
    </Border>

    <StatusBar Grid.Row="3" Background="#FF272739" Margin="0,8,0,0">
      <StatusBarItem HorizontalContentAlignment="Stretch" Width="1320">
        <DockPanel LastChildFill="True">
          <ProgressBar x:Name="PrgBar" DockPanel.Dock="Right" Width="180" Height="14"
                       Minimum="0" Maximum="100" Visibility="Collapsed" Margin="10,0,0,0"
                       Foreground="#FF3B82F6" Background="#FF2A2A3C"/>
          <TextBlock x:Name="TxtStatus" Text="Ready - set your filters (time range, user, categories) and click Run Query."/>
        </DockPanel>
      </StatusBarItem>
    </StatusBar>
  </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$Script:Win    = [Windows.Markup.XamlReader]::Load($reader)

# Title-bar / taskbar icon. As a .ps1 we load assets\winlogonauditor.ico;
# packaged as .exe we lift the icon embedded by PS2EXE (-iconFile).
try {
    $icoStream = $null
    $icoPath = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'assets\winlogonauditor.ico'
    if ($PSCommandPath -and (Test-Path -LiteralPath $icoPath)) {
        $icoStream = [System.IO.File]::OpenRead($icoPath)
    } else {
        $exe = (Get-Process -Id $PID).Path
        $ic  = [System.Drawing.Icon]::ExtractAssociatedIcon($exe)
        if ($ic) { $ms = New-Object System.IO.MemoryStream; $ic.ToBitmap().Save($ms,[System.Drawing.Imaging.ImageFormat]::Png); $ms.Position=0; $icoStream=$ms }
    }
    if ($icoStream) {
        $Script:Win.Icon = [System.Windows.Media.Imaging.BitmapFrame]::Create(
            $icoStream, 'OnLoad', 'Default')
    }
} catch {}

# Resolve named controls
$Script:ctl = @{}
$xaml.SelectNodes("//*[@*[local-name()='Name']]") | ForEach-Object {
    $n = $_.Attributes['x:Name'].Value
    if ($n) { $Script:ctl[$n] = $Script:Win.FindName($n) }
}

# Build category checkboxes
$Script:CatBoxes = @()
foreach ($g in $Script:Groups.GetEnumerator()) {
    $cb = New-Object System.Windows.Controls.CheckBox
    $cb.Content   = $g.Key
    $cb.IsChecked = $true
    $cb.Tag       = $g.Value
    $cb.Foreground = 'White'
    if ($Script:GroupTips.ContainsKey($g.Key)) { $cb.ToolTip = $Script:GroupTips[$g.Key] }
    $Script:ctl.PnlCats.Children.Add($cb) | Out-Null
    $Script:CatBoxes += $cb
}

# Busy-state helper. The wait cursor is cosmetic only, so a failure here must
# never abort a query (PS2EXE-packaged scope can make this throw).
function Set-Busy {
    param([bool]$On)
    try {
        if ($Script:Win) {
            $Script:Win.Cursor = if ($On) { [System.Windows.Input.Cursors]::Wait } else { $null }
        }
    } catch {}
}

# Run a UI action so no exception can reach the PS2EXE fatal dialog; surface
# it in the status bar and a non-fatal message box, and clear busy state.
function Invoke-Safe {
    param([scriptblock]$Action, [string]$What = 'Operation')
    try { & $Action }
    catch {
        Set-Busy $false
        try { $Script:Sync.Running = $false } catch {}
        try { $Script:ctl.BtnQuery.IsEnabled = $true } catch {}
        $ln = try { $_.InvocationInfo.ScriptLineNumber } catch { '?' }
        $stk = ('' + $_.ScriptStackTrace) -replace "`r?`n",' <<< '
        Write-Log ("$What failed: $($_.Exception.GetType().Name): $($_.Exception.Message) [line $ln] stack: $stk") 'ERROR'
        $m = "{0} failed: {1}  [line {2}]  (log: {3})" -f $What, $_.Exception.Message, $ln, $Script:RunLog
        try { $Script:ctl.TxtStatus.Text = $m } catch {}
        try { [System.Windows.MessageBox]::Show($m,'WinLogonAuditor','OK','Warning') | Out-Null } catch {}
    }
}

# Tray notifier for Watch-mode toasts (no external deps; PS2EXE-safe)
$Script:Notify = $null
function Show-Toast {
    param([string]$Title='WinLogonAuditor', [string]$Message)
    try {
        if (-not $Script:Notify) {
            $Script:Notify = New-Object System.Windows.Forms.NotifyIcon
            try {
                $exe = (Get-Process -Id $PID).Path
                $Script:Notify.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($exe)
            } catch { $Script:Notify.Icon = [System.Drawing.SystemIcons]::Information }
            $Script:Notify.Visible = $true
        }
        $Script:Notify.BalloonTipTitle = $Title
        $Script:Notify.BalloonTipText  = $Message
        $Script:Notify.ShowBalloonTip(8000)
    } catch {}
}

# Load saved config and populate the target dropdown
$Script:Config = Get-AuditConfig

function Update-TargetList {
    param([string]$Select)
    $cur = if ($Select) { $Select } else { $Script:ctl.CmbTarget.Text }
    $list = New-Object System.Collections.Generic.List[string]
    $list.Add($env:COMPUTERNAME)
    if ($env:LOGONSERVER) { $list.Add(($env:LOGONSERVER -replace '^\\\\','')) }
    foreach ($s in @($Script:Config.Servers)) { if ($s -and -not $list.Contains($s)) { $list.Add($s) } }
    $Script:ctl.CmbTarget.ItemsSource = @($list | Select-Object -Unique)
    if ($cur) { $Script:ctl.CmbTarget.Text = $cur }
}

Update-TargetList
$initialTarget = if ($Script:Config.LastTarget) { $Script:Config.LastTarget }
                 elseif ($Target -and $Target -ne $env:COMPUTERNAME) { $Target }
                 elseif ($env:LOGONSERVER) { $env:LOGONSERVER -replace '^\\\\','' }
                 else { $env:COMPUTERNAME }
$Script:ctl.CmbTarget.Text  = $initialTarget
$Script:ctl.ChkAllDc.IsChecked = [bool]$Script:Config.QueryAllDcs
$Script:ctl.TxtMax.Text = "$([int]$Script:Config.MaxEventsPerCategory)"

# Shared state for the background runspace
$Script:Sync = [hashtable]::Synchronized(@{ Running=$false; Done=$false; Rows=$null; Views=$null; Status=''; Prog=0; Error=$null; Warn=$null; Capped=$false; Excluded=0 })
$Script:AllRows = @()
$Script:DnsCache = @{}

function Get-SelectedIds {
    $ids = @()
    foreach ($cb in $Script:CatBoxes) { if ($cb.IsChecked) { $ids += $cb.Tag } }
    return ($ids | Select-Object -Unique)
}

function Get-TimeWindow {
    $now = Get-Date
    switch ($Script:ctl.CmbRange.SelectedIndex) {
        0 { return @($now.AddHours(-1),  $now) }
        1 { return @($now.AddHours(-8),  $now) }
        2 { return @($now.AddHours(-24), $now) }
        3 { return @($now.AddDays(-3),   $now) }
        4 { return @($now.AddDays(-7),   $now) }
        5 {
            $f = if ($Script:ctl.DtFrom.SelectedDate) { $Script:ctl.DtFrom.SelectedDate } else { $now.AddDays(-1) }
            $t = if ($Script:ctl.DtTo.SelectedDate)   { ([datetime]$Script:ctl.DtTo.SelectedDate).AddDays(1).AddSeconds(-1) } else { $now }
            return @($f, $t)
        }
        default { return @($now.AddHours(-24), $now) }
    }
}

$Script:Cred = $null

function Start-Audit {
    if ($Script:Sync.Running) { return }
    $ids = Get-SelectedIds
    if (-not $ids) { $Script:ctl.TxtStatus.Text = 'Select at least one category.'; return }
    $win = Get-TimeWindow

    if ($Script:ctl.ChkCred.IsChecked -and -not $Script:Cred) {
        $Script:Cred = Get-Credential -Message "Domain credentials for querying / DC discovery"
    }
    if (-not $Script:ctl.ChkCred.IsChecked) { $Script:Cred = $null }

    $maxN = 100000; [int]::TryParse($Script:ctl.TxtMax.Text, [ref]$maxN) | Out-Null
    if ($maxN -le 0) { $maxN = 100000 }
    $toN  = 45;   [int]::TryParse($Script:ctl.TxtTimeout.Text, [ref]$toN) | Out-Null
    if ($toN -lt 5) { $toN = 5 }
    $Script:Config.MaxEventsPerCategory = $maxN

    $allDc = [bool]$Script:ctl.ChkAllDc.IsChecked
    $typed = $Script:ctl.CmbTarget.Text.Trim()
    if (-not $allDc -and -not $typed) {
        $Script:ctl.TxtStatus.Text = 'Enter or pick a target server.'; return
    }

    # Persist selection
    $Script:Config.LastTarget  = $typed
    $Script:Config.QueryAllDcs = $allDc
    Save-AuditConfig $Script:Config

    $qargs = @{
        AllDcs     = $allDc
        TypedTarget= $typed
        EventIds   = $ids
        Start      = $win[0]
        End        = $win[1]
        UserFilter = $Script:ctl.TxtUser.Text.Trim()
        MaxEvents  = $maxN
        TimeoutSec = $toN
        Credential = $Script:Cred
        Excludes   = $Script:Config.Excludes
        LogFile    = $Script:RunLog
    }

    Write-Log ("RunQuery: allDC={0} target='{1}' ids=[{2}] window={3:yyyy-MM-dd HH:mm}..{4:HH:mm} max={5} timeout={6}s exU={7} exS={8} exD={9}" -f `
        $allDc, $typed, ($ids -join ','), $win[0], $win[1], $maxN, $toN,
        @($Script:Config.Excludes.Users).Count, @($Script:Config.Excludes.Sources).Count, @($Script:Config.Excludes.DCs).Count)

    $Script:Sync.Running  = $true
    $Script:Sync.Done     = $false
    $Script:Sync.Error    = $null
    $Script:Sync.Warn     = $null
    $Script:Sync.Prog     = 0
    $Script:Sync.Status   = if ($allDc) { 'Discovering domain controllers...' } else { "Querying $typed ..." }
    $Script:ctl.TxtStatus.Text  = $Script:Sync.Status
    $Script:ctl.BtnQuery.IsEnabled = $false
    # Show the progress overlay so it's obvious work is happening
    $Script:ctl.TxtProgBig.Text = if ($allDc) { 'Sweeping all domain controllers' } else { "Querying $typed" }
    $Script:ctl.TxtProgSub.Text = 'Starting...'
    $Script:ctl.PrgOverlay.Value = 0
    $Script:ctl.PrgBar.Value = 0
    $Script:ctl.PrgBar.Visibility   = 'Visible'
    $Script:ctl.PnlProgress.Visibility = 'Visible'
    Set-Busy $true

    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'; $rs.ThreadOptions = 'ReuseThread'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('sync',    $Script:Sync)
    $rs.SessionStateProxy.SetVariable('qa',      $qargs)
    $rs.SessionStateProxy.SetVariable('funcDefs',
        "${function:ConvertTo-AuditRow}|||${function:Invoke-AuditQuery}|||" +
        "${function:Get-DecodedStatus}|||${function:Get-DecodedKerb}|||${function:Get-DecodedLogonType}|||" +
        "${function:Get-DomainControllerList}|||${function:Test-MatchAny}|||${function:Test-RowExcluded}")
    $rs.SessionStateProxy.SetVariable('maps', @{
        LogonTypeMap=$Script:LogonTypeMap; StatusMap=$Script:StatusMap; KerbMap=$Script:KerbMap
        CategoryMap=$Script:CategoryMap; SecurityIds=$Script:SecurityIds; SystemIds=$Script:SystemIds })

    $worker = {
        function wlog($m,$lvl='INFO'){ try { [System.IO.File]::AppendAllText($qa.LogFile, ("[{0}] [{1}] [worker] {2}`r`n" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'),$lvl,$m)) } catch {} }
        $phase = 'init'
        try {
            wlog 'worker started'
            $Script:LogonTypeMap = $maps.LogonTypeMap; $Script:StatusMap = $maps.StatusMap
            $Script:KerbMap = $maps.KerbMap; $Script:CategoryMap = $maps.CategoryMap
            $Script:SecurityIds = $maps.SecurityIds; $Script:SystemIds = $maps.SystemIds
            $parts = $funcDefs -split '\|\|\|'
            wlog "funcDefs parts=$($parts.Count)"
            Set-Item function:ConvertTo-AuditRow       ([scriptblock]::Create($parts[0]))
            Set-Item function:Invoke-AuditQuery        ([scriptblock]::Create($parts[1]))
            Set-Item function:Get-DecodedStatus        ([scriptblock]::Create($parts[2]))
            Set-Item function:Get-DecodedKerb          ([scriptblock]::Create($parts[3]))
            Set-Item function:Get-DecodedLogonType     ([scriptblock]::Create($parts[4]))
            Set-Item function:Get-DomainControllerList ([scriptblock]::Create($parts[5]))
            Set-Item function:Test-MatchAny            ([scriptblock]::Create($parts[6]))
            Set-Item function:Test-RowExcluded         ([scriptblock]::Create($parts[7]))

            # Resolve targets off the UI thread
            $phase = 'discovery'
            if ($qa.AllDcs) {
                $sync.Status = 'Discovering domain controllers...'
                $sync.Prog   = 3
                $dc = Get-DomainControllerList -Credential $qa.Credential
                if ($dc.Error -or -not $dc.DCs) {
                    wlog "discovery failed: $($dc.Error)" 'ERROR'
                    $sync.Error = "DC discovery failed: $($dc.Error)"; $sync.Done = $true; return
                }
                $targets = @($dc.DCs)
            } else {
                $targets = @($qa.TypedTarget)
            }
            wlog "targets: $($targets -join ', ')"

            $all  = New-Object System.Collections.Generic.List[object]
            $errs = @()
            $n = $targets.Count
            $toSec = [int]$qa.TimeoutSec; if ($toSec -lt 5) { $toSec = 45 }
            $maxConc = 8

            # Each DC is queried in its own runspace so one slow/hung DC
            # (e.g. a busy PDC emulator) can't block the others. Any DC
            # exceeding the per-DC timeout is stopped and skipped.
            $childScript = {
                param($maps,$funcDefs,$tgt,$qa,$slot)
                function clog($m,$lvl='INFO'){ try { [System.IO.File]::AppendAllText($qa.LogFile, ("[{0}] [{1}] [dc:$tgt] {2}`r`n" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'),$lvl,$m)) } catch {} }
                try {
                    clog 'child started'
                    $Script:LogonTypeMap=$maps.LogonTypeMap;$Script:StatusMap=$maps.StatusMap
                    $Script:KerbMap=$maps.KerbMap;$Script:CategoryMap=$maps.CategoryMap
                    $Script:SecurityIds=$maps.SecurityIds;$Script:SystemIds=$maps.SystemIds
                    $p=$funcDefs -split '\|\|\|'
                    Set-Item function:ConvertTo-AuditRow   ([scriptblock]::Create($p[0]))
                    Set-Item function:Invoke-AuditQuery    ([scriptblock]::Create($p[1]))
                    Set-Item function:Get-DecodedStatus    ([scriptblock]::Create($p[2]))
                    Set-Item function:Get-DecodedKerb      ([scriptblock]::Create($p[3]))
                    Set-Item function:Get-DecodedLogonType ([scriptblock]::Create($p[4]))
                    $r = Invoke-AuditQuery -ComputerName $tgt -EventIds $qa.EventIds `
                            -Start $qa.Start -End $qa.End -UserFilter $qa.UserFilter `
                            -MaxEvents $qa.MaxEvents -Credential $qa.Credential
                    $slot.Rows = @($r); $slot.Ok = $true
                    $slot.Capped = (@($r).Count -ge [int]$qa.MaxEvents)
                    clog "child OK rows=$(@($r).Count) capped=$($slot.Capped)"
                } catch {
                    $stk = ('' + $_.ScriptStackTrace) -replace "`r?`n",' <<< '
                    $slot.Err = "$($_.Exception.GetType().Name): $($_.Exception.Message)  @ line $($_.InvocationInfo.ScriptLineNumber)"
                    clog "child EXCEPTION: $($slot.Err) | $($_.InvocationInfo.Line.Trim()) | stack: $stk" 'ERROR'
                }
                finally { $slot.Done = $true }
            }

            $queue   = [System.Collections.Queue]::new(@($targets))
            $jobs    = New-Object System.Collections.Generic.List[object]
            $doneCnt = 0
            $anyCapped = $false
            $sync.Status = "Querying $n server(s) in parallel (timeout ${toSec}s each)..."
            $sync.Prog   = 6

            while ($doneCnt -lt $n) {
                # Launch up to $maxConc concurrent DC queries
                while ($queue.Count -gt 0 -and @($jobs | Where-Object { -not $_.Closed }).Count -lt $maxConc) {
                    $tgt  = $queue.Dequeue()
                    $slot = [hashtable]::Synchronized(@{ Done=$false; Ok=$false; Rows=@(); Err=$null; Capped=$false })
                    $crs  = [runspacefactory]::CreateRunspace(); $crs.ThreadOptions='ReuseThread'; $crs.Open()
                    $cps  = [powershell]::Create(); $cps.Runspace = $crs
                    $cps.AddScript($childScript).AddArgument($maps).AddArgument($funcDefs).
                         AddArgument($tgt).AddArgument($qa).AddArgument($slot) | Out-Null
                    $h = $cps.BeginInvoke()
                    $jobs.Add([pscustomobject]@{ Tgt=$tgt; PS=$cps; RS=$crs; H=$h; Slot=$slot;
                                                 Start=[datetime]::Now; Closed=$false })
                }
                foreach ($j in $jobs) {
                    if ($j.Closed) { continue }
                    $el = ([datetime]::Now - $j.Start).TotalSeconds
                    if ($j.Slot.Done) {
                        if ($j.Slot.Ok) {
                            foreach ($x in @($j.Slot.Rows)) { $all.Add($x) }
                            if ($j.Slot.Capped) { $anyCapped = $true }
                        }
                        else { $errs += "[$($j.Tgt)] $($j.Slot.Err)" }
                        try { $j.PS.EndInvoke($j.H) | Out-Null } catch {}
                        try { $j.PS.Dispose(); $j.RS.Close() } catch {}
                        $j.Closed = $true; $doneCnt++
                        if ($j.Slot.Ok) { wlog "$($j.Tgt) OK rows=$(@($j.Slot.Rows).Count) capped=$($j.Slot.Capped)" }
                        else { wlog "$($j.Tgt) ERROR: $($j.Slot.Err)" 'ERROR' }
                        $sync.Status = "$($j.Tgt) done  ($doneCnt/$n)  -  $($all.Count) events so far"
                        $sync.Prog   = [int](6 + ($doneCnt / [double]$n) * 88)
                    } elseif ($el -gt $toSec) {
                        try { $j.PS.Stop() } catch {}
                        try { $j.PS.Dispose(); $j.RS.Close() } catch {}
                        $errs += "[$($j.Tgt)] timed out after ${toSec}s - skipped"
                        $j.Closed = $true; $doneCnt++
                        wlog "$($j.Tgt) TIMEOUT after ${toSec}s - skipped" 'WARN'
                        $sync.Status = "$($j.Tgt) timed out, skipped  ($doneCnt/$n)"
                        $sync.Prog   = [int](6 + ($doneCnt / [double]$n) * 88)
                    }
                }
                if ($doneCnt -lt $n) { Start-Sleep -Milliseconds 300 }
            }
            $phase = 'sort'
            wlog "all DCs done. raw=$($all.Count) errs=$($errs.Count)"
            $sync.Status = "Sorting & summarising $($all.Count) events..."
            $sync.Prog   = 96
            $rawCount = $all.Count
            $rows = @($all.ToArray() | Sort-Object Time -Descending)

            # --- Apply exclude lists (Feature 2), post-retrieval ---
            $phase = 'excludes'
            $exU = @(); $exS = @(); $exD = @()
            if ($qa.Excludes) {
                if ($qa.Excludes.Users)   { $exU = @($qa.Excludes.Users) }
                if ($qa.Excludes.Sources) { $exS = @($qa.Excludes.Sources) }
                if ($qa.Excludes.DCs)     { $exD = @($qa.Excludes.DCs) }
            }
            if ($exU.Count -or $exS.Count -or $exD.Count) {
                $exObj = [pscustomobject]@{ Users=$exU; Sources=$exS; DCs=$exD }
                $kept = foreach ($x in $rows) { if (-not (Test-RowExcluded $x $exObj)) { $x } }
                $kept = @($kept)
                $sync.Excluded = $rawCount - $kept.Count
                $rows = $kept
            } else { $sync.Excluded = 0 }
            $sync.Capped = [bool]$anyCapped
            wlog "after excludes: rows=$($rows.Count) excluded=$($sync.Excluded) capped=$($sync.Capped)"

            # --- Correlate 4740 lockouts to what actually locked them ---
            # Windows often logs 4740 with no Caller Computer Name for
            # NTLM/network lockouts. The real source is the bad-password
            # 4625 / 4776 / 4771 for the same user moments earlier.
            $phase = 'correlate'
            $srcByUser = @{}
            foreach ($x in $rows) {
                if ($x.EventId -in 4625,4776,4771 -and $x.User) {
                    $k = $x.User.ToLower()
                    if (-not $srcByUser.ContainsKey($k)) { $srcByUser[$k] = New-Object System.Collections.Generic.List[object] }
                    $srcByUser[$k].Add($x)
                }
            }
            foreach ($x in $rows) {
                if ($x.EventId -ne 4740 -or -not $x.User) { continue }
                if ($x.CallerComp -and $x.CallerComp -ne '-') { continue }
                $cands = $srcByUser[$x.User.ToLower()]
                if (-not $cands) { continue }
                $best = $null; $bestDiff = [double]::MaxValue
                foreach ($c in $cands) {
                    $diff = [math]::Abs(($x.Time - $c.Time).TotalSeconds)
                    if ($diff -le 300 -and $diff -lt $bestDiff) { $best = $c; $bestDiff = $diff }
                }
                if ($best) {
                    if (-not $x.SourceIP)   { $x.SourceIP   = $best.SourceIP }
                    if (-not $x.SourceHost) { $x.SourceHost = $best.SourceHost }
                    $loc = @()
                    if ($best.SourceHost) { $loc += "host $($best.SourceHost)" }
                    if ($best.SourceIP)   { $loc += "IP $($best.SourceIP)" }
                    if ($best.LogonType)  { $loc += "Type $($best.LogonType)" }
                    if ($best.AuthPkg)    { $loc += $best.AuthPkg }
                    if ($best.Process -and $best.Process -ne '-') { $loc += "proc $($best.Process)" }
                    $secAgo = [int]$bestDiff
                    $x.Reason = "Locked via " + ($loc -join '  |  ') + "  (from event $($best.EventId), ${secAgo}s before)"
                }
            }

            # --- Best-effort reverse DNS for source IPs (cached) ---
            $phase = 'dns'
            $dnsCache = @{}
            foreach ($x in $rows) {
                $ip = "$($x.SourceIP)"
                if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$' -and -not $x.SourceHost) {
                    if (-not $dnsCache.ContainsKey($ip)) {
                        $h = $null
                        try { $h = [System.Net.Dns]::GetHostEntry($ip).HostName } catch {}
                        $dnsCache[$ip] = $h
                    }
                    if ($dnsCache[$ip]) { $x.SourceHost = $dnsCache[$ip] }
                }
            }

            $sync.Rows = $rows
            if ($errs) {
                if ($all.Count -eq 0) { $sync.Error = ($errs -join "`n") }
                else { $sync.Warn = "Incomplete: $($errs.Count) DC(s) failed/skipped - results may miss events from them: " + ($errs -join '  |  ') }
            }

            # Pre-compute every view here (off the UI thread) using single
            # passes / hashtables, so binding on the UI thread is instant.
            $phase = 'aggregate'
            $catC = @{}; $usrF = @{}; $srcF = @{}
            $rebootTotal = 0
            $perUser = @{}   # user -> aggregate hashtable
            foreach ($x in $rows) {
                $catC[$x.Category] = 1 + ([int]$catC[$x.Category])
                $isFail = ($x.Result -eq 'Failure' -or $x.Result -eq 'Lockout')
                if ($x.EventId -eq 1074 -or $x.EventId -eq 6008 -or $x.EventId -eq 41) { $rebootTotal++ }
                if ($isFail) {
                    if ($x.User) { $usrF[$x.User] = 1 + ([int]$usrF[$x.User]) }
                    $s = if ($x.SourceHost) { $x.SourceHost } elseif ($x.SourceIP) { $x.SourceIP } else { '(unknown)' }
                    $srcF[$s] = 1 + ([int]$srcF[$s])
                }
                if ($x.User) {
                    $u = $perUser[$x.User]
                    if (-not $u) { $u = @{ lo=0; rd=0; lk=0; out=0; last=$x.Time; lastStr=$x.TimeStr }; $perUser[$x.User] = $u }
                    switch ($x.EventId) {
                        4634 { $u.lo++ } 4647 { $u.lo++ }
                        4779 { $u.rd++ } 4800 { $u.lk++ } 4740 { $u.out++ }
                    }
                    if ($x.Time -gt $u.last) { $u.last = $x.Time; $u.lastStr = $x.TimeStr }
                }
            }
            $top = { param($h) @($h.GetEnumerator() | Sort-Object Value -Descending |
                     Select-Object -First 25 | ForEach-Object { [pscustomobject]@{ Name=$_.Key; Count=$_.Value } }) }
            $byUser = foreach ($kv in $perUser.GetEnumerator()) {
                $u = $kv.Value; $likely = @()
                if ($u.out -gt 0)                    { $likely += "Account LOCKOUT ($($u.out)) - bad cached creds/old session somewhere" }
                if ($rebootTotal -gt 0 -and $u.lo -gt 0) { $likely += "Machine reboot/shutdown in window ($rebootTotal) - users dropped" }
                if ($u.rd -gt 2)                     { $likely += "Repeated RDP disconnects ($($u.rd)) - idle/session-limit GPO or network" }
                if ($u.lk -gt 5)                     { $likely += "Frequent workstation locks ($($u.lk)) - screensaver/lock GPO" }
                if (-not $likely)                    { $likely += "Normal sign-out activity" }
                [pscustomobject]@{
                    User=$kv.Key; Logoffs=$u.lo; RdpDisc=$u.rd; Locks=$u.lk; Lockouts=$u.out
                    Last=$u.last; LastStr=$u.lastStr; Likely=($likely -join '  |  ')
                }
            }
            $phase = 'views'
            $sync.Views = @{
                Cat    = @($catC.GetEnumerator() | Sort-Object Value -Descending |
                          ForEach-Object { [pscustomobject]@{ Name=$_.Key; Count=$_.Value } })
                User   = & $top $usrF
                Src    = & $top $srcF
                ByUser = @($byUser | Sort-Object Last -Descending)
            }
            wlog "worker complete: rows=$($rows.Count) views built"
        } catch {
            $eln = $_.InvocationInfo.ScriptLineNumber
            $esrc = ('' + $_.InvocationInfo.Line).Trim()
            $stk = ('' + $_.ScriptStackTrace) -replace "`r?`n",' <<< '
            $etype = $_.Exception.GetType().FullName
            wlog "EXCEPTION in phase '$phase': $etype : $($_.Exception.Message) | line $eln : $esrc | stack: $stk" 'ERROR'
            $sync.Error = "$($_.Exception.Message)  [phase=$phase line $eln : $esrc]"
        } finally {
            $sync.Done = $true
            wlog "worker finished (phase=$phase)"
        }
    }
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    $ps.AddScript($worker) | Out-Null
    $Script:Sync.PS     = $ps
    $Script:Sync.RS     = $rs
    $Script:Sync.Handle = $ps.BeginInvoke()
}

function Update-Views {
    param($rows)
    $Script:AllRows = @($rows)
    Apply-Filter
    $v = $Script:Sync.Views
    if ($v) {
        $Script:ctl.GridSumCat.ItemsSource  = $v.Cat
        $Script:ctl.GridSumUser.ItemsSource = $v.User
        $Script:ctl.GridSumSrc.ItemsSource  = $v.Src
        $Script:ctl.GridOut.ItemsSource     = $v.ByUser
    }
    # Warning banner: cap reached and/or excludes active
    $w = @()
    if ($Script:Sync.Capped) {
        $w += "Reached the per-DC cap of $($Script:Config.MaxEventsPerCategory) events - increase 'Max events/DC' or narrow the time range; results are the most recent within the window."
    }
    if ([int]$Script:Sync.Excluded -gt 0) {
        $w += "$($Script:Sync.Excluded) event(s) hidden by exclude lists."
    }
    if ($Script:Sync.Warn) {
        $w += [string]$Script:Sync.Warn
    }
    if ($w) {
        $Script:ctl.TxtWarn.Text = ($w -join '  ')
        $Script:ctl.WarnBanner.Visibility = 'Visible'
    } else {
        $Script:ctl.WarnBanner.Visibility = 'Collapsed'
    }
}

function Apply-Filter {
    $f = $Script:ctl.TxtFilter.Text
    $view = $Script:AllRows
    if ($f) {
        $view = $view | Where-Object {
            "$($_.User) $($_.SourceHost) $($_.SourceIP) $($_.Category) $($_.Reason) $($_.EventId) $($_.LoggedOn)" -like "*$f*"
        }
    }
    $Script:ctl.Grid.ItemsSource = @($view)
    $tgtLbl = if ($Script:ctl.ChkAllDc.IsChecked) { 'all DCs' } else { $Script:ctl.CmbTarget.Text }
    $exTxt  = if ([int]$Script:Sync.Excluded -gt 0) { "  |  $($Script:Sync.Excluded) excluded" } else { '' }
    $capTxt = if ($Script:Sync.Capped) { '  |  CAP HIT' } else { '' }
    $Script:ctl.TxtStatus.Text = "{0} events  |  target {1}{2}{3}  |  {4}" -f @($view).Count, $tgtLbl, $exTxt, $capTxt, (Get-Date -Format 'HH:mm:ss')
}

# --- Events / wiring ---
$Script:ctl.CmbRange.Add_SelectionChanged({
    $custom = ($Script:ctl.CmbRange.SelectedIndex -eq 5)
    $Script:ctl.DtFrom.IsEnabled = $custom; $Script:ctl.DtTo.IsEnabled = $custom
})
$Script:ctl.BtnQuery.Add_Click({ Invoke-Safe { Start-Audit } 'Query' })

$Script:ctl.BtnCancel.Add_Click({
    Invoke-Safe {
        if ($Script:Sync.PS) { try { $Script:Sync.PS.Stop() } catch {} }
        if ($Script:Sync.RS) { try { $Script:Sync.RS.Close() } catch {} }
        $Script:Sync.Running = $false
        $Script:Sync.Done    = $false
        $Script:ctl.BtnQuery.IsEnabled = $true
        $Script:ctl.PnlProgress.Visibility = 'Collapsed'
        $Script:ctl.PrgBar.Visibility = 'Collapsed'
        Set-Busy $false
        $Script:ctl.TxtStatus.Text = 'Cancelled.'
    } 'Cancel'
})

$Script:ctl.BtnDiscover.Add_Click({
    if ($Script:ctl.ChkCred.IsChecked -and -not $Script:Cred) {
        $Script:Cred = Get-Credential -Message "Domain credentials for DC discovery"
    }
    $Script:ctl.TxtStatus.Text = 'Discovering domain controllers...'
    Set-Busy $true
    $dc = Get-DomainControllerList -Credential $Script:Cred
    Set-Busy $false
    if ($dc.Error -or -not $dc.DCs) {
        $Script:ctl.TxtStatus.Text = "DC discovery failed: $($dc.Error)"
        [System.Windows.MessageBox]::Show("Could not enumerate domain controllers.`n`n$($dc.Error)`n`nTip: tick 'Alt credentials' and use a domain account, or run on a domain-joined machine.",'DC discovery','OK','Warning') | Out-Null
        return
    }
    $merged = @(@($Script:Config.Servers) + $dc.DCs | Where-Object { $_ } | Select-Object -Unique)
    $Script:Config.Servers = $merged
    Save-AuditConfig $Script:Config
    Update-TargetList
    if ($dc.Pdc) { $Script:ctl.CmbTarget.Text = $dc.Pdc }
    $pdcNote = if ($dc.Pdc) { "  PDC emulator: $($dc.Pdc) (best single target for lockouts)" } else { '' }
    $Script:ctl.TxtStatus.Text = "Found $($dc.DCs.Count) DC(s) in $($dc.Domain).$pdcNote"
})

$Script:ctl.BtnManage.Add_Click({
    [xml]$mx = @"
<Window xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'
        xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml'
        Title='Manage servers' Height='360' Width='420' WindowStartupLocation='CenterOwner'
        Background='#FF1E1E2E'>
  <Grid Margin='12'>
    <Grid.RowDefinitions><RowDefinition Height='*'/><RowDefinition Height='Auto'/><RowDefinition Height='Auto'/></Grid.RowDefinitions>
    <ListBox x:Name='Lst' Grid.Row='0' Background='#FF252536' Foreground='#FFE6E6E6'/>
    <DockPanel Grid.Row='1' Margin='0,8'>
      <Button x:Name='Rem' Content='Remove selected' DockPanel.Dock='Right' Background='#FF6B7280' Foreground='White' Padding='10,5'/>
      <TextBox x:Name='New' />
      <Button x:Name='Add' Content='Add' DockPanel.Dock='Right' Background='#FF3B82F6' Foreground='White' Padding='10,5' Margin='6,0'/>
    </DockPanel>
    <Button x:Name='Ok' Grid.Row='2' Content='Save &amp; close' Background='#FF3B82F6' Foreground='White' Padding='10,6' HorizontalAlignment='Right'/>
  </Grid>
</Window>
"@
    $mw = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $mx))
    $mw.Owner = $Script:Win
    $lst = $mw.FindName('Lst'); $new = $mw.FindName('New')
    $servers = New-Object System.Collections.ObjectModel.ObservableCollection[string]
    foreach ($s in @($Script:Config.Servers)) { if ($s) { $servers.Add($s) } }
    $lst.ItemsSource = $servers
    $mw.FindName('Add').Add_Click({ $v=$new.Text.Trim(); if ($v -and -not $servers.Contains($v)) { $servers.Add($v); $new.Clear() } })
    $mw.FindName('Rem').Add_Click({ if ($lst.SelectedItem) { $servers.Remove($lst.SelectedItem) } })
    $mw.FindName('Ok').Add_Click({
        $Script:Config.Servers = @($servers)
        Save-AuditConfig $Script:Config
        Update-TargetList
        $mw.Close()
    })
    $mw.ShowDialog() | Out-Null
})

$Script:ctl.BtnExcludes.Add_Click({ Invoke-Safe {
    [xml]$ex = @"
<Window xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'
        xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml'
        Title='Exclude lists (wildcards: svc-*  192.168.108.*  *$)' Height='460' Width='640'
        WindowStartupLocation='CenterOwner' Background='#FF1E1E2E'>
  <Grid Margin='12'>
    <Grid.RowDefinitions><RowDefinition Height='Auto'/><RowDefinition Height='*'/><RowDefinition Height='Auto'/></Grid.RowDefinitions>
    <TextBlock Grid.Row='0' Foreground='#FFB8C0FF' TextWrapping='Wrap' Margin='0,0,0,8'
      Text='One pattern per line. Users match the account; Sources match source host OR IP; DCs match the logging DC. Applies on the next Run Query / Watch poll.'/>
    <Grid Grid.Row='1'>
      <Grid.ColumnDefinitions><ColumnDefinition Width='*'/><ColumnDefinition Width='*'/><ColumnDefinition Width='*'/></Grid.ColumnDefinitions>
      <DockPanel Grid.Column='0' Margin='0,0,6,0'><TextBlock DockPanel.Dock='Top' Text='Users' Foreground='#FFE6E6E6'/><TextBox x:Name='ExU' AcceptsReturn='True' VerticalScrollBarVisibility='Auto' Background='#FF252536' Foreground='#FFE6E6E6'/></DockPanel>
      <DockPanel Grid.Column='1' Margin='3,0'><TextBlock DockPanel.Dock='Top' Text='Sources (host/IP)' Foreground='#FFE6E6E6'/><TextBox x:Name='ExS' AcceptsReturn='True' VerticalScrollBarVisibility='Auto' Background='#FF252536' Foreground='#FFE6E6E6'/></DockPanel>
      <DockPanel Grid.Column='2' Margin='6,0,0,0'><TextBlock DockPanel.Dock='Top' Text='DCs' Foreground='#FFE6E6E6'/><TextBox x:Name='ExD' AcceptsReturn='True' VerticalScrollBarVisibility='Auto' Background='#FF252536' Foreground='#FFE6E6E6'/></DockPanel>
    </Grid>
    <Button x:Name='ExOk' Grid.Row='2' Content='Save' Background='#FF3B82F6' Foreground='White' Padding='12,6' HorizontalAlignment='Right' Margin='0,10,0,0'/>
  </Grid>
</Window>
"@
    $ew = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $ex))
    $ew.Owner = $Script:Win
    $ew.FindName('ExU').Text = (@($Script:Config.Excludes.Users)   -join "`r`n")
    $ew.FindName('ExS').Text = (@($Script:Config.Excludes.Sources) -join "`r`n")
    $ew.FindName('ExD').Text = (@($Script:Config.Excludes.DCs)     -join "`r`n")
    $ew.FindName('ExOk').Add_Click({
        $split = { param($t) @($t -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
        $Script:Config.Excludes = New-ExcludesObject ([pscustomobject]@{
            Users   = (& $split $ew.FindName('ExU').Text)
            Sources = (& $split $ew.FindName('ExS').Text)
            DCs     = (& $split $ew.FindName('ExD').Text)
        })
        Save-AuditConfig $Script:Config
        $Script:ctl.TxtStatus.Text = 'Exclude lists saved - applied on next Run Query.'
        $ew.Close()
    })
    $ew.ShowDialog() | Out-Null
} 'Excludes' })

# Right-click any grid row to quick-mute its user / source
function Add-Exclude {
    param([ValidateSet('Users','Sources','DCs')]$List, [string]$Value)
    if (-not $Value) { return }
    $cur = @($Script:Config.Excludes.$List)
    if ($cur -notcontains $Value) {
        $obj = @{ Users=@($Script:Config.Excludes.Users); Sources=@($Script:Config.Excludes.Sources); DCs=@($Script:Config.Excludes.DCs) }
        $obj.$List = @($cur + $Value)
        $Script:Config.Excludes = New-ExcludesObject ([pscustomobject]$obj)
        Save-AuditConfig $Script:Config
    }
    # Drop matching rows from the current view immediately
    $Script:AllRows = @($Script:AllRows | Where-Object { -not (Test-RowExcluded $_ $Script:Config.Excludes) })
    $Script:Sync.Excluded = [int]$Script:Sync.Excluded + 1
    Apply-Filter
    $Script:ctl.TxtStatus.Text = "Muted $List = '$Value' (saved). Re-run query for full effect."
}
$Script:GridMenu = New-Object System.Windows.Controls.ContextMenu
$miU = New-Object System.Windows.Controls.MenuItem; $miU.Header = 'Mute this user'
$miH = New-Object System.Windows.Controls.MenuItem; $miH.Header = 'Mute this source host'
$miI = New-Object System.Windows.Controls.MenuItem; $miI.Header = 'Mute this source IP'
$miU.Add_Click({ $r=$Script:ctl.Grid.SelectedItem; if ($r -and $r.User)       { Add-Exclude Users   $r.User } })
$miH.Add_Click({ $r=$Script:ctl.Grid.SelectedItem; if ($r -and $r.SourceHost) { Add-Exclude Sources $r.SourceHost } })
$miI.Add_Click({ $r=$Script:ctl.Grid.SelectedItem; if ($r -and $r.SourceIP)   { Add-Exclude Sources ($r.SourceIP -replace ' \(local\)$','') } })
$Script:GridMenu.Items.Add($miU) | Out-Null
$Script:GridMenu.Items.Add($miH) | Out-Null
$Script:GridMenu.Items.Add($miI) | Out-Null
$Script:ctl.Grid.ContextMenu = $Script:GridMenu

$Script:ctl.TxtFilter.Add_TextChanged({ Apply-Filter })
$Script:ctl.Grid.Add_SelectionChanged({
    $sel = $Script:ctl.Grid.SelectedItem
    if ($sel) { $Script:ctl.TxtDetail.Text = $sel.Message }
})
$Script:ctl.BtnExport.Add_Click({ Invoke-Safe {
    if (-not $Script:AllRows) { $Script:ctl.TxtStatus.Text='Nothing to export - run a query first.'; return }
    $filtered = [int]$Script:Sync.Excluded -gt 0
    $base = "WinLogonAuditor_$(Get-Date -Format yyyyMMdd_HHmmss)"
    if ($filtered) { $base += '_filtered' }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter='CSV (*.csv)|*.csv'; $dlg.FileName="$base.csv"
    if ($dlg.ShowDialog() -eq 'OK') {
        Export-AuditCsv -Rows $Script:AllRows -Path $dlg.FileName
        $Script:ctl.TxtStatus.Text = "Exported $(@($Script:AllRows).Count) rows to $($dlg.FileName)"
    }
} 'Export' })
function Resolve-TraceTargets {
    if ($Script:ctl.ChkAllDc.IsChecked) {
        $dc = Get-DomainControllerList -Credential $Script:Cred
        if ($dc.DCs) { return @($dc.DCs) }
    }
    $t = $Script:ctl.CmbTarget.Text.Trim()
    if ($t) { return @($t) } else { return @($env:COMPUTERNAME) }
}

# Render the trace result (shared by manual Trace and Watch mode)
function Show-LockTrace {
    param([string]$User, $Trail)
    $Script:ctl.GridLock.ItemsSource = @($Trail)
    $locks = @($Trail | Where-Object { $_.EventId -eq 4740 })
    $fails = @($Trail | Where-Object { $_.EventId -in 4625,4771,4776 })
    $bySrc = $fails | Group-Object { if ($_.ClientHost) { $_.ClientHost } elseif ($_.ClientIP) { $_.ClientIP } else { '(unknown)' } } |
        ForEach-Object {
            $g = $_.Group
            [pscustomobject]@{
                Src     = $_.Name
                Count   = $_.Count
                Locks   = @($locks | Where-Object { ($_.ClientHost -eq $g[0].ClientHost) -or ($_.ClientIP -eq $g[0].ClientIP) }).Count
                Why     = ($g | Group-Object FailureReason | Sort-Object Count -Descending | Select-Object -First 1).Name
                Last    = ($g | Sort-Object Time -Descending | Select-Object -First 1).Time
                LastStr = ($g | Sort-Object Time -Descending | Select-Object -First 1).FailureTime
            }
        } | Sort-Object Count -Descending
    $Script:ctl.GridLockSrc.ItemsSource = @($bySrc)
    $top = $bySrc | Select-Object -First 1
    if (-not $locks -and -not $fails) {
        $Script:ctl.TxtLockInfo.Text = "No 4740/4771/4625/4776 for '*$User*' in the last $($Script:ctl.TxtLookback.Text) min on the selected target(s). Widen Lookback or check the target."
        return
    }
    $v = "VERDICT: '$User' - $($locks.Count) lockout(s), $($fails.Count) bad attempt(s) in last $($Script:ctl.TxtLookback.Text) min. "
    if ($top) {
        $v += "Top source: $($top.Src) ($($top.Count) hits; $($top.Why)). Investigate that device/service - stale creds in a mapped drive, Windows service, scheduled task, RDP session or cached password."
    } else {
        $v += "Lockouts present but no preceding failures captured - tick NTLM validation (4776) categories or widen Lookback."
    }
    $Script:ctl.TxtLockInfo.Text = $v
}

$Script:LockSync = [hashtable]::Synchronized(@{ Running=$false; Done=$false; Trail=$null; Err=$null; User='' })

$Script:ctl.BtnLockGo.Add_Click({ Invoke-Safe {
    $u = $Script:ctl.TxtLockUser.Text.Trim()
    if (-not $u) { $Script:ctl.TxtLockInfo.Text='Enter a username.'; return }
    if ($Script:LockSync.Running) { return }
    $lb = 60; [int]::TryParse($Script:ctl.TxtLookback.Text, [ref]$lb) | Out-Null; if ($lb -lt 1) { $lb = 60 }
    if ($Script:ctl.ChkCred.IsChecked -and -not $Script:Cred) {
        $Script:Cred = Get-Credential -Message "Domain credentials for lockout trace"
    }
    $targets = Resolve-TraceTargets
    $Script:ctl.TxtLockInfo.Text = "Tracing '$u' across $($targets -join ', ') (last $lb min)..."
    $Script:LockSync.Running = $true; $Script:LockSync.Done = $false
    $Script:LockSync.Err = $null; $Script:LockSync.User = $u
    Set-Busy $true

    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.ThreadOptions='ReuseThread'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('lsync', $Script:LockSync)
    Write-Log ("LockoutTrace: user='$u' lookback=${lb}min targets=$($targets -join ',')")
    $rs.SessionStateProxy.SetVariable('lt', @{ Targets=$targets; User=$u; Lb=$lb; Cred=$Script:Cred; LogFile=$Script:RunLog })
    $rs.SessionStateProxy.SetVariable('fd',
        "${function:ConvertTo-AuditRow}|||${function:Invoke-AuditQuery}|||${function:Get-DecodedStatus}|||" +
        "${function:Get-DecodedKerb}|||${function:Get-DecodedLogonType}|||${function:Invoke-LockoutTrace}")
    $rs.SessionStateProxy.SetVariable('maps', @{
        LogonTypeMap=$Script:LogonTypeMap; StatusMap=$Script:StatusMap; KerbMap=$Script:KerbMap
        CategoryMap=$Script:CategoryMap; SecurityIds=$Script:SecurityIds; SystemIds=$Script:SystemIds })
    $w = {
        try {
            $Script:LogonTypeMap=$maps.LogonTypeMap;$Script:StatusMap=$maps.StatusMap
            $Script:KerbMap=$maps.KerbMap;$Script:CategoryMap=$maps.CategoryMap
            $Script:SecurityIds=$maps.SecurityIds;$Script:SystemIds=$maps.SystemIds
            $p=$fd -split '\|\|\|'
            Set-Item function:ConvertTo-AuditRow   ([scriptblock]::Create($p[0]))
            Set-Item function:Invoke-AuditQuery    ([scriptblock]::Create($p[1]))
            Set-Item function:Get-DecodedStatus    ([scriptblock]::Create($p[2]))
            Set-Item function:Get-DecodedKerb      ([scriptblock]::Create($p[3]))
            Set-Item function:Get-DecodedLogonType ([scriptblock]::Create($p[4]))
            Set-Item function:Invoke-LockoutTrace  ([scriptblock]::Create($p[5]))
            $lsync.Trail = @(Invoke-LockoutTrace -Targets $lt.Targets -User $lt.User -LookbackMinutes $lt.Lb -Credential $lt.Cred -DnsCache @{})
            try { [System.IO.File]::AppendAllText($lt.LogFile, ("[{0}] [INFO] [locktrace] rows=$(@($lsync.Trail).Count)`r`n" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'))) } catch {}
        } catch {
            $lsync.Err = $_.Exception.Message
            try { [System.IO.File]::AppendAllText($lt.LogFile, ("[{0}] [ERROR] [locktrace] $($_.Exception.Message) | stack: $(('' + $_.ScriptStackTrace) -replace "`r?`n",' <<< ')`r`n" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'))) } catch {}
        }
        finally { $lsync.Done = $true }
    }
    $ps=[powershell]::Create(); $ps.Runspace=$rs
    $ps.AddScript($w) | Out-Null
    $Script:LockSync.PS=$ps; $Script:LockSync.RS=$rs; $Script:LockSync.Handle=$ps.BeginInvoke()
} 'Lockout trace' })

# Poll the runspace
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromMilliseconds(400)
$timer.Add_Tick({
    if ($Script:Sync.Running -and -not $Script:Sync.Done) {
        $s = "$($Script:Sync.Status)"
        if ($s -and $Script:ctl.TxtStatus.Text -ne $s) { $Script:ctl.TxtStatus.Text = $s }
        if ($s) { $Script:ctl.TxtProgSub.Text = $s }
        $p = [int]$Script:Sync.Prog
        $Script:ctl.PrgOverlay.Value = $p
        $Script:ctl.PrgBar.Value = $p
    }
    if ($Script:Sync.Running -and $Script:Sync.Done) {
        Invoke-Safe {
            try {
                if ($Script:Sync.PS) { $Script:Sync.PS.EndInvoke($Script:Sync.Handle) | Out-Null }
            } catch {}
            if ($Script:Sync.Error) {
                Write-Log "Query error surfaced: $($Script:Sync.Error)" 'ERROR'
                $Script:ctl.TxtStatus.Text = "ERROR: $($Script:Sync.Error)  (log: $($Script:RunLog))"
                [System.Windows.MessageBox]::Show("$($Script:Sync.Error)`n`nFull log:`n$($Script:RunLog)",'Query failed','OK','Error') | Out-Null
            } else {
                Update-Views $Script:Sync.Rows
                Write-Log "Query OK: rows=$(@($Script:AllRows).Count) excluded=$($Script:Sync.Excluded) capped=$($Script:Sync.Capped)"
                $Script:ctl.TxtStatus.Text = "{0} events  |  {1}  |  done {2}" -f `
                    @($Script:AllRows).Count, $(if($Script:ctl.ChkAllDc.IsChecked){'all DCs'}else{$Script:ctl.CmbTarget.Text}), (Get-Date -Format 'HH:mm:ss')
            }
            if ($Script:Sync.RS) { $Script:Sync.PS.Dispose(); $Script:Sync.RS.Close() }
        } 'Results'
        $Script:Sync.Running = $false
        $Script:ctl.BtnQuery.IsEnabled = $true
        $Script:ctl.PnlProgress.Visibility = 'Collapsed'
        $Script:ctl.PrgBar.Visibility = 'Collapsed'
        Set-Busy $false
    }
})
$timer.Start()

# Auto refresh
$autoTimer = New-Object System.Windows.Threading.DispatcherTimer
$autoTimer.Interval = [TimeSpan]::FromSeconds(60)
$autoTimer.Add_Tick({ if ($Script:ctl.ChkAuto.IsChecked -and -not $Script:Sync.Running) { Invoke-Safe { Start-Audit } 'Auto-refresh' } })
$autoTimer.Start()

# Poll the lockout-trace runspace
$lockTimer = New-Object System.Windows.Threading.DispatcherTimer
$lockTimer.Interval = [TimeSpan]::FromMilliseconds(400)
$lockTimer.Add_Tick({
    if ($Script:LockSync.Running -and $Script:LockSync.Done) {
        Invoke-Safe {
            try { if ($Script:LockSync.PS) { $Script:LockSync.PS.EndInvoke($Script:LockSync.Handle) | Out-Null } } catch {}
            if ($Script:LockSync.Err) {
                $Script:ctl.TxtLockInfo.Text = "Trace failed: $($Script:LockSync.Err)"
            } else {
                Show-LockTrace -User $Script:LockSync.User -Trail $Script:LockSync.Trail
            }
            if ($Script:LockSync.RS) { $Script:LockSync.PS.Dispose(); $Script:LockSync.RS.Close() }
        } 'Trace result'
        $Script:LockSync.Running = $false
        Set-Busy $false
    }
})
$lockTimer.Start()

# Watch mode: poll for new lockouts of watched users and toast + log them
$Script:WatchSeen = @{}
$watchTimer = New-Object System.Windows.Threading.DispatcherTimer
$watchTimer.Interval = [TimeSpan]::FromSeconds([math]::Max(5,[int]$Script:Config.WatchInterval))
$watchTimer.Add_Tick({ Invoke-Safe {
    if (-not $Script:ctl.ChkWatch.IsChecked) { return }
    if ($Script:LockSync.Running -or $Script:Sync.Running) { return }
    $wu = @($Script:Config.WatchUsers)
    if (-not $wu) { $wu = @($Script:ctl.TxtLockUser.Text.Trim()) }
    $wu = @($wu | Where-Object { $_ })
    if (-not $wu) { return }
    $targets = Resolve-TraceTargets
    $hist = Join-Path $Script:ConfigDir ("LockoutHunt_{0}.csv" -f (Get-Date -Format yyyyMMdd))
    foreach ($u in $wu) {
        $tr = Invoke-LockoutTrace -Targets $targets -User $u -LookbackMinutes $Script:Config.LookbackMinutes -Credential $Script:Cred -DnsCache $Script:DnsCache
        $newLocks = @($tr | Where-Object { $_.EventId -eq 4740 -and -not $Script:WatchSeen.ContainsKey("$($_.FailureTime)|$($_.User)") })
        foreach ($lk in $newLocks) {
            $Script:WatchSeen["$($lk.FailureTime)|$($lk.User)"] = $true
            try { $tr | ForEach-Object { ConvertTo-ExportRow $_ } | Export-Csv -Path $hist -NoTypeInformation -Encoding UTF8 -Append } catch {}
            $src = ($tr | Where-Object { $_.EventId -in 4625,4771,4776 } |
                    Group-Object { if ($_.ClientHost) { $_.ClientHost } elseif ($_.ClientIP) { $_.ClientIP } else { '?' } } |
                    Sort-Object Count -Descending | Select-Object -First 1)
            $msg = "Lockout: $($lk.User)"
            if ($src) { $msg += " - likely source: $($src.Name) ($($src.Count) bad attempts)" }
            Show-Toast -Title 'WinLogonAuditor' -Message $msg
            $Script:ctl.TxtStatus.Text = $msg
        }
    }
} 'Watch' })
$watchTimer.Start()

$Script:Win.Add_Closed({
    $timer.Stop(); $autoTimer.Stop(); $lockTimer.Stop(); $watchTimer.Stop()
    try {
        $Script:Config.LastTarget  = $Script:ctl.CmbTarget.Text.Trim()
        $Script:Config.QueryAllDcs = [bool]$Script:ctl.ChkAllDc.IsChecked
        Save-AuditConfig $Script:Config
    } catch {}
})

# No auto-query on open: the user sets filters first, then clicks Run Query.
$Script:ctl.TxtStatus.Text = 'Ready - set your filters (time range, user, categories) and click Run Query.'

if ($NoShow) {
    Write-Host "SELFTEST OK: window built, $($Script:ctl.Count) named controls resolved, $($Script:CatBoxes.Count) category filters." -ForegroundColor Green
    return
}
$Script:Win.ShowDialog() | Out-Null

#endregion
