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
    $srcIp = $data['IpAddress']
    if ($srcIp -in @('-','::1','127.0.0.1')) { $srcIp = "$srcIp (local)" }

    # Reason / decoded detail
    $reason = ''
    switch ($id) {
        4625 {
            $st  = Get-DecodedStatus $data['Status']
            $sub = Get-DecodedStatus $data['SubStatus']
            $reason = if ($sub -and $sub -ne '0x0') { $sub } else { $st }
        }
        4771 { $reason = Get-DecodedKerb $data['Failure'] ; if (-not $reason) { $reason = Get-DecodedKerb $data['FailureCode'] } }
        4768 { if ($data['Status'] -and $data['Status'] -ne '0x0') { $reason = Get-DecodedKerb $data['Status'] } }
        4776 { if ($data['Status'] -and $data['Status'] -ne '0x0') { $reason = Get-DecodedStatus $data['Status'] } }
        4740 { $reason = "Locked by: $($data['CallerComputerName'])" }
        4634 { $reason = Get-DecodedLogonType $data['LogonType'] }
        4647 { $reason = 'User initiated sign-out' }
    }

    $logonType = Get-DecodedLogonType $data['LogonType']

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
        LoggedOn    = $Evt.MachineName
        Process     = $data['ProcessName']
        CallerComp  = $data['CallerComputerName']
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
        [int]$MaxEvents = 5000,
        [pscredential]$Credential
    )

    $secIds = @($EventIds | Where-Object { $_ -in $Script:SecurityIds })
    $sysIds = @($EventIds | Where-Object { $_ -in $Script:SystemIds  })
    $rows   = New-Object System.Collections.Generic.List[object]
    $isLocal = $ComputerName -in @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')

    $queries = @()
    if ($secIds.Count) { $queries += ,@{ LogName='Security'; Id=$secIds; StartTime=$Start; EndTime=$End } }
    if ($sysIds.Count) { $queries += ,@{ LogName='System';   Id=$sysIds; StartTime=$Start; EndTime=$End } }

    foreach ($filter in $queries) {
        $params = @{ FilterHashtable = $filter; MaxEvents = $MaxEvents; ErrorAction = 'Stop' }
        if (-not $isLocal)   { $params['ComputerName'] = $ComputerName }
        if ($Credential -and -not $isLocal) { $params['Credential'] = $Credential }
        try {
            $raw = Get-WinEvent @params
        } catch [System.Diagnostics.Eventing.Reader.EventLogException] {
            throw "Cannot read '$($filter.LogName)' on '$ComputerName': $($_.Exception.Message). " +
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

function Get-AuditConfig {
    $def = [pscustomobject]@{ Servers = @(); LastTarget = ''; QueryAllDcs = $true }
    try {
        if (Test-Path $Script:ConfigPath) {
            $c = Get-Content $Script:ConfigPath -Raw | ConvertFrom-Json
            if (-not $c.Servers)    { $c | Add-Member Servers @() -Force }
            if ($null -eq $c.LastTarget)  { $c | Add-Member LastTarget '' -Force }
            if ($null -eq $c.QueryAllDcs) { $c | Add-Member QueryAllDcs $false -Force }
            return $c
        }
    } catch {}
    return $def
}

function Save-AuditConfig {
    param($Config)
    try {
        if (-not (Test-Path $Script:ConfigDir)) { New-Item -ItemType Directory -Path $Script:ConfigDir -Force | Out-Null }
        $Config | ConvertTo-Json -Depth 4 | Set-Content -Path $Script:ConfigPath -Encoding UTF8
    } catch {}
}

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

#region --------------------------------------------------------------- CLI mode

if ($Cli) {
    Write-Host "WinLogonAuditor (CLI) - target: $Target  user: $User  window: ${Hours}h" -ForegroundColor Cyan
    $allIds = $Script:SecurityIds + $Script:SystemIds
    $res = Invoke-AuditQuery -ComputerName $Target -EventIds $allIds `
              -Start (Get-Date).AddHours(-$Hours) -End (Get-Date) -UserFilter $User -MaxEvents 20000
    $res | Select-Object TimeStr,EventId,Result,Category,User,Domain,SourceHost,SourceIP,LogonType,Reason,LoggedOn |
        Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    Write-Host ("{0} events written to {1}" -f $res.Count, $OutFile) -ForegroundColor Green
    $res | Group-Object Category | Sort-Object Count -Descending |
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

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

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
        <ComboBox x:Name="CmbTarget" Width="190" IsEditable="True" Margin="0,0,4,0"/>
        <Button x:Name="BtnDiscover" Content="Discover DCs" Background="#FF6B7280"/>
        <Button x:Name="BtnManage" Content="Servers..." Background="#FF6B7280" Margin="0,0,12,0"/>
        <CheckBox x:Name="ChkAllDc" Content="Query all DCs"/>
        <TextBlock Text="User (wildcards ok):" Margin="0,0,6,0"/>
        <TextBox x:Name="TxtUser" Width="150" Text="*" Margin="0,0,14,0"/>
        <TextBlock Text="Range:" Margin="0,0,6,0"/>
        <ComboBox x:Name="CmbRange" Width="150" Margin="0,0,8,0">
          <ComboBoxItem Content="Last 1 hour"/>
          <ComboBoxItem Content="Last 8 hours"/>
          <ComboBoxItem Content="Last 24 hours" IsSelected="True"/>
          <ComboBoxItem Content="Last 3 days"/>
          <ComboBoxItem Content="Last 7 days"/>
          <ComboBoxItem Content="Custom range"/>
        </ComboBox>
        <DatePicker x:Name="DtFrom" Width="120" Margin="0,0,4,0" IsEnabled="False"/>
        <DatePicker x:Name="DtTo" Width="120" Margin="0,0,14,0" IsEnabled="False"/>
        <TextBlock Text="Max:" Margin="0,0,6,0"/>
        <TextBox x:Name="TxtMax" Width="70" Text="5000" Margin="0,0,14,0"/>
        <CheckBox x:Name="ChkCred" Content="Alt credentials"/>
        <Button x:Name="BtnQuery" Content="Run Query"/>
        <Button x:Name="BtnExport" Content="Export CSV" Background="#FF6B7280"/>
        <CheckBox x:Name="ChkAuto" Content="Auto-refresh 60s"/>
      </WrapPanel>
    </Border>

    <!-- Category filters -->
    <Border Grid.Row="1" Background="#FF272739" CornerRadius="6" Padding="8" Margin="0,0,0,8">
      <WrapPanel x:Name="PnlCats"/>
    </Border>

    <!-- Tabs -->
    <TabControl Grid.Row="2" Background="#FF1E1E2E" BorderBrush="#FF3A3A4C">
      <TabItem Header="Events">
        <Grid>
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
          <DockPanel Grid.Row="0" Margin="0,4">
            <TextBlock Text="Quick filter:" DockPanel.Dock="Left" Margin="2,0,6,0"/>
            <TextBox x:Name="TxtFilter" />
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
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <StackPanel Orientation="Horizontal" Grid.Row="0" Margin="0,0,0,8">
            <TextBlock Text="Locked user:" Margin="0,0,6,0"/>
            <TextBox x:Name="TxtLockUser" Width="180" Margin="0,0,10,0"/>
            <Button x:Name="BtnLockGo" Content="Trace lockout source"/>
            <TextBlock x:Name="TxtLockInfo" Margin="14,0,0,0" Foreground="#FFFFC857"/>
          </StackPanel>
          <DataGrid x:Name="GridLock" Grid.Row="1" AutoGenerateColumns="False" IsReadOnly="True"
                    Background="#FF1E1E2E" Foreground="#FFE6E6E6" RowBackground="#FF252536"
                    AlternatingRowBackground="#FF2A2A3C" HeadersVisibility="Column">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Time" Binding="{Binding TimeStr}" Width="140"/>
              <DataGridTextColumn Header="ID" Binding="{Binding EventId}" Width="55"/>
              <DataGridTextColumn Header="Category" Binding="{Binding Category}" Width="200"/>
              <DataGridTextColumn Header="User" Binding="{Binding User}" Width="140"/>
              <DataGridTextColumn Header="Source Host" Binding="{Binding SourceHost}" Width="150"/>
              <DataGridTextColumn Header="Source IP" Binding="{Binding SourceIP}" Width="130"/>
              <DataGridTextColumn Header="Reason / Detail" Binding="{Binding Reason}" Width="320"/>
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

    <StatusBar Grid.Row="3" Background="#FF272739" Margin="0,8,0,0">
      <StatusBarItem><TextBlock x:Name="TxtStatus" Text="Ready."/></StatusBarItem>
    </StatusBar>
  </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$Win    = [Windows.Markup.XamlReader]::Load($reader)

# Resolve named controls
$ctl = @{}
$xaml.SelectNodes("//*[@*[local-name()='Name']]") | ForEach-Object {
    $n = $_.Attributes['x:Name'].Value
    if ($n) { $ctl[$n] = $Win.FindName($n) }
}

# Build category checkboxes
$Script:CatBoxes = @()
foreach ($g in $Script:Groups.GetEnumerator()) {
    $cb = New-Object System.Windows.Controls.CheckBox
    $cb.Content   = $g.Key
    $cb.IsChecked = $true
    $cb.Tag       = $g.Value
    $cb.Foreground = 'White'
    $ctl.PnlCats.Children.Add($cb) | Out-Null
    $Script:CatBoxes += $cb
}

# Load saved config and populate the target dropdown
$Script:Config = Get-AuditConfig

function Update-TargetList {
    param([string]$Select)
    $cur = if ($Select) { $Select } else { $ctl.CmbTarget.Text }
    $list = New-Object System.Collections.Generic.List[string]
    $list.Add($env:COMPUTERNAME)
    if ($env:LOGONSERVER) { $list.Add(($env:LOGONSERVER -replace '^\\\\','')) }
    foreach ($s in @($Script:Config.Servers)) { if ($s -and -not $list.Contains($s)) { $list.Add($s) } }
    $ctl.CmbTarget.ItemsSource = @($list | Select-Object -Unique)
    if ($cur) { $ctl.CmbTarget.Text = $cur }
}

Update-TargetList
$initialTarget = if ($Script:Config.LastTarget) { $Script:Config.LastTarget }
                 elseif ($Target -and $Target -ne $env:COMPUTERNAME) { $Target }
                 elseif ($env:LOGONSERVER) { $env:LOGONSERVER -replace '^\\\\','' }
                 else { $env:COMPUTERNAME }
$ctl.CmbTarget.Text  = $initialTarget
$ctl.ChkAllDc.IsChecked = [bool]$Script:Config.QueryAllDcs

# Shared state for the background runspace
$Script:Sync = [hashtable]::Synchronized(@{ Running=$false; Done=$false; Rows=$null; Error=$null })
$Script:AllRows = @()

function Get-SelectedIds {
    $ids = @()
    foreach ($cb in $Script:CatBoxes) { if ($cb.IsChecked) { $ids += $cb.Tag } }
    return ($ids | Select-Object -Unique)
}

function Get-TimeWindow {
    $now = Get-Date
    switch ($ctl.CmbRange.SelectedIndex) {
        0 { return @($now.AddHours(-1),  $now) }
        1 { return @($now.AddHours(-8),  $now) }
        2 { return @($now.AddHours(-24), $now) }
        3 { return @($now.AddDays(-3),   $now) }
        4 { return @($now.AddDays(-7),   $now) }
        5 {
            $f = if ($ctl.DtFrom.SelectedDate) { $ctl.DtFrom.SelectedDate } else { $now.AddDays(-1) }
            $t = if ($ctl.DtTo.SelectedDate)   { ([datetime]$ctl.DtTo.SelectedDate).AddDays(1).AddSeconds(-1) } else { $now }
            return @($f, $t)
        }
        default { return @($now.AddHours(-24), $now) }
    }
}

$Script:Cred = $null

function Start-Audit {
    if ($Script:Sync.Running) { return }
    $ids = Get-SelectedIds
    if (-not $ids) { $ctl.TxtStatus.Text = 'Select at least one category.'; return }
    $win = Get-TimeWindow

    if ($ctl.ChkCred.IsChecked -and -not $Script:Cred) {
        $Script:Cred = Get-Credential -Message "Domain credentials for querying / DC discovery"
    }
    if (-not $ctl.ChkCred.IsChecked) { $Script:Cred = $null }

    $maxN = 5000; [int]::TryParse($ctl.TxtMax.Text, [ref]$maxN) | Out-Null

    # Resolve target(s): one typed host, or every discovered DC.
    if ($ctl.ChkAllDc.IsChecked) {
        $ctl.TxtStatus.Text = 'Discovering domain controllers...'
        $dc = Get-DomainControllerList -Credential $Script:Cred
        if ($dc.Error -or -not $dc.DCs) {
            $ctl.TxtStatus.Text = "DC discovery failed: $($dc.Error)"; return
        }
        $targets = @($dc.DCs)
    } else {
        $t = $ctl.CmbTarget.Text.Trim()
        if (-not $t) { $ctl.TxtStatus.Text = 'Enter or pick a target server.'; return }
        $targets = @($t)
    }

    # Persist selection
    $Script:Config.LastTarget  = $ctl.CmbTarget.Text.Trim()
    $Script:Config.QueryAllDcs = [bool]$ctl.ChkAllDc.IsChecked
    Save-AuditConfig $Script:Config

    $qargs = @{
        Targets    = $targets
        EventIds   = $ids
        Start      = $win[0]
        End        = $win[1]
        UserFilter = $ctl.TxtUser.Text.Trim()
        MaxEvents  = $maxN
        Credential = $Script:Cred
    }

    $Script:Sync.Running = $true
    $Script:Sync.Done    = $false
    $Script:Sync.Error   = $null
    $ctl.TxtStatus.Text  = "Querying $($qargs.Targets -join ', ') ..."
    $ctl.BtnQuery.IsEnabled = $false
    $Win.Cursor = [System.Windows.Input.Cursors]::Wait

    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'; $rs.ThreadOptions = 'ReuseThread'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('sync',    $Script:Sync)
    $rs.SessionStateProxy.SetVariable('qa',      $qargs)
    $rs.SessionStateProxy.SetVariable('funcDefs',
        "${function:ConvertTo-AuditRow}|||${function:Invoke-AuditQuery}|||" +
        "${function:Get-DecodedStatus}|||${function:Get-DecodedKerb}|||${function:Get-DecodedLogonType}")
    $rs.SessionStateProxy.SetVariable('maps', @{
        LogonTypeMap=$Script:LogonTypeMap; StatusMap=$Script:StatusMap; KerbMap=$Script:KerbMap
        CategoryMap=$Script:CategoryMap; SecurityIds=$Script:SecurityIds; SystemIds=$Script:SystemIds })

    $worker = {
        try {
            $Script:LogonTypeMap = $maps.LogonTypeMap; $Script:StatusMap = $maps.StatusMap
            $Script:KerbMap = $maps.KerbMap; $Script:CategoryMap = $maps.CategoryMap
            $Script:SecurityIds = $maps.SecurityIds; $Script:SystemIds = $maps.SystemIds
            $parts = $funcDefs -split '\|\|\|'
            Set-Item function:ConvertTo-AuditRow     ([scriptblock]::Create($parts[0]))
            Set-Item function:Invoke-AuditQuery      ([scriptblock]::Create($parts[1]))
            Set-Item function:Get-DecodedStatus      ([scriptblock]::Create($parts[2]))
            Set-Item function:Get-DecodedKerb        ([scriptblock]::Create($parts[3]))
            Set-Item function:Get-DecodedLogonType   ([scriptblock]::Create($parts[4]))
            $all = New-Object System.Collections.Generic.List[object]
            $errs = @()
            foreach ($tgt in $qa.Targets) {
                try {
                    $r = Invoke-AuditQuery -ComputerName $tgt -EventIds $qa.EventIds `
                            -Start $qa.Start -End $qa.End -UserFilter $qa.UserFilter `
                            -MaxEvents $qa.MaxEvents -Credential $qa.Credential
                    foreach ($x in @($r)) { $all.Add($x) }
                } catch {
                    $errs += "[$tgt] $($_.Exception.Message)"
                }
            }
            $sync.Rows = @($all | Sort-Object Time -Descending)
            if ($errs -and $all.Count -eq 0) { $sync.Error = ($errs -join "`n") }
        } catch {
            $sync.Error = $_.Exception.Message
        } finally {
            $sync.Done = $true
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
    # Summary - by category
    $ctl.GridSumCat.ItemsSource = @($rows | Group-Object Category | Sort-Object Count -Descending |
        ForEach-Object { [pscustomobject]@{ Name=$_.Name; Count=$_.Count } })
    # Top users by failure
    $ctl.GridSumUser.ItemsSource = @($rows | Where-Object { $_.Result -in 'Failure','Lockout' -and $_.User } |
        Group-Object User | Sort-Object Count -Descending | Select-Object -First 25 |
        ForEach-Object { [pscustomobject]@{ Name=$_.Name; Count=$_.Count } })
    # Top sources by failure
    $ctl.GridSumSrc.ItemsSource = @($rows | Where-Object { $_.Result -in 'Failure','Lockout' } |
        ForEach-Object { if ($_.SourceHost) { $_.SourceHost } elseif ($_.SourceIP) { $_.SourceIP } else { '(unknown)' } } |
        Group-Object | Sort-Object Count -Descending | Select-Object -First 25 |
        ForEach-Object { [pscustomobject]@{ Name=$_.Name; Count=$_.Count } })

    # Logout analyzer - group by user
    $byUser = $rows | Where-Object { $_.User } | Group-Object User | ForEach-Object {
        $g = $_.Group
        $lo = @($g | Where-Object EventId -in 4634,4647).Count
        $rd = @($g | Where-Object EventId -eq 4779).Count
        $lk = @($g | Where-Object EventId -eq 4800).Count
        $out= @($g | Where-Object EventId -eq 4740).Count
        $reboot = @($rows | Where-Object EventId -in 1074,6008,41).Count
        $likely = @()
        if ($out -gt 0)            { $likely += "Account LOCKOUT ($out) - bad cached creds/old session somewhere" }
        if ($reboot -gt 0 -and $lo -gt 0) { $likely += "Machine reboot/shutdown in window ($reboot) - users dropped" }
        if ($rd -gt 2)             { $likely += "Repeated RDP disconnects ($rd) - idle/session-limit GPO or network" }
        if ($lk -gt 5)             { $likely += "Frequent workstation locks ($lk) - screensaver/lock GPO" }
        if (-not $likely)          { $likely += "Normal sign-out activity" }
        [pscustomobject]@{
            User=$_.Name; Logoffs=$lo; RdpDisc=$rd; Locks=$lk; Lockouts=$out
            Last=($g | Sort-Object Time -Descending | Select-Object -First 1).Time
            LastStr=($g | Sort-Object Time -Descending | Select-Object -First 1).TimeStr
            Likely=($likely -join '  |  ')
        }
    }
    $ctl.GridOut.ItemsSource = @($byUser | Sort-Object Last -Descending)
}

function Apply-Filter {
    $f = $ctl.TxtFilter.Text
    $view = $Script:AllRows
    if ($f) {
        $view = $view | Where-Object {
            "$($_.User) $($_.SourceHost) $($_.SourceIP) $($_.Category) $($_.Reason) $($_.EventId) $($_.LoggedOn)" -like "*$f*"
        }
    }
    $ctl.Grid.ItemsSource = @($view)
    $tgtLbl = if ($ctl.ChkAllDc.IsChecked) { 'all DCs' } else { $ctl.CmbTarget.Text }
    $ctl.TxtStatus.Text = "{0} events  |  target {1}  |  {2}" -f @($view).Count, $tgtLbl, (Get-Date -Format 'HH:mm:ss')
}

# --- Events / wiring ---
$ctl.CmbRange.Add_SelectionChanged({
    $custom = ($ctl.CmbRange.SelectedIndex -eq 5)
    $ctl.DtFrom.IsEnabled = $custom; $ctl.DtTo.IsEnabled = $custom
})
$ctl.BtnQuery.Add_Click({ Start-Audit })

$ctl.BtnDiscover.Add_Click({
    if ($ctl.ChkCred.IsChecked -and -not $Script:Cred) {
        $Script:Cred = Get-Credential -Message "Domain credentials for DC discovery"
    }
    $ctl.TxtStatus.Text = 'Discovering domain controllers...'
    $Win.Cursor = [System.Windows.Input.Cursors]::Wait
    $dc = Get-DomainControllerList -Credential $Script:Cred
    $Win.Cursor = $null
    if ($dc.Error -or -not $dc.DCs) {
        $ctl.TxtStatus.Text = "DC discovery failed: $($dc.Error)"
        [System.Windows.MessageBox]::Show("Could not enumerate domain controllers.`n`n$($dc.Error)`n`nTip: tick 'Alt credentials' and use a domain account, or run on a domain-joined machine.",'DC discovery','OK','Warning') | Out-Null
        return
    }
    $merged = @(@($Script:Config.Servers) + $dc.DCs | Where-Object { $_ } | Select-Object -Unique)
    $Script:Config.Servers = $merged
    Save-AuditConfig $Script:Config
    Update-TargetList
    if ($dc.Pdc) { $ctl.CmbTarget.Text = $dc.Pdc }
    $pdcNote = if ($dc.Pdc) { "  PDC emulator: $($dc.Pdc) (best single target for lockouts)" } else { '' }
    $ctl.TxtStatus.Text = "Found $($dc.DCs.Count) DC(s) in $($dc.Domain).$pdcNote"
})

$ctl.BtnManage.Add_Click({
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
    $mw.Owner = $Win
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

$ctl.TxtFilter.Add_TextChanged({ Apply-Filter })
$ctl.Grid.Add_SelectionChanged({
    $sel = $ctl.Grid.SelectedItem
    if ($sel) { $ctl.TxtDetail.Text = $sel.Message }
})
$ctl.BtnExport.Add_Click({
    if (-not $Script:AllRows) { $ctl.TxtStatus.Text='Nothing to export - run a query first.'; return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter='CSV (*.csv)|*.csv'; $dlg.FileName="WinLogonAuditor_$(Get-Date -Format yyyyMMdd_HHmmss).csv"
    if ($dlg.ShowDialog() -eq 'OK') {
        $Script:AllRows | Select-Object TimeStr,EventId,Result,Category,User,Domain,SourceHost,SourceIP,LogonType,Reason,LoggedOn |
            Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
        $ctl.TxtStatus.Text = "Exported $(@($Script:AllRows).Count) rows to $($dlg.FileName)"
    }
})
$ctl.BtnLockGo.Add_Click({
    $u = $ctl.TxtLockUser.Text.Trim()
    if (-not $u) { $ctl.TxtLockInfo.Text='Enter a username.'; return }
    $rows = $Script:AllRows | Where-Object {
        $_.User -like "*$u*" -and $_.EventId -in 4740,4625,4771,4768,4776,4624
    } | Sort-Object Time -Descending
    $ctl.GridLock.ItemsSource = @($rows)
    $src = ($rows | Where-Object EventId -eq 4740 | Select-Object -First 1).Reason
    $lastFail = ($rows | Where-Object EventId -in 4625,4771 | Select-Object -First 1)
    $msg = if ($src) { "Most recent lockout -> $src." } else { "No 4740 in current data (widen range / query the DC)." }
    if ($lastFail) { $msg += "  Last failure from host '$($lastFail.SourceHost)' IP '$($lastFail.SourceIP)': $($lastFail.Reason)" }
    $ctl.TxtLockInfo.Text = $msg
})

# Poll the runspace
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromMilliseconds(400)
$timer.Add_Tick({
    if ($Script:Sync.Running -and $Script:Sync.Done) {
        try {
            if ($Script:Sync.PS) { $Script:Sync.PS.EndInvoke($Script:Sync.Handle) | Out-Null }
        } catch {}
        if ($Script:Sync.Error) {
            $ctl.TxtStatus.Text = "ERROR: $($Script:Sync.Error)"
            [System.Windows.MessageBox]::Show($Script:Sync.Error,'Query failed','OK','Error') | Out-Null
        } else {
            Update-Views $Script:Sync.Rows
        }
        if ($Script:Sync.RS) { $Script:Sync.PS.Dispose(); $Script:Sync.RS.Close() }
        $Script:Sync.Running = $false
        $ctl.BtnQuery.IsEnabled = $true
        $Win.Cursor = $null
    }
})
$timer.Start()

# Auto refresh
$autoTimer = New-Object System.Windows.Threading.DispatcherTimer
$autoTimer.Interval = [TimeSpan]::FromSeconds(60)
$autoTimer.Add_Tick({ if ($ctl.ChkAuto.IsChecked -and -not $Script:Sync.Running) { Start-Audit } })
$autoTimer.Start()

$Win.Add_Closed({
    $timer.Stop(); $autoTimer.Stop()
    try {
        $Script:Config.LastTarget  = $ctl.CmbTarget.Text.Trim()
        $Script:Config.QueryAllDcs = [bool]$ctl.ChkAllDc.IsChecked
        Save-AuditConfig $Script:Config
    } catch {}
})

# Kick off an initial query
$Win.Add_ContentRendered({ Start-Audit })

if ($NoShow) {
    Write-Host "SELFTEST OK: window built, $($ctl.Count) named controls resolved, $($Script:CatBoxes.Count) category filters." -ForegroundColor Green
    return
}
$Win.ShowDialog() | Out-Null

#endregion
