<#
.SYNOPSIS
    Driftwatch baseline hygiene check for Windows. Read-only.

.DESCRIPTION
    Collects the state of Defender, Attack Surface Reduction, LSASS protection, Credential Guard,
    PowerShell logging, Sysmon coverage, audit policy, the firewall and SMBv1, and prints one JSON document
    (schema driftwatch.hygiene/v1) to stdout. The Driftwatch agent embeds this script and runs it for the
    signed hygiene.collect action; it can also be run by hand:

        powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-DriftwatchBaseline.ps1 | ConvertFrom-Json

    Every check returns pass, fail or unknown (unknown means the state could not be read, for example
    without administrator rights). Nothing on the system is changed.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0.0'
$checks = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('low', 'medium', 'high')][string]$Severity,
        [Parameter(Mandatory)][string]$Expected,
        [Parameter(Mandatory)][scriptblock]$Probe,
        [object[]]$ArgumentList = @()
    )
    # $Probe returns @{ status = 'pass'|'fail'|'unknown'; actual = '...'; detail = '...' }
    $entry = [ordered]@{ id = $Id; title = $Title; severity = $Severity; expected = $Expected
                         status = 'unknown'; actual = $null; detail = '' }
    try {
        $r = & $Probe @ArgumentList
        $entry.status = $r.status
        $entry.actual = [string]$r.actual
        if ($r.ContainsKey('detail')) { $entry.detail = [string]$r.detail }
    } catch {
        $entry.detail = "could not read: $($_.Exception.Message)"
    }
    $checks.Add([pscustomobject]$entry)
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Name
}

function Test-Bool([bool]$Value, [string]$WhenTrue = 'enabled', [string]$WhenFalse = 'disabled') {
    if ($Value) { return @{ status = 'pass'; actual = $WhenTrue } }
    return @{ status = 'fail'; actual = $WhenFalse }
}

# --- Microsoft Defender ------------------------------------------------------------------------------
$mp = $null
$mpPref = $null
try { $mp = Get-MpComputerStatus } catch { $mp = $null }
try { $mpPref = Get-MpPreference } catch { $mpPref = $null }

Add-Check 'win.defender.antivirus_enabled' 'Defender antivirus enabled' 'high' 'enabled' {
    if (-not $mp) { return @{ status = 'unknown'; actual = 'Defender status unavailable' } }
    Test-Bool $mp.AntivirusEnabled
}
Add-Check 'win.defender.realtime_protection' 'Defender real-time protection' 'high' 'enabled' {
    if (-not $mp) { return @{ status = 'unknown'; actual = 'Defender status unavailable' } }
    Test-Bool $mp.RealTimeProtectionEnabled
}
Add-Check 'win.defender.cloud_protection' 'Defender cloud-delivered protection' 'medium' 'MAPS basic or advanced' {
    if (-not $mpPref) { return @{ status = 'unknown'; actual = 'Defender preferences unavailable' } }
    $level = [int]$mpPref.MAPSReporting
    $names = @{ 0 = 'disabled'; 1 = 'basic'; 2 = 'advanced' }
    @{ status = $(if ($level -ge 1) { 'pass' } else { 'fail' }); actual = $names[$level] }
}
Add-Check 'win.defender.tamper_protection' 'Defender tamper protection' 'high' 'enabled' {
    if (-not $mp -or -not ($mp.PSObject.Properties.Name -contains 'IsTamperProtected')) {
        return @{ status = 'unknown'; actual = 'not reported by this Defender version' }
    }
    Test-Bool $mp.IsTamperProtected
}
Add-Check 'win.defender.signature_age' 'Defender signatures updated in the last 3 days' 'medium' '<= 3 days' {
    if (-not $mp) { return @{ status = 'unknown'; actual = 'Defender status unavailable' } }
    $age = [int]$mp.AntivirusSignatureAge
    @{ status = $(if ($age -le 3) { 'pass' } else { 'fail' }); actual = "$age days" }
}

# --- Attack Surface Reduction ------------------------------------------------------------------------
$asrRules = [ordered]@{
    'block_lsass_credential_theft'  = @('9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'Block credential stealing from LSASS', 'high')
    'block_obfuscated_scripts'      = @('5beb7efe-fd9a-4556-801d-275e5ffc04cc', 'Block potentially obfuscated scripts', 'high')
    'block_office_child_processes'  = @('d4f940ab-401b-4efc-aadc-ad5f3c50688a', 'Block Office apps from creating child processes', 'high')
    'block_email_executable_content' = @('be9ba2d9-53ea-4cdc-84e5-9b1eeee46550', 'Block executable content from email', 'medium')
    'block_wmi_persistence'         = @('e6db77e5-3df2-4cf1-b95a-636979351e5b', 'Block persistence through WMI event subscription', 'medium')
}
$asrModes = @{ 0 = 'off'; 1 = 'block'; 2 = 'audit'; 5 = 'not configured'; 6 = 'warn' }
$asrState = @{}
if ($mpPref -and $mpPref.AttackSurfaceReductionRules_Ids) {
    for ($i = 0; $i -lt @($mpPref.AttackSurfaceReductionRules_Ids).Count; $i++) {
        $asrState[([string]@($mpPref.AttackSurfaceReductionRules_Ids)[$i]).ToLower()] =
            [int]@($mpPref.AttackSurfaceReductionRules_Actions)[$i]
    }
}
foreach ($name in $asrRules.Keys) {
    $guid, $title, $sev = $asrRules[$name]
    Add-Check "win.asr.$name" "ASR: $title" $sev 'block' -ArgumentList $guid -Probe {
        param($guid)
        if (-not $mpPref) { return @{ status = 'unknown'; actual = 'Defender preferences unavailable' } }
        if (-not $asrState.ContainsKey($guid)) { return @{ status = 'fail'; actual = 'not configured'; detail = $guid } }
        $mode = $asrState[$guid]
        $label = if ($asrModes.ContainsKey($mode)) { $asrModes[$mode] } else { "mode $mode" }
        @{ status = $(if ($mode -eq 1) { 'pass' } else { 'fail' }); actual = $label; detail = $guid }
    }
}

# --- LSASS and credentials ---------------------------------------------------------------------------
Add-Check 'win.lsass.runasppl' 'LSASS runs as a protected process (RunAsPPL)' 'high' '1 or 2' {
    $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
    if ($null -eq $v) { return @{ status = 'fail'; actual = 'not set' } }
    @{ status = $(if ([int]$v -in 1, 2) { 'pass' } else { 'fail' }); actual = "RunAsPPL=$v" }
}
Add-Check 'win.lsass.wdigest_disabled' 'WDigest does not cache clear-text credentials' 'high' 'UseLogonCredential != 1' {
    $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    @{ status = $(if ($v -eq 1) { 'fail' } else { 'pass' }); actual = $(if ($null -eq $v) { 'not set (default off)' } else { "UseLogonCredential=$v" }) }
}
Add-Check 'win.credential_guard.running' 'Credential Guard running' 'medium' 'running' {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
    Test-Bool (@($dg.SecurityServicesRunning) -contains 1) 'running' 'not running'
}

# --- Logging coverage --------------------------------------------------------------------------------
Add-Check 'win.powershell.scriptblock_logging' 'PowerShell script block logging' 'medium' 'enabled' {
    $v = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    Test-Bool ($v -eq 1)
}
$sysmon = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
Add-Check 'win.sysmon.process_creation' 'Sysmon service running (process creation)' 'high' 'running' {
    if (-not $sysmon) { return @{ status = 'fail'; actual = 'not installed' } }
    Test-Bool ($sysmon.Status -eq 'Running') 'running' ([string]$sysmon.Status)
}
foreach ($probe in @(@('win.sysmon.dns', 22, 'Sysmon DNS query events (ID 22) in the last 24h'),
                     @('win.sysmon.registry', 13, 'Sysmon registry events (ID 13) in the last 24h'))) {
    $id, $eventId, $title = $probe
    Add-Check $id $title 'medium' 'events present' -ArgumentList $eventId -Probe {
        param($eventId)
        if (-not $sysmon) { return @{ status = 'fail'; actual = 'Sysmon not installed' } }
        $evt = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = $eventId
                                                StartTime = (Get-Date).AddHours(-24) } -MaxEvents 1 -ErrorAction SilentlyContinue
        Test-Bool ($null -ne $evt) 'events present' 'no events in 24h (check the Sysmon config)'
    }
}
Add-Check 'win.audit.object_access' 'Audit policy: File System object access (success)' 'medium' 'Success' {
    # Subcategory GUID avoids localized names.
    $csv = & auditpol.exe /get /subcategory:'{0CCE921D-69AE-11D9-BED3-505054503030}' /r 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $csv) { return @{ status = 'unknown'; actual = 'auditpol needs administrator rights' } }
    $row = $csv | Where-Object { $_ } | ConvertFrom-Csv | Select-Object -First 1
    $setting = [string]$row.'Inclusion Setting'
    @{ status = $(if ($setting -match 'Success') { 'pass' } else { 'fail' }); actual = $setting }
}

# --- Network hardening -------------------------------------------------------------------------------
foreach ($profileName in 'Domain', 'Private', 'Public') {
    Add-Check "win.firewall.$($profileName.ToLower())" "Windows Firewall $profileName profile" 'medium' 'enabled' -ArgumentList $profileName -Probe {
        param($profileName)
        $p = Get-NetFirewallProfile -Name $profileName
        Test-Bool ([bool]$p.Enabled)
    }
}
Add-Check 'win.smb1.disabled' 'SMBv1 server protocol disabled' 'high' 'disabled' {
    $smb = Get-SmbServerConfiguration
    Test-Bool (-not $smb.EnableSMB1Protocol) 'disabled' 'enabled'
}

$os = Get-CimInstance Win32_OperatingSystem
[ordered]@{
    schema         = 'driftwatch.hygiene/v1'
    platform       = 'windows'
    hostname       = $env:COMPUTERNAME
    os_version     = "$($os.Caption) $($os.Version)"
    script_version = $ScriptVersion
    collected_at   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'")
    is_admin       = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                        [Security.Principal.WindowsBuiltInRole]::Administrator)
    checks         = $checks
} | ConvertTo-Json -Depth 5 -Compress
