#Requires -Version 7.2
<#
.SYNOPSIS
    Restart the host only inside the maintenance window and only when a restart is actually pending.

.DESCRIPTION
    Checks the usual pending-reboot markers (CBS, Windows Update, pending file rename operations)
    and refuses to restart while a scan is running or a nightly job is still active. Used by a
    scheduled task with two triggers inside the allowed window (Maintenance.RebootTimes).

.PARAMETER WhatIf
    Report the decision without restarting.

.EXAMPLE
    .\Invoke-RebootWindow.ps1 -WhatIf
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $ConfigPath,
    [switch] $WhatIf,
    [switch] $Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

Import-Module -Name (Join-Path $PSScriptRoot 'HMailKaspersky.Kit.psm1') -Force

$config = Get-KitConfig -ConfigPath $ConfigPath
$component = 'reboot-window'
$delaySeconds = [int] (Get-KitValue -Config $config -Path 'Maintenance.RebootDelaySeconds' -Default 180)
$skipWhileScanning = [bool] (Get-KitValue -Config $config -Path 'Maintenance.RebootSkipWhileScanning' -Default $true)

$reasons = [System.Collections.Generic.List[string]]::new()

if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
    $reasons.Add('Component Based Servicing: RebootPending')
}
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
    $reasons.Add('Windows Update: RebootRequired')
}

try {
    $sessionManager = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
    if ($sessionManager.PSObject.Properties['PendingFileRenameOperations']) {
        $count = @($sessionManager.PendingFileRenameOperations).Count
        if ($count -gt 0) { $reasons.Add(('Session Manager: PendingFileRenameOperations x{0}' -f $count)) }
    }
}
catch {
    Write-KitLog -Config $config -Component $component -Level 'WARN' -Quiet:$Quiet -Message ('pending rename check failed: {0}' -f $_.Exception.Message)
}

$avp = Resolve-KitAvpPath -Config $config -UsePublished
if ($avp) {
    $status = Invoke-KitProcess -FilePath $avp -ArgumentList @('STATUS') -TimeoutSeconds 60 -WorkingDirectory (Split-Path -Parent $avp)
    $hits = @($status.StdOut -split "`r?`n" | Where-Object { $_ -match '(?i)restart required|reboot required|требуется перезагруз' })
    if ($hits.Count -gt 0) { $reasons.Add('Kaspersky STATUS: restart required') }
}

if ($reasons.Count -eq 0) {
    Write-KitLog -Config $config -Component $component -Quiet:$Quiet -Message 'nothing is waiting for a reboot; no action'
    Write-Output 'REBOOT=no reason'
    exit 0
}
foreach ($reason in $reasons) { Write-KitLog -Config $config -Component $component -Quiet:$Quiet -Message ('reason: ' + $reason) }

if ($skipWhileScanning) {
    $running = @(Get-Process -Name 'avp.com' -ErrorAction SilentlyContinue).Count
    if ($running -gt 2) {
        Write-KitLog -Config $config -Component $component -Level 'WARN' -Quiet:$Quiet -Message ('skip: {0} avp.com processes are running (scan in progress)' -f $running)
        Write-Output 'REBOOT=skipped (scan running)'
        exit 0
    }
}

if ($WhatIf) {
    Write-KitLog -Config $config -Component $component -Quiet:$Quiet -Message ('whatIf: would restart; reason: ' + ($reasons -join '; '))
    Write-Output ('REBOOT=would reboot: ' + ($reasons -join '; '))
    exit 0
}

if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, ('Restart in {0}s: {1}' -f $delaySeconds, ($reasons -join '; ')))) {
    Write-Output 'REBOOT=skipped (ShouldProcess)'
    exit 0
}

Write-KitLog -Config $config -Component $component -Quiet:$Quiet -Message ('requesting restart in {0}s' -f $delaySeconds)
& shutdown.exe /r /t $delaySeconds /d p:2:4 /c 'Scheduled maintenance window: pending updates require a restart'
Write-Output ('REBOOT=requested in {0}s: {1}' -f $delaySeconds, ($reasons -join '; '))
exit 0
