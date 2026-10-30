#Requires -Version 7.2
<#
.SYNOPSIS
    Install or update the kit: copy scripts, keep the local configuration, register the tasks.

.DESCRIPTION
    Updates are additive: `git pull` changes the tracked scripts, while config.local.psd1 stays
    untracked and is never overwritten by this installer. Re-running the installer after an update
    refreshes the scripts and re-registers the tasks, and it reports clearly whether the local
    configuration was preserved, created or left alone.

    Tasks are registered as SYSTEM with the names from config Tasks.*:
      * Nightly     - Invoke-HMailKasperskyNightly.ps1 (default 02:09);
      * PathRefresh - Update-KavCurrent.ps1 -Quiet (default 22:11);
      * Update      - Invoke-KavUpdate.ps1 -Quiet (default 06:05);
      * Reboot      - Invoke-RebootWindow.ps1 (default 06:15 and 06:40).

.PARAMETER DryRun
    Print what would be copied and registered, change nothing.

.PARAMETER NoTasks
    Copy the files only.

.EXAMPLE
    .\Install-HMailKasperskyKit.ps1 -DryRun
#>

[CmdletBinding()]
param(
    [string] $ConfigPath,
    [switch] $DryRun,
    [switch] $NoTasks,
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module -Name (Join-Path $PSScriptRoot 'HMailKaspersky.Kit.psm1') -Force

$config = Get-KitConfig -ConfigPath $ConfigPath
$installDirectory = [string] (Get-KitValue -Config $config -Path 'Kit.InstallDirectory' -Default 'C:\ProgramData\hMailKaspersky\kit')
$logDirectory = [string] (Get-KitValue -Config $config -Path 'Kit.LogDirectory')
$stateDirectory = [string] (Get-KitValue -Config $config -Path 'Kit.StateDirectory')

function Write-Step {
    param([string] $Message)
    Write-Output $Message
}

Write-Step ('install directory: {0}' -f $installDirectory)
Write-Step ('configuration:     {0}' -f $config['ConfigPath'])

$files = @(Get-ChildItem -LiteralPath $PSScriptRoot -File | Where-Object {
        $_.Extension -in @('.ps1', '.psm1', '.psd1') -or $_.Name -in @('LICENSE')
    } | Where-Object { $_.Name -ne 'config.local.psd1' })

if ($DryRun) {
    foreach ($file in $files) { Write-Step ('would copy: {0}' -f $file.Name) }
}
else {
    foreach ($directory in @($installDirectory, $logDirectory, $stateDirectory)) {
        if ($directory -and -not (Test-Path -LiteralPath $directory)) { $null = New-Item -ItemType Directory -Force -Path $directory }
    }

    foreach ($file in $files) {
        $destination = Join-Path $installDirectory $file.Name
        Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
    }
    Write-Step ('copied {0} file(s)' -f $files.Count)

    # the local configuration is untracked: never overwrite an existing one
    $localConfig = Join-Path $PSScriptRoot 'config.local.psd1'
    $installLocal = Join-Path $installDirectory 'config.local.psd1'
    if (Test-Path -LiteralPath $installLocal) {
        Write-Step 'local configuration preserved (install directory already has config.local.psd1)'
    }
    elseif (Test-Path -LiteralPath $localConfig) {
        Copy-Item -LiteralPath $localConfig -Destination $installLocal -Force
        Write-Step 'local configuration copied into the install directory'
    }
    else {
        Write-Step 'NO config.local.psd1: copy config.example.psd1 there and fill in your paths before registering tasks'
    }
}

if ($NoTasks) { Write-Step 'tasks skipped (-NoTasks)'; exit 0 }

if (-not (Get-Command -Name 'pwsh.exe' -ErrorAction SilentlyContinue)) {
    Write-Step 'pwsh.exe not found in PATH: scheduled tasks need PowerShell 7'
}

$pwshPath = (Get-Command -Name 'pwsh.exe' -ErrorAction SilentlyContinue).Source
if (-not $pwshPath) { $pwshPath = 'C:\Program Files\PowerShell\7\pwsh.exe' }

$taskSpecs = @(
    @{ Name = [string] (Get-KitValue -Config $config -Path 'Tasks.Nightly'); Script = 'Invoke-HMailKasperskyNightly.ps1'; Argument = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"'; Trigger = '02:09'; Limit = (New-TimeSpan -Hours 6) }
    @{ Name = [string] (Get-KitValue -Config $config -Path 'Tasks.PathRefresh'); Script = 'Update-KavCurrent.ps1'; Argument = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Quiet'; Trigger = '22:11'; Limit = (New-TimeSpan -Minutes 30) }
    @{ Name = [string] (Get-KitValue -Config $config -Path 'Tasks.Update'); Script = 'Invoke-KavUpdate.ps1'; Argument = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Quiet'; Trigger = [string] (Get-KitValue -Config $config -Path 'Maintenance.UpdateTime' -Default '06:05'); Limit = (New-TimeSpan -Hours 1) }
)

$rebootTimes = @(Get-KitValue -Config $config -Path 'Maintenance.RebootTimes' -Default @('06:15', '06:40'))
$taskSpecs += @{ Name = [string] (Get-KitValue -Config $config -Path 'Tasks.Reboot'); Script = 'Invoke-RebootWindow.ps1'; Argument = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"'; Triggers = @($rebootTimes); Limit = (New-TimeSpan -Minutes 30) }

foreach ($spec in $taskSpecs) {
    if ([string]::IsNullOrWhiteSpace($spec.Name)) { Write-Step ('skip task: name is empty for {0}' -f $spec.Script); continue }

    $scriptPath = Join-Path $installDirectory $spec.Script
    $arguments = $spec.Argument -f $scriptPath
    $times = if ($spec.ContainsKey('Triggers')) { @($spec.Triggers) } else { @([string] $spec.Trigger) }

    if ($DryRun) {
        Write-Step ('would register: {0} at {1}' -f $spec.Name, ($times -join ', '))
        continue
    }

    $action = New-ScheduledTaskAction -Execute $pwshPath -Argument $arguments -WorkingDirectory $installDirectory
    $triggers = @($times | ForEach-Object { New-ScheduledTaskTrigger -Daily -At $_ })
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit $spec.Limit

    Register-ScheduledTask -TaskName $spec.Name -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
    Write-Step ('registered task: {0} at {1}' -f $spec.Name, ($times -join ', '))
}

Write-Step 'done. Next: set the credentials (Set-KavAdminCredential.ps1) and check one run by hand.'
exit 0
