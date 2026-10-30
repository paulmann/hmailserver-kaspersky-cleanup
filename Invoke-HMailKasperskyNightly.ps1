#Requires -Version 7.2
<#
.SYNOPSIS
    Nightly audit of the hMailServer store: refresh the avp.com path, update bases, scan, plan.

.DESCRIPTION
    Orchestrates the existing tools with settings from config.local.psd1:
      1. Update-KavCurrent.ps1 logic inline: publish a live avp.com path;
      2. optional `avp.com UPDATE` (bases and modules; no credentials are accepted by UPDATE);
      3. Invoke-HMailKasperskyCleanup.ps1 -Mode Scan for the last Nightly.SinceDays days;
      4. optional remediation (-Mode Delete) when Nightly.AutoRemediate is enabled and a plan exists.

    Deletion always goes through hMailServer's COM API and keeps a quarantine copy; the antivirus
    itself never modifies the store.

.PARAMETER SinceDays
    Override Nightly.SinceDays for this run.

.PARAMETER SkipUpdate
    Do not refresh the bases before scanning.

.PARAMETER DryRun
    Force report-only mode even when Nightly.AutoRemediate is enabled.

.EXAMPLE
    .\Invoke-HMailKasperskyNightly.ps1 -SinceDays 2 -SkipUpdate -DryRun
#>

[CmdletBinding()]
param(
    [string] $ConfigPath,
    [ValidateRange(0, 3650)] [int] $SinceDays = -1,
    [switch] $SkipUpdate,
    [switch] $DryRun,
    [switch] $Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module -Name (Join-Path $PSScriptRoot 'HMailKaspersky.Kit.psm1') -Force

$config = Get-KitConfig -ConfigPath $ConfigPath
$component = 'nightly'

function Write-Nightly {
    param([string] $Message, [string] $Level = 'INFO')
    Write-KitLog -Config $config -Component $component -Level $Level -Message $Message -Quiet:$Quiet
}

$days = if ($SinceDays -ge 0) { $SinceDays } else { [int] (Get-KitValue -Config $config -Path 'Nightly.SinceDays' -Default 2) }
$batchSize = [int] (Get-KitValue -Config $config -Path 'Nightly.BatchSize' -Default 40)
$timeoutMinutes = [int] (Get-KitValue -Config $config -Path 'Nightly.TimeoutMinutes' -Default 20)
$reports = [string] (Get-KitValue -Config $config -Path 'Nightly.ReportsDirectory')
$quarantine = [string] (Get-KitValue -Config $config -Path 'Nightly.QuarantineDirectory')
$autoRemediate = [bool] (Get-KitValue -Config $config -Path 'Nightly.AutoRemediate' -Default $false)
$doUpdate = -not $SkipUpdate -and [bool] (Get-KitValue -Config $config -Path 'Nightly.UpdateDatabases' -Default $true)
$reportOnly = $DryRun -or $config['Nightly']['DryRun']

Write-Nightly ('=== nightly start: sinceDays={0}; batch={1}; timeout={2}m; dryRun={3} ===' -f $days, $batchSize, $timeoutMinutes, [bool] $reportOnly)

# --- 1. publish a live avp.com path
$avp = Resolve-KitAvpPath -Config $config -UsePublished
if (-not $avp) {
    Write-Nightly 'no usable avp.com found; nightly aborted' 'ERROR'
    exit 1
}
$record = Publish-KitAvpPath -Config $config -AvpPath $avp -Source 'nightly'
Write-Nightly ('kaspersky: {0} (version {1})' -f $record.AvpPath, $record.Version)

# --- 2. bases and modules
if ($doUpdate) {
    $update = Invoke-KitProcess -FilePath $avp -ArgumentList @('UPDATE') -TimeoutSeconds 900 -WorkingDirectory (Split-Path -Parent $avp)
    Write-Nightly ('bases update: exit={0}; {1:n1}s' -f $update.ExitCode, $update.Elapsed.TotalSeconds) $(if ($update.ExitCode -eq 0) { 'INFO' } else { 'WARN' })
}
else {
    Write-Nightly 'bases update skipped by request'
}

# --- 3. scan
$tool = [string] (Get-KitValue -Config $config -Path 'Nightly.CleanupToolPath')
if ([string]::IsNullOrWhiteSpace($tool)) { $tool = Join-Path $PSScriptRoot 'Invoke-HMailKasperskyCleanup.ps1' }
if (-not (Test-Path -LiteralPath $tool)) {
    Write-Nightly ('cleanup tool not found: {0}' -f $tool) 'ERROR'
    exit 1
}

$scanArguments = @(
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $tool),
    '-Mode', 'Scan',
    '-SinceDays', $days,
    '-BatchSize', $batchSize,
    '-TimeoutMinutes', $timeoutMinutes,
    '-ReportDirectory', ('"{0}"' -f $reports),
    '-QuarantineDirectory', ('"{0}"' -f $quarantine),
    '-AvpPath', ('"{0}"' -f $avp)
)
$process = Invoke-KitProcess -FilePath 'pwsh.exe' -ArgumentList $scanArguments -TimeoutSeconds (($timeoutMinutes + 10) * 60)
Write-Nightly ('scan: exit={0}; {1:n1}s' -f $process.ExitCode, $process.Elapsed.TotalSeconds)
if ($process.ExitCode -ne 0) {
    Write-Nightly ('scan finished with exit {0}; tail: {1}' -f $process.ExitCode, (($process.StdOut -split "`r?`n" | Select-Object -Last 3) -join ' | ')) 'WARN'
}

# --- 4. remediation
if ($reportOnly) {
    Write-Nightly 'report-only mode: no messages are deleted'
    exit 0
}

if (-not $autoRemediate) {
    Write-Nightly 'remediation is disabled (Nightly.AutoRemediate = $false); review the plan and run -Mode Delete manually'
    exit 0
}

$latestPlan = Get-ChildItem -LiteralPath $reports -Directory -Filter 'run-*' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | ForEach-Object { Join-Path $_.FullName 'remediation-plan.json' } |
    Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

if (-not $latestPlan) {
    Write-Nightly 'no remediation plan produced; nothing to delete'
    exit 0
}

$deleteArguments = @(
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $tool),
    '-Mode', 'Delete', '-PlanPath', ('"{0}"' -f $latestPlan),
    '-QuarantineDirectory', ('"{0}"' -f $quarantine),
    '-TimeoutMinutes', $timeoutMinutes
)
$delete = Invoke-KitProcess -FilePath 'pwsh.exe' -ArgumentList $deleteArguments -TimeoutSeconds (($timeoutMinutes + 10) * 60)
Write-Nightly ('remediation: exit={0}; plan={1}' -f $delete.ExitCode, $latestPlan)
exit $delete.ExitCode
