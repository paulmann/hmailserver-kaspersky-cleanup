#Requires -Version 7.2
<#
.SYNOPSIS
    Real-time scanner for hMailServer: checks one message through the Kaspersky console client.

.DESCRIPTION
    Register this script as hMailServer's external virus scanner. hMailServer calls it for every
    incoming message and treats exit code 2 as "infected" (message blocked/quarantined by
    hMailServer itself, never by the antivirus).

    The message is copied to a snapshot directory outside the store first. Scanning a file inside
    Program Files through a direct argument is unreliable: the path contains spaces, and the
    console client then receives a truncated argument and never finishes. A snapshot always has a
    space-free name, so the call stays stable.

    Fail-open: if the scanner cannot run (no avp.com, timeout, unreadable file), the message is
    accepted and the problem is logged. Blocking all mail because the antivirus is unavailable is
    worse than delivering it unscanned, and the nightly audit still covers the store.

.PARAMETER MessageFile
    Path to the .eml file. hMailServer appends it as the last argument.

.PARAMETER ConfigPath
    Explicit configuration file; otherwise the standard lookup order is used.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string] $MessageFile,

    [string] $ConfigPath,

    [switch] $Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module -Name (Join-Path $PSScriptRoot 'HMailKaspersky.Kit.psm1') -Force

$config = Get-KitConfig -ConfigPath $ConfigPath
$reportsDirectory = [string] (Get-KitValue -Config $config -Path 'Scanner.ReportsDirectory')
$detectionsDirectory = [string] (Get-KitValue -Config $config -Path 'Scanner.DetectionsDirectory')
$timeoutSeconds = [int] (Get-KitValue -Config $config -Path 'Scanner.TimeoutSeconds' -Default 120)
$maxSnapshotMb = [int] (Get-KitValue -Config $config -Path 'Scanner.MaxSnapshotMb' -Default 64)
$detectionExitCode = [int] (Get-KitValue -Config $config -Path 'Scanner.ExitCodeOnDetection' -Default 2)
$keepSnapshots = [bool] (Get-KitValue -Config $config -Path 'Scanner.KeepSnapshots' -Default $false)

foreach ($directory in @($reportsDirectory, $detectionsDirectory)) {
    if ($directory -and -not (Test-Path -LiteralPath $directory)) { $null = New-Item -ItemType Directory -Force -Path $directory }
}

if ([string]::IsNullOrWhiteSpace($MessageFile) -or -not (Test-Path -LiteralPath $MessageFile)) {
    Write-KitLog -Config $config -Component 'scanner' -Level 'ERROR' -Quiet:$Quiet -Message ('message file not found: {0}' -f $MessageFile)
    exit 0
}

$snapshotDirectory = [string] (Get-KitValue -Config $config -Path 'Scanner.SnapshotDirectory')
if ([string]::IsNullOrWhiteSpace($snapshotDirectory)) { $snapshotDirectory = Join-Path $env:TEMP 'kav-scan' }
if (-not (Test-Path -LiteralPath $snapshotDirectory)) { $null = New-Item -ItemType Directory -Force -Path $snapshotDirectory }

$snapshot = Join-Path $snapshotDirectory ('msg-{0}.eml' -f ([guid]::NewGuid().ToString('N')))

try {
    $sizeMb = (Get-Item -LiteralPath $MessageFile).Length / 1MB
    if ($sizeMb -gt $maxSnapshotMb) {
        Write-KitLog -Config $config -Component 'scanner' -Level 'WARN' -Quiet:$Quiet -Message ('message too large for a snapshot ({0:n1} MB > {1} MB), accepted unscanned: {2}' -f $sizeMb, $maxSnapshotMb, $MessageFile)
        exit 0
    }

    Copy-Item -LiteralPath $MessageFile -Destination $snapshot -Force

    $avp = Resolve-KitAvpPath -Config $config -UsePublished
    if (-not $avp) {
        Write-KitLog -Config $config -Component 'scanner' -Level 'ERROR' -Quiet:$Quiet -Message 'no usable avp.com found; message accepted unscanned'
        exit 0
    }

    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss-fff')
    $report = Join-Path $reportsDirectory ('scan-{0}.report.txt' -f $stamp)

    $result = Invoke-KitProcess -FilePath $avp -ArgumentList @('SCAN', '/i0', ('/RA:' + $report), $snapshot) `
        -TimeoutSeconds $timeoutSeconds -WorkingDirectory (Split-Path -Parent $avp)

    $detected = 0
    if (Test-Path -LiteralPath $report) {
        $text = Get-Content -LiteralPath $report -Raw -Encoding Default
        $match = [regex]::Match($text, '(?m)^;\s*Total detected:\s*(\d+)')
        if ($match.Success) { $detected = [int] $match.Groups[1].Value }
    }

    if ($detected -gt 0) {
        $evidence = Join-Path $detectionsDirectory ('{0}.report.txt' -f $stamp)
        Copy-Item -LiteralPath $report -Destination $evidence -Force -ErrorAction SilentlyContinue
        Write-KitLog -Config $config -Component 'scanner' -Level 'WARN' -Quiet:$Quiet -Message ('THREAT detected={0}; exit={1}; {2} ms; file={3}; report={4}' -f $detected, $result.ExitCode, [int] $result.Elapsed.TotalMilliseconds, $MessageFile, $evidence)
        exit $detectionExitCode
    }

    if ($result.TimedOut) {
        Write-KitLog -Config $config -Component 'scanner' -Level 'ERROR' -Quiet:$Quiet -Message ('scan timed out after {0}s for {1}; message accepted' -f $timeoutSeconds, $MessageFile)
        exit 0
    }

    Write-KitLog -Config $config -Component 'scanner' -Level 'INFO' -Quiet:$Quiet -Message ('clean; exit={0}; {1} ms; file={2}' -f $result.ExitCode, [int] $result.Elapsed.TotalMilliseconds, $MessageFile)
    exit 0
}
catch {
    Write-KitLog -Config $config -Component 'scanner' -Level 'ERROR' -Quiet:$Quiet -Message ('scanner failure: {0}; message accepted' -f $_.Exception.Message)
    exit 0
}
finally {
    if (-not $keepSnapshots -and (Test-Path -LiteralPath $snapshot)) {
        Remove-Item -LiteralPath $snapshot -Force -ErrorAction SilentlyContinue
    }
}
