#Requires -Version 7.2
<#
.SYNOPSIS
    Discover a working avp.com, publish its path, and (optionally) wait until it appears.

.DESCRIPTION
    A Kaspersky upgrade changes the product folder name (e.g. 21.26 -> 21.27). Scripts that are
    already running hold the old path; the scanner must not fail until the next manual fix. This
    script resolves a live build (each candidate is proven with HELP), stores it in the registry
    key configured as Kaspersky.RegistryKey, in the machine environment variable and in a JSON
    state file, then reports what it published.

    Run it from a scheduled task before the nightly job and right after product updates.

.PARAMETER WaitSeconds
    Retry for this long when no usable build is found: an upgrade may still be settling.

.PARAMETER Quiet
    Log only, do not write to the host output (used by scheduled tasks).

.EXAMPLE
    .\Update-KavCurrent.ps1 -Quiet
#>

[CmdletBinding()]
param(
    [string] $ConfigPath,
    [ValidateRange(0, 3600)] [int] $WaitSeconds = 60,
    [switch] $Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module -Name (Join-Path $PSScriptRoot 'HMailKaspersky.Kit.psm1') -Force

$config = Get-KitConfig -ConfigPath $ConfigPath
$deadline = (Get-Date).AddSeconds($WaitSeconds)

while ($true) {
    $published = Get-KitPublishedAvpPath -Config $config
    if ($published -and (Test-KitAvpUsable -AvpPath $published)) {
        Write-KitLog -Config $config -Component 'publish' -Quiet:$Quiet -Message ('published path is alive: {0}' -f $published)
        exit 0
    }

    $resolved = Resolve-KitAvpPath -Config $config
    if ($resolved) {
        $record = Publish-KitAvpPath -Config $config -AvpPath $resolved -Source 'resolved'
        Write-KitLog -Config $config -Component 'publish' -Quiet:$Quiet -Message ('published {0} (version {1})' -f $record.AvpPath, $record.Version)
        exit 0
    }

    if ((Get-Date) -ge $deadline) {
        Write-KitLog -Config $config -Component 'publish' -Level 'ERROR' -Quiet:$Quiet -Message ('no usable avp.com found under {0}; waited {1}s' -f (Get-KitValue -Config $config -Path 'Kaspersky.ProductRoot'), $WaitSeconds)
        exit 1
    }

    Start-Sleep -Seconds 5
}
