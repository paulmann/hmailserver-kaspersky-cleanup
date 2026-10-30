#Requires -Version 7.2
<#
.SYNOPSIS
    Refresh Kaspersky bases and modules inside the allowed maintenance window.

.DESCRIPTION
    A product update may require a restart. Running the update at a fixed early-morning time keeps
    such restarts inside the maintenance window instead of the working day. No credentials are
    accepted by UPDATE: /login and /password belong to EXPORT/IMPORT only.

.EXAMPLE
    .\Invoke-KavUpdate.ps1 -Quiet
#>

[CmdletBinding()]
param(
    [string] $ConfigPath,
    [ValidateRange(60, 3600)] [int] $TimeoutSeconds = 900,
    [switch] $Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module -Name (Join-Path $PSScriptRoot 'HMailKaspersky.Kit.psm1') -Force

$config = Get-KitConfig -ConfigPath $ConfigPath
$avp = Resolve-KitAvpPath -Config $config -UsePublished
if (-not $avp) {
    Write-KitLog -Config $config -Component 'update-window' -Level 'ERROR' -Quiet:$Quiet -Message 'no usable avp.com found; update skipped'
    exit 1
}

$result = Invoke-KitProcess -FilePath $avp -ArgumentList @('UPDATE') -TimeoutSeconds $TimeoutSeconds -WorkingDirectory (Split-Path -Parent $avp)
Write-KitLog -Config $config -Component 'update-window' -Quiet:$Quiet -Message ('UPDATE exit={0}; {1:n1}s; avp={2}' -f $result.ExitCode, $result.Elapsed.TotalSeconds, $avp)

if ($result.ExitCode -ne 0) {
    Write-KitLog -Config $config -Component 'update-window' -Level 'WARN' -Quiet:$Quiet -Message (($result.StdOut -split "`r?`n" | Select-Object -First 3) -join ' | ')
    exit 1
}
exit 0
