#Requires -Version 7.2
<#
.SYNOPSIS
    Export or import Kaspersky product settings through avp.com, using a stored credential.

.DESCRIPTION
    Only settings commands accept /login and /password. SCAN and UPDATE reject them: adding the
    parameters to a scan makes the console client answer `Unknown parameter '/login=...'` and
    perform no scan at all.

    Typical use: export the settings as a rollback point, edit the exclusions/trusted applications
    in the exported .cfg, import it, then export again to verify.

.PARAMETER Action
    Status - check that a credential and a live avp.com are available;
    Export - write the current product settings (default path under Kit.StateDirectory);
    Import - apply a settings file produced by Export.

.PARAMETER Path
    Settings file. Export appends `.cfg` if the console client does so.

.EXAMPLE
    .\Kav-Settings.ps1 -Action Export

.EXAMPLE
    .\Kav-Settings.ps1 -Action Import -Path C:\ProgramData\hMailKaspersky\state\settings-20261030.cfg
#>

[CmdletBinding()]
param(
    [ValidateSet('Status', 'Export', 'Import')]
    [string] $Action = 'Status',

    [string] $Path,

    [string] $ConfigPath,

    [ValidateRange(30, 1800)] [int] $TimeoutSeconds = 300,

    [switch] $Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module -Name (Join-Path $PSScriptRoot 'HMailKaspersky.Kit.psm1') -Force

$config = Get-KitConfig -ConfigPath $ConfigPath
$component = 'settings'
$avp = Resolve-KitAvpPath -Config $config -UsePublished
$credentialFile = [string] (Get-KitValue -Config $config -Path 'Kaspersky.CredentialFile')
$credential = if ($credentialFile) { Get-KitStoredCredential -CredentialFile $credentialFile -UserName ([string] (Get-KitValue -Config $config -Path 'Kaspersky.Login' -Default 'KLAdmin')) } else { $null }

Write-KitLog -Config $config -Component $component -Quiet:$Quiet -Message ('action={0}; avp={1}; credential={2}' -f $Action, $(if ($avp) { $avp } else { 'not found' }), $(if ($credential) { 'present' } else { 'missing' }))

switch ($Action) {
    'Status' {
        if (-not $avp) { exit 1 }
        if (-not $credential) {
            Write-KitLog -Config $config -Component $component -Level 'WARN' -Quiet:$Quiet -Message ('no stored credential; run Set-KavAdminCredential.ps1 (file: {0})' -f $credentialFile)
            exit 1
        }
        exit 0
    }

    'Export' {
        if ([string]::IsNullOrWhiteSpace($Path)) {
            $stateDirectory = [string] (Get-KitValue -Config $config -Path 'Kit.StateDirectory')
            if (-not (Test-Path -LiteralPath $stateDirectory)) { $null = New-Item -ItemType Directory -Force -Path $stateDirectory }
            $Path = Join-Path $stateDirectory ('settings-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        }

        $result = Invoke-KitAvpSettingsCommand -Config $config -Command EXPORT -Path $Path -AvpPath $avp -TimeoutSeconds $TimeoutSeconds
        $expected = $Path + '.cfg'
        Write-KitLog -Config $config -Component $component -Quiet:$Quiet -Message ('EXPORT exit={0}; {1:n1}s; file={2}' -f $result.ExitCode, $result.Elapsed.TotalSeconds, $expected)
        if ($result.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $expected)) {
            Write-KitLog -Config $config -Component $component -Level 'ERROR' -Quiet:$Quiet -Message (($result.StdOut -split "`r?`n" | Select-Object -First 3) -join ' | ')
            exit 1
        }
        Write-Output $expected
        exit 0
    }

    'Import' {
        if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
            Write-KitLog -Config $config -Component $component -Level 'ERROR' -Quiet:$Quiet -Message ('import requires an existing settings file: {0}' -f $Path)
            exit 1
        }
        $result = Invoke-KitAvpSettingsCommand -Config $config -Command IMPORT -Path $Path -AvpPath $avp -TimeoutSeconds $TimeoutSeconds
        Write-KitLog -Config $config -Component $component -Quiet:$Quiet -Message ('IMPORT exit={0}; {1:n1}s; file={2}' -f $result.ExitCode, $result.Elapsed.TotalSeconds, $Path)
        if ($result.ExitCode -ne 0) {
            Write-KitLog -Config $config -Component $component -Level 'ERROR' -Quiet:$Quiet -Message (($result.StdOut -split "`r?`n" | Select-Object -First 3) -join ' | ')
            exit 1
        }
        exit 0
    }
}
