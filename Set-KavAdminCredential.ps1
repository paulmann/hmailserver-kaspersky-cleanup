#Requires -Version 7.2
<#
.SYNOPSIS
    Store a password as a machine-scope DPAPI blob so scheduled tasks can run unattended.

.DESCRIPTION
    Two credentials are used by the kit:
      * Kaspersky password protection (EXPORT/IMPORT only) - Kaspersky.CredentialFile;
      * hMailServer administrator (COM remediation) - hMailServer.CredentialFile.

    The blob is bound to the local machine (LocalMachine DPAPI scope), so a task running as SYSTEM
    can read it, and no password is stored in the repository or in a script.

.PARAMETER Target
    Kaspersky (default) or hMailServer.

.PARAMETER Password
    SecureString. When omitted, the plain value is read from the environment variable named by
    -EnvironmentVariable, which keeps the secret out of the command line.

.EXAMPLE
    .\Set-KavAdminCredential.ps1 -Target Kaspersky

.EXAMPLE
    $p = Read-Host -AsSecureString 'hMailServer Administrator'
    .\Set-KavAdminCredential.ps1 -Target hMailServer -Password $p
#>

[CmdletBinding()]
param(
    [ValidateSet('Kaspersky', 'hMailServer')]
    [string] $Target = 'Kaspersky',

    [securestring] $Password,

    [string] $EnvironmentVariable = 'HMAIL_KASPERSKY_SECRET',

    [string] $ConfigPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module -Name (Join-Path $PSScriptRoot 'HMailKaspersky.Kit.psm1') -Force

$config = Get-KitConfig -ConfigPath $ConfigPath
$credentialFile = switch ($Target) {
    'Kaspersky' { [string] (Get-KitValue -Config $config -Path 'Kaspersky.CredentialFile') }
    'hMailServer' { [string] (Get-KitValue -Config $config -Path 'hMailServer.CredentialFile') }
}
if ([string]::IsNullOrWhiteSpace($credentialFile)) { throw ('CredentialFile is not configured for {0}' -f $Target) }

$secret = $Password
if ($null -eq $secret) {
    $plain = [Environment]::GetEnvironmentVariable($EnvironmentVariable, 'Process')
    if ([string]::IsNullOrEmpty($plain)) {
        $secret = Read-Host -AsSecureString ('{0} password' -f $Target)
    }
    else {
        $secret = ConvertTo-SecureString -String $plain -AsPlainText -Force
    }
}

$result = Set-KitStoredCredential -CredentialFile $credentialFile -Password $secret
Write-Output ('credential written: {0} ({1} bytes); roundtrip={2}; target={3}' -f $result.CredentialFile, $result.Length, $result.RoundTrip, $Target)
exit 0
