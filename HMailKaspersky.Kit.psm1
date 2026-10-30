#Requires -Version 7.2
<#
.SYNOPSIS
    Shared configuration, logging, avp.com discovery and process helpers for the kit.

.DESCRIPTION
    One place for everything host-specific. Every script in the kit loads its settings through
    Get-KitConfig, so nothing needs editing after `git pull`.

    Configuration lookup order (first existing file wins):
      1. -ConfigPath parameter of the calling script (if it has one);
      2. $env:HMAIL_KASPERSKY_CONFIG;
      3. config.local.psd1 next to this module;
      4. config.example.psd1 next to this module (neutral defaults only).

    config.local.psd1 is listed in .gitignore: the toolkit can be updated from git without losing
    local settings, and secrets never enter the repository.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:KitDefaults = @{
    Kit       = @{ InstallDirectory = 'C:\ProgramData\hMailKaspersky\kit'; LogDirectory = 'C:\ProgramData\hMailKaspersky\logs'; StateDirectory = 'C:\ProgramData\hMailKaspersky\state' }
    hMailServer = @{ ServiceName = 'hMailServer'; DataDirectory = ''; TempDirectory = 'C:\Program Files (x86)\hMailServer\Temp'; AdminUser = 'Administrator'; CredentialFile = 'C:\ProgramData\hMailKaspersky\hmail.cred.machine.bin' }
    Kaspersky = @{ ProductRoot = 'C:\Program Files (x86)\Kaspersky Lab'; AvpFileName = 'avp.com'; Login = 'KLAdmin'; CredentialFile = 'C:\ProgramData\hMailKaspersky\kladmin.cred.machine.bin'; RegistryKey = 'SOFTWARE\hMailServerKav'; EnvironmentVariable = 'KAV_AVP_PATH' }
    Scanner   = @{ SnapshotDirectory = ''; ReportsDirectory = 'C:\ProgramData\hMailKaspersky\reports\realtime'; DetectionsDirectory = 'C:\ProgramData\hMailKaspersky\reports\realtime\detections'; TimeoutSeconds = 120; MaxSnapshotMb = 64; ExitCodeOnDetection = 2; KeepSnapshots = $false }
    Nightly   = @{ SinceDays = 2; BatchSize = 40; TimeoutMinutes = 20; UpdateDatabases = $true; QuarantineDirectory = 'C:\ProgramData\hMailKaspersky\quarantine'; ReportsDirectory = 'C:\ProgramData\hMailKaspersky\reports'; CleanupToolPath = ''; AutoRemediate = $false; DryRun = $false }
    Maintenance = @{ UpdateTime = '06:05'; RebootTimes = @('06:15', '06:40'); RebootDelaySeconds = 180; RebootOnPendingOnly = $true; RebootSkipWhileScanning = $true }
    Tasks     = @{ Nightly = 'hMailKasperskyNightly'; PathRefresh = 'hMailKasperskyPathRefresh'; Update = 'KasperskyUpdateWindow'; Reboot = 'MailServerRebootWindow' }
    Logging   = @{ Level = 'INFO'; RetentionDays = 30 }
}

$script:LevelOrder = @{ DEBUG = 0; INFO = 1; WARN = 2; ERROR = 3 }

function Get-KitConfigPath {
    <#
    .SYNOPSIS
        Resolve which configuration file will be used, without loading it.
    #>
    [CmdletBinding()]
    param([string] $ConfigPath)

    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        if (-not (Test-Path -LiteralPath $ConfigPath)) { throw ('Configuration file not found: {0}' -f $ConfigPath) }
        return (Resolve-Path -LiteralPath $ConfigPath).Path
    }

    $fromEnv = [Environment]::GetEnvironmentVariable('HMAIL_KASPERSKY_CONFIG', 'Process')
    if (-not [string]::IsNullOrWhiteSpace($fromEnv) -and (Test-Path -LiteralPath $fromEnv)) {
        return (Resolve-Path -LiteralPath $fromEnv).Path
    }

    $local = Join-Path -Path $PSScriptRoot -ChildPath 'config.local.psd1'
    if (Test-Path -LiteralPath $local) { return $local }

    $example = Join-Path -Path $PSScriptRoot -ChildPath 'config.example.psd1'
    if (Test-Path -LiteralPath $example) { return $example }

    throw 'No configuration file found: create config.local.psd1 (see config.example.psd1).'
}

function Merge-KitHashtable {
    param([hashtable] $Base, [hashtable] $Override)

    $result = @{}
    foreach ($key in $Base.Keys) { $result[$key] = $Base[$key] }

    foreach ($key in $Override.Keys) {
        $value = $Override[$key]
        if ($value -is [hashtable] -and $result[$key] -is [hashtable]) {
            $result[$key] = Merge-KitHashtable -Base $result[$key] -Override $value
        }
        else {
            $result[$key] = $value
        }
    }
    return $result
}

function Get-KitConfig {
    <#
    .SYNOPSIS
        Load the configuration file and merge it over the neutral defaults.

    .PARAMETER ConfigPath
        Explicit file. When omitted the standard lookup order is used.

    .OUTPUTS
        Hashtable with Kit, hMailServer, Kaspersky, Scanner, Nightly, Maintenance, Tasks, Logging.
    #>
    [CmdletBinding()]
    param([string] $ConfigPath)

    $path = Get-KitConfigPath -ConfigPath $ConfigPath
    $loaded = Import-PowerShellDataFile -LiteralPath $path
    if ($null -eq $loaded -or $loaded -isnot [hashtable]) {
        throw ('Configuration file must contain a hashtable: {0}' -f $path)
    }

    $merged = Merge-KitHashtable -Base $script:KitDefaults -Override $loaded
    $merged['ConfigPath'] = $path
    return $merged
}

function Get-KitValue {
    <#
    .SYNOPSIS
        Read a dotted path from the configuration, e.g. 'Kaspersky.ProductRoot'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Config,
        [Parameter(Mandatory)] [string] $Path,
        $Default = $null
    )

    $node = $Config
    foreach ($part in $Path.Split('.')) {
        if ($node -is [hashtable] -and $node.ContainsKey($part)) {
            $node = $node[$part]
            continue
        }
        return $Default
    }
    if ($null -eq $node) { return $Default }
    return $node
}

function Write-KitLog {
    <#
    .SYNOPSIS
        Append one line to the kit log and (optionally) to the host output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Config,
        [Parameter(Mandatory)] [string] $Message,
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')] [string] $Level = 'INFO',
        [string] $Component = 'kit',
        [string] $LogFile,
        [switch] $Quiet
    )

    $minLevel = [string] (Get-KitValue -Config $Config -Path 'Logging.Level' -Default 'INFO')
    if ($script:LevelOrder[$Level] -lt $script:LevelOrder[$minLevel]) { return }

    $line = '{0} [{1}] [{2}] {3}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'), $Level, $Component, $Message

    if (-not $LogFile) {
        $directory = [string] (Get-KitValue -Config $Config -Path 'Kit.LogDirectory' -Default 'C:\ProgramData\hMailKaspersky\logs')
        if (-not (Test-Path -LiteralPath $directory)) { $null = New-Item -ItemType Directory -Force -Path $directory }
        $LogFile = Join-Path $directory ('{0}-{1}.log' -f $Component, (Get-Date -Format 'yyyyMMdd'))
    }

    Add-Content -LiteralPath $LogFile -Value $line -Encoding utf8
    if (-not $Quiet) {
        if ($Level -eq 'ERROR') { Write-Error -Message $Message -ErrorAction Continue }
        else { Write-Information -MessageData $line -InformationAction Continue }
    }
    return $LogFile
}

function Invoke-KitProcess {
    <#
    .SYNOPSIS
        Run a console program with a timeout and capture its output.

    .OUTPUTS
        PSCustomObject: ExitCode, TimedOut, Elapsed, StdOut, StdErr, Arguments.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $FilePath,
        [string[]] $ArgumentList = @(),
        [int] $TimeoutSeconds = 120,
        [string] $WorkingDirectory
    )

    $stdout = [System.IO.Path]::GetTempFileName()
    $stderr = [System.IO.Path]::GetTempFileName()
    $watch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $startArgs = @{
            FilePath               = $FilePath
            ArgumentList           = $ArgumentList
            NoNewWindow            = $true
            PassThru               = $true
            RedirectStandardOutput = $stdout
            RedirectStandardError  = $stderr
        }
        if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) { $startArgs['WorkingDirectory'] = $WorkingDirectory }

        $process = Start-Process @startArgs
        $finished = $process.WaitForExit($TimeoutSeconds * 1000)
        if (-not $finished) { try { $process.Kill($true) } catch { } }
        $watch.Stop()

        $encoding = [System.Text.Encoding]::GetEncoding(866)
        $out = if (Test-Path -LiteralPath $stdout) { [System.IO.File]::ReadAllText($stdout, $encoding) } else { '' }
        $err = if (Test-Path -LiteralPath $stderr) { [System.IO.File]::ReadAllText($stderr, $encoding) } else { '' }

        return [pscustomobject]@{
            ExitCode  = if ($finished) { [int] $process.ExitCode } else { -1 }
            TimedOut  = (-not $finished)
            Elapsed   = $watch.Elapsed
            StdOut    = $out.Trim()
            StdErr    = $err.Trim()
            Arguments = $ArgumentList
        }
    }
    finally {
        Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
}

function Test-KitAvpUsable {
    <#
    .SYNOPSIS
        Prove that an avp.com answers HELP (a stale product folder may accept calls and answer nothing).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $AvpPath,
        [int] $TimeoutSeconds = 60
    )

    if (-not (Test-Path -LiteralPath $AvpPath)) { return $false }

    $result = Invoke-KitProcess -FilePath $AvpPath -ArgumentList @('HELP') -TimeoutSeconds $TimeoutSeconds -WorkingDirectory (Split-Path -Parent $AvpPath)
    if ($result.TimedOut) { return $false }
    return ($result.StdOut -match 'Usage|SCAN|UPDATE')
}

function Get-KitRegistryPath {
    param([hashtable] $Config)
    $key = [string] (Get-KitValue -Config $Config -Path 'Kaspersky.RegistryKey' -Default 'SOFTWARE\hMailServerKav')
    return ('HKLM:\{0}' -f $key)
}

function Get-KitPublishedAvpPath {
    <#
    .SYNOPSIS
        Read the published avp.com path from HKLM (or $null).
    #>
    [CmdletBinding()]
    param([hashtable] $Config)

    try {
        $key = Get-KitRegistryPath -Config $Config
        if (-not (Test-Path $key)) { return $null }
        $value = (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).AvpPath
        if ([string]::IsNullOrWhiteSpace([string] $value)) { return $null }
        return [string] $value
    }
    catch { return $null }
}

function Resolve-KitAvpPath {
    <#
    .SYNOPSIS
        Find a working avp.com: published path first, then the product root, then HELP verification.

    .PARAMETER UsePublished
        Prefer the path published in the registry when it is still usable.
    #>
    [CmdletBinding()]
    param(
        [hashtable] $Config,
        [switch] $UsePublished,
        [switch] $SkipPublished
    )

    if ($null -eq $Config) { $Config = Get-KitConfig }

    if ($UsePublished -and -not $SkipPublished) {
        $published = Get-KitPublishedAvpPath -Config $Config
        if ($published -and (Test-KitAvpUsable -AvpPath $published)) { return $published }
    }

    $root = [string] (Get-KitValue -Config $Config -Path 'Kaspersky.ProductRoot' -Default 'C:\Program Files (x86)\Kaspersky Lab')
    $file = [string] (Get-KitValue -Config $Config -Path 'Kaspersky.AvpFileName' -Default 'avp.com')

    if (-not (Test-Path -LiteralPath $root)) { return $null }

    $candidates = @(
        Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
            Sort-Object -Property Name -Descending |
            ForEach-Object { Join-Path $_.FullName $file }
    )
    foreach ($candidate in $candidates) {
        if (Test-KitAvpUsable -AvpPath $candidate) { return $candidate }
    }
    return $null
}

function Publish-KitAvpPath {
    <#
    .SYNOPSIS
        Publish a working avp.com path to HKLM, the machine environment and a JSON file.

    .DESCRIPTION
        Lets every script (including the hMailServer scanner running as SYSTEM) find the same build
        after a product upgrade changes the folder name. The JSON copy is for humans and tooling.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Config,
        [Parameter(Mandatory)] [string] $AvpPath,
        [string] $Source = 'discovery'
    )

    if (-not (Test-KitAvpUsable -AvpPath $AvpPath)) {
        throw ('Refusing to publish an unusable avp.com: {0}' -f $AvpPath)
    }

    $version = (Get-Item -LiteralPath $AvpPath).VersionInfo.ProductVersion
    if ([string]::IsNullOrWhiteSpace([string] $version)) { $version = 'unknown' }

    $key = Get-KitRegistryPath -Config $Config
    if (-not (Test-Path $key)) { $null = New-Item -Path $key -Force }

    $record = [ordered]@{
        AvpPath   = $AvpPath
        AvpDir    = Split-Path -Parent $AvpPath
        Version   = $version
        Source    = $Source
        Alive     = 1
        CheckedAt = (Get-Date).ToString('o')
        Host      = $env:COMPUTERNAME
        Schema    = 1
    }
    foreach ($name in $record.Keys) {
        New-ItemProperty -LiteralPath $key -Name $name -Value $record[$name] -PropertyType String -Force | Out-Null
    }

    $envName = [string] (Get-KitValue -Config $Config -Path 'Kaspersky.EnvironmentVariable' -Default 'KAV_AVP_PATH')
    if (-not [string]::IsNullOrWhiteSpace($envName)) {
        [Environment]::SetEnvironmentVariable($envName, $AvpPath, 'Machine')
    }

    $stateDirectory = [string] (Get-KitValue -Config $Config -Path 'Kit.StateDirectory' -Default 'C:\ProgramData\hMailKaspersky\state')
    if (-not (Test-Path -LiteralPath $stateDirectory)) { $null = New-Item -ItemType Directory -Force -Path $stateDirectory }
    $jsonPath = Join-Path $stateDirectory 'kav-current.json'
    $record | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $jsonPath -Encoding utf8

    return [pscustomobject]$record
}

function Get-KitStoredCredential {
    <#
    .SYNOPSIS
        Read a machine-scope DPAPI credential blob into a PSCustomObject (User/Password) or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $CredentialFile,
        [string] $UserName = ''
    )

    if (-not (Test-Path -LiteralPath $CredentialFile)) { return $null }

    try {
        $blob = [System.IO.File]::ReadAllBytes($CredentialFile)
        $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $blob, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        $text = [System.Text.Encoding]::UTF8.GetString($plain)
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }

        return [pscustomobject]@{
            UserName = $UserName
            Password = (ConvertTo-SecureString -String $text -AsPlainText -Force)
        }
    }
    catch {
        Write-Verbose ('Credential blob unreadable: {0}' -f $_.Exception.Message)
        return $null
    }
}

function Set-KitStoredCredential {
    <#
    .SYNOPSIS
        Store a password as a machine-scope DPAPI blob for unattended use by scheduled tasks.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $CredentialFile,
        [Parameter(Mandatory)] [securestring] $Password
    )

    $plain = [System.Net.NetworkCredential]::new('', $Password).Password
    if ([string]::IsNullOrEmpty($plain)) { throw 'Empty password.' }

    $directory = Split-Path -Parent $CredentialFile
    if ($directory -and -not (Test-Path -LiteralPath $directory)) { $null = New-Item -ItemType Directory -Force -Path $directory }

    $blob = [System.Security.Cryptography.ProtectedData]::Protect(
        [System.Text.Encoding]::UTF8.GetBytes($plain),
        $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine)

    [System.IO.File]::WriteAllBytes($CredentialFile, $blob)

    $back = [System.Security.Cryptography.ProtectedData]::Unprotect(
        [System.IO.File]::ReadAllBytes($CredentialFile), $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    if ([System.Text.Encoding]::UTF8.GetString($back) -ne $plain) {
        throw 'Credential round-trip failed; the blob is not readable on this machine.'
    }

    return [pscustomobject]@{ CredentialFile = $CredentialFile; Length = $blob.Length; RoundTrip = $true }
}

function Invoke-KitAvpSettingsCommand {
    <#
    .SYNOPSIS
        Run avp.com EXPORT/IMPORT with the stored password-protection credential.

    .DESCRIPTION
        Only settings commands accept /login and /password; SCAN and UPDATE must not receive them
        (the console client rejects the parameters and performs no scan).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Config,
        [Parameter(Mandatory)] [ValidateSet('EXPORT', 'IMPORT')] [string] $Command,
        [Parameter(Mandatory)] [string] $Path,
        [string] $AvpPath,
        [int] $TimeoutSeconds = 300
    )

    if ([string]::IsNullOrWhiteSpace($AvpPath)) {
        $AvpPath = Resolve-KitAvpPath -Config $Config -UsePublished
        if (-not $AvpPath) { throw 'No usable avp.com found.' }
    }

    $credentialFile = [string] (Get-KitValue -Config $Config -Path 'Kaspersky.CredentialFile')
    $login = [string] (Get-KitValue -Config $Config -Path 'Kaspersky.Login' -Default 'KLAdmin')
    $credential = Get-KitStoredCredential -CredentialFile $credentialFile -UserName $login
    if ($null -eq $credential) {
        throw ('No stored credential for settings commands: {0} (use Set-KitStoredCredential).' -f $credentialFile)
    }

    $plain = [System.Net.NetworkCredential]::new('', $credential.Password).Password
    $arguments = @($Command, $Path, ('/login={0}' -f $login), ('/password={0}' -f $plain))

    return Invoke-KitProcess -FilePath $AvpPath -ArgumentList $arguments -TimeoutSeconds $TimeoutSeconds -WorkingDirectory (Split-Path -Parent $AvpPath)
}

Export-ModuleMember -Function @(
    'Get-KitConfigPath',
    'Get-KitConfig',
    'Get-KitValue',
    'Write-KitLog',
    'Invoke-KitProcess',
    'Test-KitAvpUsable',
    'Get-KitPublishedAvpPath',
    'Resolve-KitAvpPath',
    'Publish-KitAvpPath',
    'Get-KitStoredCredential',
    'Set-KitStoredCredential',
    'Invoke-KitAvpSettingsCommand'
)
