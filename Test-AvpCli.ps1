#Requires -Version 7.2
<#
.SYNOPSIS
    Full behavioural test harness for the Kaspersky console client (avp.com), with a
    discovery-only mode that other PowerShell 7 scripts can consume.

.DESCRIPTION
    Builds a disposable laboratory corpus based on the EICAR anti-malware test string,
    then drives avp.com through a complete matrix of invocation forms and records what
    actually happens: exit codes, runtime, the first line of output, whether a report file
    was produced, whether the report is parseable, and whether the test object survived.

    Locating avp.com is treated as a first-class problem. A machine can carry several
    product folders at once - a pending or failed upgrade leaves the previous version in
    place - and only the build whose resident process is running actually answers commands.
    The other one accepts the binary invocation and returns exit code 3 with no output for
    every command, which produces a matrix full of identical meaningless failures.

    Candidates are collected from four sources and ranked by trustworthiness:
      0. the explicit -AvpPath value;
      1. the directory of the running avp.exe or avpui.exe process;
      2. the image path of the Kaspersky services;
      3. directory values under HKLM\SOFTWARE\[WOW6432Node\]KasperskyLab\AVP*\environment
         and InstallLocation from the Windows uninstall keys;
      4. a scan of the Kaspersky Lab folders under both Program Files trees.

    Each candidate is probed for liveness: a bare invocation must return 0 and HELP must
    either return 0 or print something. The first live candidate wins, so an explicit path
    that points at a dead build degrades to automatic discovery with a warning instead of
    wasting a full run.

    With -ResolvePathOnly the script performs discovery only and emits a single object on
    the success stream, so other scripts can reuse the resolution logic:

        $avp = .\Test-AvpCli.ps1 -ResolvePathOnly -Quiet
        & $avp.Path SCAN 'C:\mail\spool' /i0

    Real-time protection deletes EICAR objects while the matrix runs. The harness never
    asks you to disable protection or to create exclusions: it rebuilds the corpus for
    every runner and records a case whose target vanished as "corpus lost" rather than
    pretending the missing file produced a scan result.

    Password protection differs between product lines. Kaspersky Endpoint Security accepts
    /login=<user name> together with /password=<password>. The consumer line accepts
    /password only, has no account name, and only a small set of commands accepts it at
    all, so credentials are appended solely to commands documented as protected.

.PARAMETER LabRoot
    Root directory for the laboratory corpus and all artefacts. Unused with -ResolvePathOnly.

.PARAMETER AvpPath
    Preferred path to avp.com. Accepts a file or a product directory. Validated and probed;
    discovery continues automatically when the path is missing, is not avp.com, or belongs
    to a build that answers nothing.

.PARAMETER KasperskyRoot
    Additional directory that contains Kaspersky product folders.

.PARAMETER KasperskyLogin
    User account for Password protection. KLAdmin is the built-in Endpoint Security
    account. Ignored on the consumer line and when -AuthStyle is PasswordOnly or None.

.PARAMETER KasperskyPassword
    Password protecting product settings, when configured.

.PARAMETER KasperskyCredential
    Convenience alternative to -KasperskyLogin plus -KasperskyPassword.

.PARAMETER AuthStyle
    Auto, LoginAndPassword, PasswordOnly or None. Auto follows the detected product line.

.PARAMETER CredentialScope
    Protected (default) appends credentials only to protected commands. All appends them
    everywhere, which unprotected commands normally reject. Diagnostic use only.

.PARAMETER Runner
    Cmd (cmd.exe with redirection), Direct (.NET pipes) or Both.

.PARAMETER TimeoutMinutes
    Timeout for a single avp.com call.

.PARAMETER IncludeDestructive
    Also test /i1, /i2 and /i8 actions against throwaway copies of the corpus.

.PARAMETER SkipEicar
    Build only clean control files. Use this for a pure syntax matrix that real-time
    protection cannot disturb.

.PARAMETER SkipAuthProbe
    Do not run the authentication group.

.PARAMETER SkipLivenessProbe
    Accept the highest ranked candidate without probing it.

.PARAMETER ResolvePathOnly
    Resolve avp.com, emit the result on the success stream and exit without running any
    test case. Nothing is written to disk except a temporary probe file that is removed
    before returning.

.PARAMETER PathFormat
    Shape of the -ResolvePathOnly output.
      Object - a PSCustomObject with Path, Directory, Version, ProductLine, Source and the
               probe details (default).
      Path   - the full path to avp.com as a bare string.
      Json   - the same object serialised, for caching or cross-process handover.

.PARAMETER Quiet
    Suppress the information and warning streams. The success stream is unaffected, so
    -ResolvePathOnly still returns its value.

.EXAMPLE
    .\Test-AvpCli.ps1

.EXAMPLE
    .\Test-AvpCli.ps1 -SkipEicar -Runner Both

.EXAMPLE
    $avp = .\Test-AvpCli.ps1 -ResolvePathOnly -Quiet
    & $avp.Path SCAN 'C:\mail\spool' /i0

.EXAMPLE
    $path = .\Test-AvpCli.ps1 -ResolvePathOnly -PathFormat Path -Quiet

.EXAMPLE
    .\Test-AvpCli.ps1 -ResolvePathOnly -PathFormat Json -Quiet | Set-Content .\avp-location.json

.EXAMPLE
    .\Test-AvpCli.ps1 -KasperskyCredential (Get-Credential KLAdmin) -AuthStyle LoginAndPassword

.NOTES
    Run elevated in an interactive session with the resident Kaspersky process active.
    Password protection locks the account after repeated failed sign-in attempts, so the
    harness never probes invalid credentials: it compares "with credentials" against
    "without". The password never reaches a process command line, the log, the CSV, the
    JSON or the console; in the Cmd runner it travels through a process environment
    variable and is substituted by cmd.exe.

    -ResolvePathOnly throws when no candidate answers, so callers should wrap it in
    try/catch. The exception message lists every path that was checked with its exit codes.
#>
[CmdletBinding()]
param(
    [string] $LabRoot,

    [string] $AvpPath,

    [string] $KasperskyRoot = 'C:\Program Files (x86)\Kaspersky Lab',

    [string] $KasperskyLogin,

    [securestring] $KasperskyPassword,

    [pscredential] $KasperskyCredential,

    [ValidateSet('Auto', 'LoginAndPassword', 'PasswordOnly', 'None')]
    [string] $AuthStyle = 'Auto',

    [ValidateSet('Protected', 'All')]
    [string] $CredentialScope = 'Protected',

    [ValidateSet('Cmd', 'Direct', 'Both')]
    [string] $Runner = 'Both',

    [ValidateRange(1, 240)]
    [int] $TimeoutMinutes = 10,

    [switch] $IncludeDestructive,

    [switch] $SkipEicar,

    [switch] $SkipAuthProbe,

    [switch] $SkipLivenessProbe,

    [Alias('WhereIsAvp')]
    [switch] $ResolvePathOnly,

    [ValidateSet('Object', 'Path', 'Json')]
    [string] $PathFormat = 'Object',

    [switch] $Quiet
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

if ($Quiet) {
    $InformationPreference = 'SilentlyContinue'
    $WarningPreference = 'SilentlyContinue'
}

if (-not $IsWindows) {
    throw 'This harness targets the Windows build of avp.com.'
}

try {
    [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance)
}
catch {
    Write-Debug ('code page provider not registered: {0}' -f $_.Exception.Message)
}

$script:LogFile = $null
$script:Result = [System.Collections.Generic.List[object]]::new()
$script:CaseNumber = 0
$script:Secret = $null

$script:ProtectedCommand = @(
    'ACTIVATE'
    'ADDKEY'
    'DISABLE'
    'EXIT'
    'EXPORT'
    'IMPORT'
    'LICENSE'
    'MDRLICENSE'
    'PAUSE'
    'RESTORE'
    'RESUME'
    'SELFPROTECTION'
    'STOP'
)

$script:ScanningGroup = @('target', 'container', 'list', 'report', 'depth', 'filter', 'action')

#region Infrastructure

function Remove-Secret {
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string] $Text,

        [AllowNull()]
        [AllowEmptyString()]
        [string] $Secret
    )

    if ([string]::IsNullOrEmpty($Text)) {
        return $Text
    }

    $value = if ([string]::IsNullOrWhiteSpace($Secret)) { $script:Secret } else { $Secret }
    $clean = $Text

    if (-not [string]::IsNullOrWhiteSpace($value)) {
        $clean = $clean.Replace($value, '***')
    }

    return [regex]::Replace($clean, '(?i)(/password=)\S+', '$1***')
}

function Write-Line {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Message,

        [ValidateSet('INFO', 'WARN')]
        [string] $Level = 'INFO'
    )

    $safeMessage = Remove-Secret -Text $Message
    $line = '[{0:HH:mm:ss.fff}] [{1}] {2}' -f (Get-Date), $Level, $safeMessage

    if ($Level -eq 'WARN') {
        Write-Warning -Message $safeMessage
    }
    else {
        Write-Information -MessageData $line
    }

    if ($script:LogFile) {
        try {
            Add-Content -LiteralPath $script:LogFile -Value $line -Encoding utf8
        }
        catch {
            Write-Debug ('log line not written: {0}' -f $_.Exception.Message)
        }
    }
}

function Test-VolumeAvailable {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $root = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($Path))

    if ([string]::IsNullOrWhiteSpace($root)) {
        return $false
    }

    if ($root.StartsWith('\\')) {
        return $true
    }

    return (Test-Path -LiteralPath $root -PathType Container)
}

function New-LabDirectory {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not (Test-VolumeAvailable -Path $Path)) {
        $available = @(Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name | ForEach-Object -Process { '{0}:\' -f $_ })
        throw ('The lab volume does not exist: {0}. Available drives: {1}' -f $Path, ($available -join ', '))
    }

    return (New-Item -ItemType Directory -Force -Path $Path).FullName
}

function Get-CodePageEncoding {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Ansi', 'Oem', 'Unicode', 'Utf8')]
        [string] $Name
    )

    switch ($Name) {
        'Unicode' {
            return [System.Text.Encoding]::Unicode
        }
        'Utf8' {
            return [System.Text.UTF8Encoding]::new($false)
        }
        'Oem' {
            try {
                return [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
            }
            catch {
                return [System.Text.Encoding]::Default
            }
        }
        default {
            try {
                return [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage)
            }
            catch {
                return [System.Text.Encoding]::Default
            }
        }
    }
}

function Get-DecodedText {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return ''
    }

    $bytes = [System.IO.File]::ReadAllBytes($Path)

    if ($bytes.Length -eq 0) {
        return ''
    }

    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        return [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
    }

    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        return [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
    }

    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        return [System.Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2)
    }

    $sample = [Math]::Min(512, $bytes.Length)
    $zero = 0

    for ($index = 0; $index -lt $sample; $index++) {
        if ($bytes[$index] -eq 0) {
            $zero++
        }
    }

    if ($sample -ge 4 -and $zero -gt ($sample / 5)) {
        return [System.Text.Encoding]::Unicode.GetString($bytes)
    }

    return (Get-CodePageEncoding -Name 'Oem').GetString($bytes)
}

function Get-FirstLine {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Text,

        [int] $MaxLength = 160
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $line = @($Text -split '\r\n|\n|\r' | ForEach-Object -Process { $_.Trim() } | Where-Object -FilterScript { $_ -ne '' } | Select-Object -First 1)

    if ($line.Count -eq 0) {
        return ''
    }

    $value = [string] $line[0]

    if ($value.Length -gt $MaxLength) {
        return $value.Substring(0, $MaxLength)
    }

    return $value
}

function ConvertTo-WindowsArgument {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }

    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function Get-ExitDescription {
    param(
        [AllowNull()]
        [System.Nullable[int]] $Code
    )

    if ($null -eq $Code) {
        return 'not executed'
    }

    switch ([int] $Code) {
        0 { return 'success' }
        1 { return 'invalid parameter value' }
        2 { return 'unknown error' }
        3 { return 'task completion error' }
        4 { return 'task cancelled' }
        101 { return 'all dangerous objects processed' }
        102 { return 'dangerous objects detected' }
        -10 { return 'undocumented -10, observed with the /@: scope list form' }
        -1 { return 'harness could not start the process' }
        default { return 'undocumented code' }
    }
}

function Resolve-AvpCredential {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Login,

        [AllowNull()]
        [securestring] $Password,

        [AllowNull()]
        [pscredential] $Credential,

        [Parameter(Mandatory)]
        [ValidateSet('Auto', 'LoginAndPassword', 'PasswordOnly', 'None')]
        [string] $Style,

        [Parameter(Mandatory)]
        [ValidateSet('Endpoint', 'Consumer')]
        [string] $ProductLine
    )

    $effectiveLogin = $Login
    $effectiveSecret = $null
    $effectiveStyle = $Style

    if ($null -ne $Credential) {
        if (-not [string]::IsNullOrWhiteSpace($Credential.UserName)) {
            if (-not [string]::IsNullOrWhiteSpace($effectiveLogin) -and $effectiveLogin -ne $Credential.UserName) {
                Write-Line -Message ('KasperskyLogin ({0}) is overridden by the credential user name ({1}).' -f $effectiveLogin, $Credential.UserName) -Level 'WARN'
            }

            $effectiveLogin = $Credential.UserName
        }

        $effectiveSecret = $Credential.GetNetworkCredential().Password
    }
    elseif ($null -ne $Password) {
        $effectiveSecret = [System.Net.NetworkCredential]::new('', $Password).Password
    }

    if ($effectiveStyle -eq 'Auto') {
        if ($ProductLine -eq 'Consumer') {
            $effectiveStyle = 'PasswordOnly'
            Write-Line -Message 'Consumer product line detected: the /login switch does not exist there, so only /password will be sent.'
        }
        elseif (-not [string]::IsNullOrWhiteSpace($effectiveLogin)) {
            $effectiveStyle = 'LoginAndPassword'
        }
        else {
            $effectiveStyle = 'PasswordOnly'
        }
    }

    if ($effectiveStyle -eq 'None') {
        if (-not [string]::IsNullOrWhiteSpace($effectiveSecret) -or -not [string]::IsNullOrWhiteSpace($effectiveLogin)) {
            Write-Line -Message 'AuthStyle is None: the supplied credentials are ignored.' -Level 'WARN'
        }

        return [pscustomobject]@{ Login = $null; Secret = $null; Supplied = $false; Style = 'None'; Requested = $Style }
    }

    if ($effectiveStyle -eq 'PasswordOnly' -and -not [string]::IsNullOrWhiteSpace($effectiveLogin)) {
        Write-Line -Message ('The login {0} will not be sent: this product line takes /password without an account name.' -f $effectiveLogin) -Level 'WARN'
        $effectiveLogin = $null
    }

    if ($effectiveStyle -eq 'LoginAndPassword') {
        if ([string]::IsNullOrWhiteSpace($effectiveSecret)) {
            throw 'AuthStyle LoginAndPassword requires a password. Pass -KasperskyCredential or -KasperskyPassword.'
        }

        if ([string]::IsNullOrWhiteSpace($effectiveLogin)) {
            $effectiveLogin = 'KLAdmin'
            Write-Line -Message 'No login was supplied; falling back to the built-in KLAdmin account.' -Level 'WARN'
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($effectiveLogin) -and [string]::IsNullOrWhiteSpace($effectiveSecret)) {
        Write-Line -Message 'A login without a password is not a usable combination; /login will not be sent.' -Level 'WARN'
        $effectiveLogin = $null
    }

    $supplied = -not [string]::IsNullOrWhiteSpace($effectiveSecret)

    if ($supplied) {
        if ([string]::IsNullOrWhiteSpace($effectiveLogin)) {
            Write-Line -Message 'credentials: /password only, no account name'
        }
        else {
            Write-Line -Message ('credentials: /login={0} plus /password (masked in every artefact)' -f $effectiveLogin)
        }
    }
    else {
        Write-Line -Message 'credentials: none supplied; protected commands are expected to fail'
    }

    return [pscustomobject]@{
        Login     = $effectiveLogin
        Secret    = $effectiveSecret
        Supplied  = $supplied
        Style     = $effectiveStyle
        Requested = $Style
    }
}

function Test-CommandNeedsCredential {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $ArgumentList,

        [Parameter(Mandatory)]
        [ValidateSet('Protected', 'All')]
        [string] $Scope
    )

    if ($Scope -eq 'All') {
        return $true
    }

    if (@($ArgumentList).Count -eq 0) {
        return $false
    }

    $command = ([string] $ArgumentList[0]).Trim().ToUpperInvariant()
    return ($script:ProtectedCommand -contains $command)
}

#endregion

#region avp.com discovery

function Get-ProcessImagePath {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Process] $Process
    )

    try {
        if (-not [string]::IsNullOrWhiteSpace($Process.Path)) {
            return $Process.Path
        }
    }
    catch {
        Write-Debug ('managed path unavailable for pid {0}: {1}' -f $Process.Id, $_.Exception.Message)
    }

    try {
        $query = 'SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {0}' -f $Process.Id
        $wmiPath = @(Get-CimInstance -Query $query -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty ExecutablePath)

        if ($wmiPath.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($wmiPath[0])) {
            return [string] $wmiPath[0]
        }
    }
    catch {
        Write-Debug ('CIM path unavailable for pid {0}: {1}' -f $Process.Id, $_.Exception.Message)
    }

    return $null
}

function Get-ResidentDirectory {
    $directory = [System.Collections.Generic.List[string]]::new()

    foreach ($name in @('avp', 'avpui', 'ksde', 'ksdeui')) {
        foreach ($process in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
            $path = Get-ProcessImagePath -Process $process

            if ([string]::IsNullOrWhiteSpace($path)) {
                continue
            }

            $folder = Split-Path -Path $path -Parent

            if (-not [string]::IsNullOrWhiteSpace($folder) -and -not $directory.Contains($folder)) {
                $directory.Add($folder)
            }
        }
    }

    return @($directory)
}

function Get-ServiceDirectory {
    $directory = [System.Collections.Generic.List[string]]::new()

    try {
        $serviceList = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
            Where-Object -FilterScript { $_.Name -like 'AVP*' -or $_.PathName -like '*Kaspersky*' })
    }
    catch {
        Write-Debug ('service enumeration failed: {0}' -f $_.Exception.Message)
        return @()
    }

    foreach ($service in $serviceList) {
        $pathName = [string] $service.PathName

        if ([string]::IsNullOrWhiteSpace($pathName)) {
            continue
        }

        $match = [regex]::Match($pathName, '^\s*"?(?<image>[a-zA-Z]:\\[^"]+?\.exe)"?')

        if (-not $match.Success) {
            continue
        }

        $folder = Split-Path -Path $match.Groups['image'].Value -Parent

        if (-not [string]::IsNullOrWhiteSpace($folder) -and -not $directory.Contains($folder)) {
            $directory.Add($folder)
        }
    }

    return @($directory)
}

function Get-RegistryDirectory {
    $directory = [System.Collections.Generic.List[string]]::new()

    $productRoot = @(
        'HKLM:\SOFTWARE\WOW6432Node\KasperskyLab'
        'HKLM:\SOFTWARE\KasperskyLab'
    )

    foreach ($root in $productRoot) {
        if (-not (Test-Path -LiteralPath $root)) {
            continue
        }

        foreach ($productKey in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            foreach ($subKeyName in @('environment', 'Environment', '')) {
                $keyPath = if ([string]::IsNullOrWhiteSpace($subKeyName)) { $productKey.PSPath } else { Join-Path -Path $productKey.PSPath -ChildPath $subKeyName }

                if (-not (Test-Path -LiteralPath $keyPath)) {
                    continue
                }

                $property = $null

                try {
                    $property = Get-ItemProperty -LiteralPath $keyPath -ErrorAction SilentlyContinue
                }
                catch {
                    Write-Debug ('registry key not read: {0}' -f $keyPath)
                }

                if ($null -eq $property) {
                    continue
                }

                foreach ($member in @($property.PSObject.Properties | Where-Object -FilterScript { $_.MemberType -eq 'NoteProperty' })) {
                    $value = $member.Value

                    if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) {
                        continue
                    }

                    $expanded = [System.Environment]::ExpandEnvironmentVariables($value).Trim().Trim('"')

                    if ($expanded -notmatch '^[a-zA-Z]:\\') {
                        continue
                    }

                    $folder = if (Test-Path -LiteralPath $expanded -PathType Container) {
                        $expanded
                    }
                    elseif (Test-Path -LiteralPath $expanded -PathType Leaf) {
                        Split-Path -Path $expanded -Parent
                    }
                    else {
                        $null
                    }

                    if (-not [string]::IsNullOrWhiteSpace($folder) -and -not $directory.Contains($folder)) {
                        $directory.Add($folder)
                    }
                }
            }
        }
    }

    $uninstallRoot = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    foreach ($root in $uninstallRoot) {
        if (-not (Test-Path -LiteralPath $root)) {
            continue
        }

        foreach ($entry in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $property = $null

            try {
                $property = Get-ItemProperty -LiteralPath $entry.PSPath -ErrorAction SilentlyContinue
            }
            catch {
                Write-Debug ('uninstall key not read: {0}' -f $entry.PSPath)
            }

            if ($null -eq $property) {
                continue
            }

            $publisher = if ($property.PSObject.Properties.Name -contains 'Publisher') { [string] $property.Publisher } else { '' }
            $displayName = if ($property.PSObject.Properties.Name -contains 'DisplayName') { [string] $property.DisplayName } else { '' }

            if ($publisher -notmatch '(?i)kaspersky' -and $displayName -notmatch '(?i)kaspersky') {
                continue
            }

            if ($property.PSObject.Properties.Name -notcontains 'InstallLocation') {
                continue
            }

            $location = [string] $property.InstallLocation

            if ([string]::IsNullOrWhiteSpace($location)) {
                continue
            }

            $location = $location.Trim().Trim('"').TrimEnd('\')

            if ((Test-Path -LiteralPath $location -PathType Container) -and -not $directory.Contains($location)) {
                $directory.Add($location)
            }
        }
    }

    return @($directory)
}

function Get-FolderScanDirectory {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $ExtraRoot
    )

    $directory = [System.Collections.Generic.List[string]]::new()
    $baseList = @($ExtraRoot, "${env:ProgramFiles(x86)}\Kaspersky Lab", "$env:ProgramFiles\Kaspersky Lab")

    foreach ($base in $baseList) {
        if ([string]::IsNullOrWhiteSpace($base) -or -not (Test-Path -LiteralPath $base -PathType Container)) {
            continue
        }

        $ordered = @(@(Get-Item -LiteralPath $base) + @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue) |
            Sort-Object -Property CreationTime -Descending)

        foreach ($candidate in $ordered) {
            if (-not $directory.Contains($candidate.FullName)) {
                $directory.Add($candidate.FullName)
            }
        }
    }

    return @($directory)
}

function Get-AvpCandidate {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Explicit,

        [AllowNull()]
        [AllowEmptyString()]
        [string] $ExtraRoot
    )

    $candidate = [System.Collections.Generic.List[object]]::new()

    $addCandidate = {
        param($Path, $Source, $Rank)

        if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            return
        }

        $full = (Get-Item -LiteralPath $Path).FullName
        $existing = @($candidate | Where-Object -FilterScript { $_.Path -eq $full })

        if ($existing.Count -gt 0) {
            if ($Rank -lt $existing[0].Rank) {
                $existing[0].Rank = $Rank
                $existing[0].Source = $Source
            }

            return
        }

        $candidate.Add([pscustomobject]@{
            Path   = $full
            Source = $Source
            Rank   = $Rank
        })
    }

    if (-not [string]::IsNullOrWhiteSpace($Explicit)) {
        $explicitPath = $Explicit

        if (Test-Path -LiteralPath $explicitPath -PathType Container) {
            $explicitPath = Join-Path -Path $explicitPath -ChildPath 'avp.com'
        }

        if (Test-Path -LiteralPath $explicitPath -PathType Leaf) {
            & $addCandidate $explicitPath 'explicit -AvpPath' 0
        }
        else {
            Write-Line -Message ('-AvpPath does not point to an existing avp.com: {0}. Falling back to automatic discovery.' -f $Explicit) -Level 'WARN'
        }
    }

    foreach ($folder in (Get-ResidentDirectory)) {
        & $addCandidate (Join-Path -Path $folder -ChildPath 'avp.com') ('resident process in {0}' -f $folder) 1
    }

    foreach ($folder in (Get-ServiceDirectory)) {
        & $addCandidate (Join-Path -Path $folder -ChildPath 'avp.com') ('service image in {0}' -f $folder) 2
    }

    foreach ($folder in (Get-RegistryDirectory)) {
        & $addCandidate (Join-Path -Path $folder -ChildPath 'avp.com') ('registry value pointing at {0}' -f $folder) 3
    }

    foreach ($folder in (Get-FolderScanDirectory -ExtraRoot $ExtraRoot)) {
        & $addCandidate (Join-Path -Path $folder -ChildPath 'avp.com') ('folder scan of {0}' -f $folder) 4
    }

    return @($candidate | Sort-Object -Property Rank, Path)
}

function Invoke-Avp {
    param(
        [Parameter(Mandatory)]
        [string] $Avp,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $ArgumentList,

        [Parameter(Mandatory)]
        [ValidateSet('Cmd', 'Direct')]
        [string] $RunnerMode,

        [Parameter(Mandatory)]
        [string] $StdOutFile,

        [ValidateRange(1, 240)]
        [int] $Timeout = 10,

        [AllowNull()]
        [AllowEmptyString()]
        [string] $Secret,

        [AllowNull()]
        [AllowEmptyString()]
        [string] $Login
    )

    $workingDirectory = Split-Path -Path $Avp -Parent
    $effectiveArgument = [System.Collections.Generic.List[string]]::new()

    foreach ($argument in @($ArgumentList)) {
        $effectiveArgument.Add($argument)
    }

    $credentialSent = $false

    if (-not [string]::IsNullOrWhiteSpace($Secret)) {
        if (-not [string]::IsNullOrWhiteSpace($Login)) {
            $effectiveArgument.Add(('/login={0}' -f $Login))
        }

        $effectiveArgument.Add(('/password={0}' -f $Secret))
        $credentialSent = $true
    }

    if (Test-Path -LiteralPath $StdOutFile) {
        Remove-Item -LiteralPath $StdOutFile -Force
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.WorkingDirectory = $workingDirectory
    $passwordValue = $null
    $loginValue = $null

    if ($RunnerMode -eq 'Cmd') {
        $shellArgument = foreach ($argument in $effectiveArgument) {
            if ($argument -match '^(?i)/password=(.*)$') {
                $passwordValue = $Matches[1]
                '/password=%KASPERSKY_CLI_SECRET%'
            }
            elseif ($argument -match '^(?i)/login=(.*)$') {
                $loginValue = $Matches[1]
                '/login=%KASPERSKY_CLI_LOGIN%'
            }
            else {
                $argument
            }
        }

        $quoted = @(@($shellArgument) | ForEach-Object -Process { ConvertTo-WindowsArgument -Value $_ })
        $inner = 'cd /d {0} && {1} {2} > {3} 2>&1' -f (ConvertTo-WindowsArgument -Value $workingDirectory), (ConvertTo-WindowsArgument -Value $Avp), ($quoted -join ' '), (ConvertTo-WindowsArgument -Value $StdOutFile)
        $startInfo.FileName = Join-Path -Path $env:SystemRoot -ChildPath 'System32\cmd.exe'
        $startInfo.Arguments = '/d /s /v:off /c "{0}"' -f $inner

        if ($null -ne $passwordValue) {
            $startInfo.Environment['KASPERSKY_CLI_SECRET'] = $passwordValue
        }

        if ($null -ne $loginValue) {
            $startInfo.Environment['KASPERSKY_CLI_LOGIN'] = $loginValue
        }
    }
    else {
        $startInfo.FileName = $Avp
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true

        foreach ($argument in $effectiveArgument) {
            $null = $startInfo.ArgumentList.Add($argument)
        }
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $exitCode = -1
    $outputText = ''
    $note = ''

    try {
        if (-not $process.Start()) {
            throw 'the process did not start'
        }

        $outTask = $null
        $errTask = $null

        if ($RunnerMode -eq 'Direct') {
            $outTask = $process.StandardOutput.ReadToEndAsync()
            $errTask = $process.StandardError.ReadToEndAsync()
        }

        if (-not $process.WaitForExit($Timeout * 60 * 1000)) {
            try {
                $process.Kill($true)
            }
            catch {
                Write-Debug ('process tree not killed: {0}' -f $_.Exception.Message)
            }

            $note = 'timeout after {0} minute(s)' -f $Timeout
        }

        $process.WaitForExit()
        $exitCode = $process.ExitCode

        if ($RunnerMode -eq 'Direct') {
            $outputText = $outTask.GetAwaiter().GetResult() + $errTask.GetAwaiter().GetResult()
            [System.IO.File]::WriteAllText($StdOutFile, (Remove-Secret -Text $outputText -Secret $Secret), [System.Text.UTF8Encoding]::new($false))
        }
        else {
            $outputText = Get-DecodedText -Path $StdOutFile
        }
    }
    catch {
        $note = $_.Exception.Message
    }
    finally {
        $stopwatch.Stop()
        $process.Dispose()

        if ($startInfo.Environment.ContainsKey('KASPERSKY_CLI_SECRET')) {
            $null = $startInfo.Environment.Remove('KASPERSKY_CLI_SECRET')
        }

        if ($startInfo.Environment.ContainsKey('KASPERSKY_CLI_LOGIN')) {
            $null = $startInfo.Environment.Remove('KASPERSKY_CLI_LOGIN')
        }

        $passwordValue = $null
        $loginValue = $null
    }

    $masked = @(@($effectiveArgument) | ForEach-Object -Process {
        if ($_ -match '^(?i)/password=') { '/password=***' } else { $_ }
    })

    return [pscustomobject]@{
        ExitCode       = [int] $exitCode
        StdOut         = (Remove-Secret -Text $outputText -Secret $Secret)
        CommandLine    = 'avp.com ' + ($masked -join ' ')
        Elapsed        = $stopwatch.Elapsed
        Note           = (Remove-Secret -Text $note -Secret $Secret)
        StdOutFile     = $StdOutFile
        CredentialSent = $credentialSent
    }
}

function Test-AvpAlive {
    param(
        [Parameter(Mandatory)]
        [string] $Avp,

        [Parameter(Mandatory)]
        [string] $OutputDirectory
    )

    $probeFile = Join-Path -Path $OutputDirectory -ChildPath 'preflight.out'
    $bare = Invoke-Avp -Avp $Avp -ArgumentList @() -RunnerMode 'Direct' -StdOutFile $probeFile -Timeout 2
    $help = Invoke-Avp -Avp $Avp -ArgumentList @('HELP') -RunnerMode 'Direct' -StdOutFile $probeFile -Timeout 2
    $helpBytes = if ($null -eq $help.StdOut) { 0 } else { $help.StdOut.Length }
    $alive = ($help.ExitCode -eq 0) -or ($helpBytes -gt 0)

    return [pscustomobject]@{
        Path      = $Avp
        Alive     = $alive
        BareExit  = $bare.ExitCode
        HelpExit  = $help.ExitCode
        HelpBytes = $helpBytes
        FirstLine = Get-FirstLine -Text $help.StdOut
    }
}

function Resolve-Avp {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Explicit,

        [AllowNull()]
        [AllowEmptyString()]
        [string] $ExtraRoot,

        [Parameter(Mandatory)]
        [string] $OutputDirectory,

        [switch] $SkipProbe
    )

    $candidate = Get-AvpCandidate -Explicit $Explicit -ExtraRoot $ExtraRoot

    if ($candidate.Count -eq 0) {
        throw 'avp.com was not found through the resident process, the services, the registry or a folder scan. Pass -AvpPath explicitly.'
    }

    foreach ($entry in $candidate) {
        Write-Line -Message ('candidate rank {0}: {1} [{2}]' -f $entry.Rank, $entry.Path, $entry.Source)
    }

    if ($SkipProbe) {
        Write-Line -Message ('liveness probe skipped; taking the highest ranked candidate: {0}' -f $candidate[0].Path) -Level 'WARN'
        return [pscustomobject]@{ Path = $candidate[0].Path; Source = $candidate[0].Source; Probe = $null }
    }

    $probeResult = [System.Collections.Generic.List[object]]::new()

    foreach ($entry in $candidate) {
        $probe = Test-AvpAlive -Avp $entry.Path -OutputDirectory $OutputDirectory
        $probeResult.Add($probe)
        Write-Line -Message ('probe {0}: alive={1}; bare exit={2}; HELP exit={3}; HELP bytes={4}' -f $entry.Path, $probe.Alive, $probe.BareExit, $probe.HelpExit, $probe.HelpBytes)

        if ($probe.Alive) {
            if ($entry.Rank -gt 0 -and -not [string]::IsNullOrWhiteSpace($Explicit)) {
                Write-Line -Message ('The explicit path did not answer; using the live build found by {0}.' -f $entry.Source) -Level 'WARN'
            }

            return [pscustomobject]@{ Path = $entry.Path; Source = $entry.Source; Probe = $probe }
        }

        Write-Line -Message ('{0} answers nothing and is skipped; a stale product folder from an interrupted upgrade behaves exactly like this.' -f $entry.Path) -Level 'WARN'
    }

    $detail = @($probeResult | ForEach-Object -Process { '{0} (bare={1}, help={2}, bytes={3})' -f $_.Path, $_.BareExit, $_.HelpExit, $_.HelpBytes })
    throw ('No avp.com candidate answered a HELP call. Checked: {0}' -f ($detail -join '; '))
}

function Get-ProductLine {
    param(
        [Parameter(Mandatory)]
        [string] $Avp
    )

    $item = Get-Item -LiteralPath $Avp
    $productName = ''

    try {
        $productName = [string] $item.VersionInfo.ProductName
    }
    catch {
        Write-Debug ('product name not read: {0}' -f $_.Exception.Message)
    }

    $probe = '{0} {1}' -f $productName, (Split-Path -Path $Avp -Parent)

    if ($probe -match '(?i)endpoint\s+security|security\s+for\s+windows\s+server|security\s+10\b|security\s+11\b|security\s+12\b') {
        return 'Endpoint'
    }

    return 'Consumer'
}

function Get-AvpLocation {
    <#
        Discovery-only entry point. Returns a single object describing the live avp.com,
        suitable for consumption by other PowerShell 7 scripts.
    #>
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Explicit,

        [AllowNull()]
        [AllowEmptyString()]
        [string] $ExtraRoot,

        [switch] $SkipProbe
    )

    $probeRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('avp-resolve-{0}' -f ([guid]::NewGuid().ToString('n')))
    $null = New-Item -ItemType Directory -Force -Path $probeRoot

    try {
        $resolved = Resolve-Avp -Explicit $Explicit -ExtraRoot $ExtraRoot -OutputDirectory $probeRoot -SkipProbe:$SkipProbe
        $item = Get-Item -LiteralPath $resolved.Path
        $productLine = Get-ProductLine -Avp $resolved.Path

        $productName = ''

        try {
            $productName = [string] $item.VersionInfo.ProductName
        }
        catch {
            Write-Debug ('product name not read: {0}' -f $_.Exception.Message)
        }

        return [pscustomobject]@{
            Path             = $resolved.Path
            Directory        = $item.DirectoryName
            FileName         = $item.Name
            Version          = [string] $item.VersionInfo.FileVersion
            ProductName      = $productName
            ProductLine      = $productLine
            SupportsLogin    = ($productLine -eq 'Endpoint')
            Source           = $resolved.Source
            Probed           = (-not $SkipProbe)
            Alive            = if ($null -eq $resolved.Probe) { $null } else { $resolved.Probe.Alive }
            BareExit         = if ($null -eq $resolved.Probe) { $null } else { $resolved.Probe.BareExit }
            HelpExit         = if ($null -eq $resolved.Probe) { $null } else { $resolved.Probe.HelpExit }
            HelpBytes        = if ($null -eq $resolved.Probe) { $null } else { $resolved.Probe.HelpBytes }
            LastWriteTime    = $item.LastWriteTime
            ComputerName     = $env:COMPUTERNAME
            ResolvedAt       = (Get-Date)
        }
    }
    finally {
        Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

#endregion

#region Discovery-only mode

if ($ResolvePathOnly) {
    $location = Get-AvpLocation -Explicit $AvpPath -ExtraRoot $KasperskyRoot -SkipProbe:$SkipLivenessProbe

    switch ($PathFormat) {
        'Path' {
            $location.Path
        }
        'Json' {
            $location | ConvertTo-Json -Depth 4
        }
        default {
            $location
        }
    }

    return
}

#endregion

#region Corpus

function Get-EicarString {
    $part = @('X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR', 'STANDARD', 'ANTIVIRUS', 'TEST', 'FILE!$H+H*')
    return ($part[0] + '-' + $part[1] + '-' + $part[2] + '-' + $part[3] + '-' + $part[4])
}

function New-TestCorpus {
    param(
        [Parameter(Mandatory)]
        [string] $Root,

        [switch] $WithoutEicar
    )

    $corpus = New-LabDirectory -Path (Join-Path -Path $Root -ChildPath 'corpus')
    $cyrillic = New-LabDirectory -Path (Join-Path -Path $corpus -ChildPath ([char]0x043f + [char]0x043e + [char]0x0447 + [char]0x0442 + [char]0x0430))
    $item = [System.Collections.Generic.List[object]]::new()
    $ascii = [System.Text.Encoding]::ASCII

    $cleanEml = Join-Path -Path $corpus -ChildPath 'clean-control.eml'
    $cleanBody = @(
        'From: control@example.test'
        'To: postmaster@example.test'
        'Subject: clean control message'
        'MIME-Version: 1.0'
        'Content-Type: text/plain; charset=us-ascii'
        ''
        'This message contains no test signature.'
    )

    [System.IO.File]::WriteAllLines($cleanEml, [string[]] $cleanBody, $ascii)
    $item.Add([pscustomobject]@{ Name = 'clean-eml'; Path = $cleanEml; Kind = 'control'; ExpectDetection = $false })

    if ($WithoutEicar) {
        $cleanText = Join-Path -Path $cyrillic -ChildPath 'clean-cyrillic-path.txt'
        [System.IO.File]::WriteAllText($cleanText, 'clean control file in a Cyrillic directory', $ascii)
        $item.Add([pscustomobject]@{ Name = 'clean-cyrillic-path'; Path = $cleanText; Kind = 'control in a Cyrillic directory'; ExpectDetection = $false })

        Write-Line -Message 'SkipEicar was supplied: only clean control objects were created, so real-time protection cannot disturb the matrix.' -Level 'WARN'

        foreach ($entry in $item) {
            $entry | Add-Member -NotePropertyName 'CreatedOnDisk' -NotePropertyValue (Test-Path -LiteralPath $entry.Path -PathType Leaf)
        }

        return [pscustomobject]@{
            Root     = $corpus
            Cyrillic = $cyrillic
            Item     = @($item)
        }
    }

    $eicar = Get-EicarString
    $encoded = [Convert]::ToBase64String($ascii.GetBytes($eicar))

    $plain = Join-Path -Path $corpus -ChildPath 'eicar-plain.com'
    [System.IO.File]::WriteAllText($plain, $eicar, $ascii)
    $item.Add([pscustomobject]@{ Name = 'eicar-plain'; Path = $plain; Kind = 'plain file'; ExpectDetection = $true })

    $renamed = Join-Path -Path $cyrillic -ChildPath 'eicar-cyrillic-path.txt'
    [System.IO.File]::WriteAllText($renamed, $eicar, $ascii)
    $item.Add([pscustomobject]@{ Name = 'eicar-cyrillic-path'; Path = $renamed; Kind = 'plain file in a Cyrillic directory'; ExpectDetection = $true })

    $emlBody = @(
        'From: purchase@example.test'
        'To: postmaster@example.test'
        'Subject: Official Purchase Order 14000083968'
        'MIME-Version: 1.0'
        'Content-Type: multipart/mixed; boundary="lab-boundary"'
        ''
        '--lab-boundary'
        'Content-Type: text/plain; charset=us-ascii'
        ''
        'Attachment carries the EICAR test signature.'
        ''
        '--lab-boundary'
        'Content-Type: application/octet-stream; name="Scanned_RFQ.js"'
        'Content-Transfer-Encoding: base64'
        'Content-Disposition: attachment; filename="Scanned_RFQ.js"'
        ''
        $encoded
        ''
        '--lab-boundary--'
    )

    $eml = Join-Path -Path $corpus -ChildPath 'eicar-attachment.eml'
    [System.IO.File]::WriteAllLines($eml, [string[]] $emlBody, $ascii)
    $item.Add([pscustomobject]@{ Name = 'eicar-eml-attachment'; Path = $eml; Kind = 'mail message with a base64 attachment'; ExpectDetection = $true })

    $mboxBody = [System.Collections.Generic.List[string]]::new()
    $mboxBody.Add('From MAILER-DAEMON Sun Jul 05 21:46:32 2026')
    $mboxBody.Add('From: first@example.test')
    $mboxBody.Add('Subject: clean message inside the container')
    $mboxBody.Add('')
    $mboxBody.Add('Nothing to see here.')
    $mboxBody.Add('')
    $mboxBody.Add('From MAILER-DAEMON Sun Jul 05 21:47:11 2026')

    foreach ($line in $emlBody) {
        $mboxBody.Add($line)
    }

    $mboxBody.Add('')
    $mboxBody.Add('From MAILER-DAEMON Sun Jul 05 21:48:02 2026')
    $mboxBody.Add('From: third@example.test')
    $mboxBody.Add('Subject: another clean message')
    $mboxBody.Add('')
    $mboxBody.Add('Trailing clean content keeps the container mixed.')

    $mbox = Join-Path -Path $corpus -ChildPath 'INBOX'
    [System.IO.File]::WriteAllLines($mbox, [string[]] $mboxBody, $ascii)
    $item.Add([pscustomobject]@{ Name = 'eicar-mbox-container'; Path = $mbox; Kind = 'mbox folder file: detectable but not curable in place'; ExpectDetection = $true })

    $zipSource = New-LabDirectory -Path (Join-Path -Path $Root -ChildPath 'ziptemp')
    $zipEntry = Join-Path -Path $zipSource -ChildPath 'eicar.com'
    [System.IO.File]::WriteAllText($zipEntry, $eicar, $ascii)
    $zip = Join-Path -Path $corpus -ChildPath 'eicar-archive.zip'

    try {
        Compress-Archive -LiteralPath $zipEntry -DestinationPath $zip -Force
        $item.Add([pscustomobject]@{ Name = 'eicar-zip'; Path = $zip; Kind = 'zip archive'; ExpectDetection = $true })
    }
    catch {
        Write-Line -Message ('zip corpus not created: {0}' -f $_.Exception.Message) -Level 'WARN'
    }
    finally {
        Remove-Item -LiteralPath $zipSource -Recurse -Force -ErrorAction SilentlyContinue
    }

    $lost = 0

    foreach ($entry in $item) {
        $exists = Test-Path -LiteralPath $entry.Path -PathType Leaf
        $entry | Add-Member -NotePropertyName 'CreatedOnDisk' -NotePropertyValue $exists

        if (-not $exists) {
            $lost++
            Write-Line -Message ('{0} was removed by real-time protection immediately after creation; that is a valid observation.' -f $entry.Name) -Level 'WARN'
        }
    }

    if ($lost -gt 0) {
        Write-Line -Message ('{0} corpus object(s) did not survive creation. Rerun with -SkipEicar for a syntax-only matrix that protection cannot disturb.' -f $lost) -Level 'WARN'
    }

    return [pscustomobject]@{
        Root     = $corpus
        Cyrillic = $cyrillic
        Item     = @($item)
    }
}

function Get-CorpusPath {
    param(
        [Parameter(Mandatory)]
        [object] $Corpus,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $match = @($Corpus.Item | Where-Object -FilterScript { $_.Name -eq $Name })

    if ($match.Count -eq 0) {
        return $null
    }

    return [string] $match[0].Path
}

function New-ScopeList {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $Path,

        [Parameter(Mandatory)]
        [string] $File,

        [Parameter(Mandatory)]
        [ValidateSet('Ansi', 'Oem', 'Unicode', 'Utf8')]
        [string] $Encoding
    )

    [System.IO.File]::WriteAllLines($File, [string[]] @($Path), (Get-CodePageEncoding -Name $Encoding))
    return $File
}

#endregion

#region Test cases

function Add-SkippedCase {
    param(
        [Parameter(Mandatory)]
        [string] $CaseId,

        [Parameter(Mandatory)]
        [string] $Group,

        [Parameter(Mandatory)]
        [string] $Description,

        [Parameter(Mandatory)]
        [string] $RunnerMode,

        [Parameter(Mandatory)]
        [string] $Reason
    )

    $entry = [pscustomobject]@{
        Case            = $CaseId
        Group           = $Group
        Description     = $Description
        Runner          = $RunnerMode
        Authenticated   = $false
        Login           = $null
        CommandLine     = ''
        ExitCode        = $null
        ExitMeaning     = 'not executed'
        Succeeded       = $false
        ElapsedMs       = 0
        FirstLine       = ''
        StdOutLines     = 0
        ReportRequested = $false
        ReportCreated   = $false
        ReportBytes     = 0
        DetectionMarker = $false
        AuthMarker      = $false
        VerdictCount    = 0
        WatchBefore     = $false
        WatchAfter      = $false
        Note            = $Reason
    }

    $script:Result.Add($entry)
    Write-Line -Message ('{0} [{1}/{2}] skipped: {3}' -f $CaseId, $Group, $RunnerMode, $Reason) -Level 'WARN'
    return $entry
}

function Add-TestCase {
    param(
        [Parameter(Mandatory)]
        [string] $Avp,

        [Parameter(Mandatory)]
        [string] $Group,

        [Parameter(Mandatory)]
        [string] $Description,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $ArgumentList,

        [Parameter(Mandatory)]
        [ValidateSet('Cmd', 'Direct')]
        [string] $RunnerMode,

        [Parameter(Mandatory)]
        [string] $OutputDirectory,

        [AllowNull()]
        [AllowEmptyString()]
        [string] $ReportFile,

        [AllowNull()]
        [AllowEmptyString()]
        [string] $WatchPath,

        [AllowNull()]
        [AllowEmptyString()]
        [string] $Secret,

        [AllowNull()]
        [AllowEmptyString()]
        [string] $Login,

        [ValidateSet('Protected', 'All')]
        [string] $CredentialScope = 'Protected',

        [switch] $NoCredential,

        [int] $Timeout = 10
    )

    $script:CaseNumber++
    $caseId = 'case-{0:d3}' -f $script:CaseNumber

    if (-not [string]::IsNullOrWhiteSpace($WatchPath) -and -not (Test-Path -LiteralPath $WatchPath -PathType Leaf)) {
        return (Add-SkippedCase -CaseId $caseId -Group $Group -Description $Description -RunnerMode $RunnerMode -Reason ('the target was removed by real-time protection before the call: {0}' -f $WatchPath))
    }

    $stdOutFile = Join-Path -Path $OutputDirectory -ChildPath ('{0}.out' -f $caseId)
    $watchBefore = if (-not [string]::IsNullOrWhiteSpace($WatchPath)) { Test-Path -LiteralPath $WatchPath -PathType Leaf } else { $false }

    $wantsCredential = -not $NoCredential -and (Test-CommandNeedsCredential -ArgumentList $ArgumentList -Scope $CredentialScope)
    $effectiveSecret = if ($wantsCredential) { $Secret } else { $null }
    $effectiveLogin = if ($wantsCredential) { $Login } else { $null }

    $invocation = Invoke-Avp -Avp $Avp -ArgumentList $ArgumentList -RunnerMode $RunnerMode -StdOutFile $stdOutFile -Timeout $Timeout -Secret $effectiveSecret -Login $effectiveLogin
    $reportExists = $false
    $reportBytes = 0
    $reportText = ''

    if (-not [string]::IsNullOrWhiteSpace($ReportFile)) {
        $reportExists = Test-Path -LiteralPath $ReportFile -PathType Leaf

        if ($reportExists) {
            $reportBytes = (Get-Item -LiteralPath $ReportFile).Length
            $reportText = Get-DecodedText -Path $ReportFile
        }
    }

    $combined = $invocation.StdOut + [System.Environment]::NewLine + $reportText
    $verdictHit = [regex]::Matches($combined, '(?i)\bEICAR[\w\-\.]*')
    $scanned = (-not [string]::IsNullOrWhiteSpace($WatchPath)) -or ($script:ScanningGroup -contains $Group)
    $detectionMarker = [bool] ($scanned -and $verdictHit.Count -gt 0)
    $authMarker = [bool] ($combined -match '(?i)(not\s+authoriz|access\s+denied|wrong\s+password|invalid\s+password|\u0434\u043e\u0441\u0442\u0443\u043f\s+\u0437\u0430\u043f\u0440\u0435\u0449|\u043d\u0435\u0432\u0435\u0440\u043d\u044b\u0439\s+\u043f\u0430\u0440\u043e\u043b)')
    $watchAfter = if (-not [string]::IsNullOrWhiteSpace($WatchPath)) { Test-Path -LiteralPath $WatchPath -PathType Leaf } else { $false }

    $entry = [pscustomobject]@{
        Case            = $caseId
        Group           = $Group
        Description     = $Description
        Runner          = $RunnerMode
        Authenticated   = [bool] $invocation.CredentialSent
        Login           = $effectiveLogin
        CommandLine     = $invocation.CommandLine
        ExitCode        = [System.Nullable[int]] $invocation.ExitCode
        ExitMeaning     = Get-ExitDescription -Code $invocation.ExitCode
        Succeeded       = ($invocation.ExitCode -in 0, 101, 102)
        ElapsedMs       = [int] $invocation.Elapsed.TotalMilliseconds
        FirstLine       = Get-FirstLine -Text $invocation.StdOut
        StdOutLines     = @($invocation.StdOut -split '\r\n|\n|\r' | Where-Object -FilterScript { $_ -ne '' }).Count
        ReportRequested = (-not [string]::IsNullOrWhiteSpace($ReportFile))
        ReportCreated   = $reportExists
        ReportBytes     = $reportBytes
        DetectionMarker = $detectionMarker
        AuthMarker      = $authMarker
        VerdictCount    = $verdictHit.Count
        WatchBefore     = $watchBefore
        WatchAfter      = $watchAfter
        Note            = $invocation.Note
    }

    $script:Result.Add($entry)
    Write-Line -Message ('{0} [{1}/{2}] auth={3} exit={4} ({5}); report={6}; verdicts={7}; {8}' -f $caseId, $Group, $RunnerMode, $entry.Authenticated, $entry.ExitCode, $entry.ExitMeaning, $entry.ReportCreated, $entry.VerdictCount, $Description)
    return $entry
}

#endregion

#region Main

$started = Get-Date
$stamp = $started.ToString('yyyyMMdd-HHmmss')

if ([string]::IsNullOrWhiteSpace($LabRoot)) {
    $systemDrive = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
    $LabRoot = Join-Path -Path $systemDrive -ChildPath ('avlab\{0}' -f $stamp)
}

$labRootFull = New-LabDirectory -Path $LabRoot
$outputDirectory = New-LabDirectory -Path (Join-Path -Path $labRootFull -ChildPath 'output')
$script:LogFile = Join-Path -Path $outputDirectory -ChildPath 'harness.log'

try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    $elevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    $sessionId = (Get-Process -Id $PID).SessionId
    Write-Line -Message ('harness start; pwsh={0}; identity={1}; elevated={2}; session={3}' -f $PSVersionTable.PSVersion, $identity.Name, $elevated, $sessionId)
    Write-Line -Message ('lab root: {0}' -f $labRootFull)

    if (-not $elevated) {
        Write-Line -Message 'The session is not elevated; avp.com task results will not be representative.' -Level 'WARN'
    }

    foreach ($name in @('avp', 'avpui', 'ksde', 'ksdeui')) {
        $processList = @(Get-Process -Name $name -ErrorAction SilentlyContinue)

        if ($processList.Count -eq 0) {
            continue
        }

        $sessions = @($processList | Select-Object -ExpandProperty SessionId | Sort-Object -Unique)
        $folders = @($processList | ForEach-Object -Process { Get-ProcessImagePath -Process $_ } | Where-Object -FilterScript { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object -Process { Split-Path -Path $_ -Parent } | Sort-Object -Unique)
        Write-Line -Message ('process {0}: {1} instance(s), session(s) {2}, folder(s) {3}' -f $name, $processList.Count, ($sessions -join ','), ($folders -join ' | '))

        if ($folders.Count -gt 1) {
            Write-Line -Message ('{0} runs from more than one product folder, which indicates an interrupted upgrade. Resolve that before trusting any result.' -f $name) -Level 'WARN'
        }
    }

    if (@(Get-Process -Name 'avp' -ErrorAction SilentlyContinue).Count -eq 0) {
        Write-Line -Message 'The resident process avp.exe is not running; every task is expected to fail.' -Level 'WARN'
    }

    $resolved = Resolve-Avp -Explicit $AvpPath -ExtraRoot $KasperskyRoot -OutputDirectory $outputDirectory -SkipProbe:$SkipLivenessProbe
    $avp = $resolved.Path
    Write-Line -Message ('avp.com selected: {0} [{1}]' -f $avp, $resolved.Source)
    $product = Get-Item -LiteralPath $avp
    Write-Line -Message ('avp.com version {0}; modified {1:yyyy-MM-dd}' -f $product.VersionInfo.FileVersion, $product.LastWriteTime)

    $productLine = Get-ProductLine -Avp $avp
    Write-Line -Message ('product line: {0}' -f $productLine)

    $credential = Resolve-AvpCredential -Login $KasperskyLogin -Password $KasperskyPassword -Credential $KasperskyCredential -Style $AuthStyle -ProductLine $productLine
    $secret = $credential.Secret
    $login = $credential.Login
    $script:Secret = $secret
    $loginLabel = if ([string]::IsNullOrWhiteSpace($login)) { 'none (password-only form)' } else { $login }

    if ($CredentialScope -eq 'All') {
        Write-Line -Message 'CredentialScope is All: credentials are appended to every call, which unprotected commands normally reject.' -Level 'WARN'
    }
    else {
        Write-Line -Message ('credential scope: protected commands only ({0})' -f (($script:ProtectedCommand | Sort-Object) -join ', '))
    }

    $runnerList = if ($Runner -eq 'Both') { @('Cmd', 'Direct') } else { @($Runner) }

    foreach ($runnerMode in $runnerList) {
        $runnerRoot = New-LabDirectory -Path (Join-Path -Path $labRootFull -ChildPath $runnerMode.ToLowerInvariant())
        $corpus = New-TestCorpus -Root $runnerRoot -WithoutEicar:$SkipEicar
        $surviving = @($corpus.Item | Where-Object -FilterScript { $_.CreatedOnDisk })
        Write-Line -Message ('[{0}] corpus objects: {1} created, {2} survived; root: {3}' -f $runnerMode, @($corpus.Item).Count, $surviving.Count, $corpus.Root)

        $emlPath = Get-CorpusPath -Corpus $corpus -Name 'eicar-eml-attachment'
        $mboxPath = Get-CorpusPath -Corpus $corpus -Name 'eicar-mbox-container'
        $plainPath = Get-CorpusPath -Corpus $corpus -Name 'eicar-plain'
        $allPath = [string[]] @($corpus.Item | Select-Object -ExpandProperty Path)

        $common = @{
            Avp             = $avp
            RunnerMode      = $runnerMode
            OutputDirectory = $outputDirectory
            Secret          = $secret
            Login           = $login
            CredentialScope = $CredentialScope
            Timeout         = $TimeoutMinutes
        }

        Add-TestCase @common -Group 'help' -Description 'general help output' -ArgumentList @('HELP') | Out-Null
        Add-TestCase @common -Group 'help' -Description 'help for the SCAN command' -ArgumentList @('HELP', 'SCAN') | Out-Null
        Add-TestCase @common -Group 'state' -Description 'product status' -ArgumentList @('STATUS') | Out-Null
        Add-TestCase @common -Group 'state' -Description 'component statistics' -ArgumentList @('STATISTICS') | Out-Null
        Add-TestCase @common -Group 'error' -Description 'unknown command, expected invalid parameter' -ArgumentList @('NOSUCHCOMMAND') | Out-Null
        Add-TestCase @common -Group 'error' -Description 'scan of a non-existent path' -ArgumentList @('SCAN', (Join-Path -Path $labRootFull -ChildPath 'no-such-directory'), '/i0') | Out-Null

        Add-TestCase @common -Group 'target' -Description 'directory target, report only' -ArgumentList @('SCAN', $corpus.Root, '/i0') | Out-Null
        Add-TestCase @common -Group 'target' -Description 'directory target without an action switch' -ArgumentList @('SCAN', $corpus.Root) | Out-Null
        Add-TestCase @common -Group 'target' -Description 'Cyrillic directory target' -ArgumentList @('SCAN', $corpus.Cyrillic, '/i0') | Out-Null

        if (-not [string]::IsNullOrWhiteSpace($plainPath)) {
            Add-TestCase @common -Group 'target' -Description 'single plain EICAR file' -ArgumentList @('SCAN', $plainPath, '/i0') -WatchPath $plainPath | Out-Null
        }

        if (-not [string]::IsNullOrWhiteSpace($emlPath)) {
            Add-TestCase @common -Group 'container' -Description 'single .eml with base64 attachment' -ArgumentList @('SCAN', $emlPath, '/i0') -WatchPath $emlPath | Out-Null
        }

        if (-not [string]::IsNullOrWhiteSpace($mboxPath)) {
            Add-TestCase @common -Group 'container' -Description 'mbox folder file, detectable but not curable' -ArgumentList @('SCAN', $mboxPath, '/i0') -WatchPath $mboxPath | Out-Null
        }

        foreach ($encoding in @('Ansi', 'Oem', 'Unicode', 'Utf8')) {
            $listFile = New-ScopeList -Path $allPath -File (Join-Path -Path $outputDirectory -ChildPath ('scope-{0}-{1}.lst' -f $runnerMode.ToLowerInvariant(), $encoding.ToLowerInvariant())) -Encoding $encoding
            Add-TestCase @common -Group 'list' -Description ('scope list in {0}' -f $encoding) -ArgumentList @('SCAN', ('/@:{0}' -f $listFile), '/i0') | Out-Null
        }

        $emptyList = New-ScopeList -Path @() -File (Join-Path -Path $outputDirectory -ChildPath ('scope-empty-{0}.lst' -f $runnerMode.ToLowerInvariant())) -Encoding 'Ansi'
        Add-TestCase @common -Group 'list' -Description 'empty scope list' -ArgumentList @('SCAN', ('/@:{0}' -f $emptyList), '/i0') | Out-Null

        foreach ($reportOption in @('RA', 'R')) {
            $reportFile = Join-Path -Path $outputDirectory -ChildPath ('report-{0}-{1}.txt' -f $runnerMode.ToLowerInvariant(), $reportOption.ToLowerInvariant())
            Add-TestCase @common -Group 'report' -Description ('directory scan with /{0}' -f $reportOption) -ArgumentList @('SCAN', $corpus.Root, '/i0', ('/{0}:{1}' -f $reportOption, $reportFile)) -ReportFile $reportFile | Out-Null
        }

        foreach ($switch in @('/fa', '/fe', '/fi')) {
            Add-TestCase @common -Group 'depth' -Description ('directory scan with {0}' -f $switch) -ArgumentList @('SCAN', $corpus.Root, $switch, '/i0') | Out-Null
        }

        Add-TestCase @common -Group 'filter' -Description 'archive handling enabled explicitly' -ArgumentList @('SCAN', $corpus.Root, '/i0', '/e:A') | Out-Null
        Add-TestCase @common -Group 'filter' -Description 'mail databases and plain mail excluded' -ArgumentList @('SCAN', $corpus.Root, '/i0', '/e:BM') | Out-Null

        if (-not $SkipAuthProbe) {
            $exportProfileFile = Join-Path -Path $outputDirectory -ChildPath ('settings-profile-{0}.dat' -f $runnerMode.ToLowerInvariant())
            $exportPlainFile = Join-Path -Path $outputDirectory -ChildPath ('settings-plain-{0}.dat' -f $runnerMode.ToLowerInvariant())

            Add-TestCase @common -Group 'auth' -Description 'EXPORT RTP without credentials' -ArgumentList @('EXPORT', 'RTP', $exportProfileFile) -NoCredential | Out-Null
            Add-TestCase @common -Group 'auth' -Description 'EXPORT file-only form without credentials' -ArgumentList @('EXPORT', $exportPlainFile) -NoCredential | Out-Null

            if ($credential.Supplied) {
                Add-TestCase @common -Group 'auth' -Description 'EXPORT RTP with credentials' -ArgumentList @('EXPORT', 'RTP', $exportProfileFile) | Out-Null
                Add-TestCase @common -Group 'auth' -Description 'EXPORT file-only form with credentials' -ArgumentList @('EXPORT', $exportPlainFile) | Out-Null
            }
            else {
                Write-Line -Message 'No credentials were supplied: the auth group records the unauthenticated baseline only.' -Level 'WARN'
            }
        }

        if ($IncludeDestructive) {
            foreach ($action in @('/i1', '/i2', '/i8')) {
                $copyRoot = New-LabDirectory -Path (Join-Path -Path $runnerRoot -ChildPath ('destructive\{0}' -f $action.Trim('/')))
                Copy-Item -LiteralPath $corpus.Root -Destination $copyRoot -Recurse -Force
                $watch = Join-Path -Path (Join-Path -Path $copyRoot -ChildPath 'corpus') -ChildPath 'eicar-plain.com'
                Add-TestCase @common -Group 'action' -Description ('destructive action {0} on a throwaway copy' -f $action) -ArgumentList @('SCAN', $copyRoot, $action) -WatchPath $watch | Out-Null
            }
        }
    }

    $resultArray = @($script:Result)
    $csvPath = Join-Path -Path $outputDirectory -ChildPath 'avp-cli-matrix.csv'
    $jsonPath = Join-Path -Path $outputDirectory -ChildPath 'avp-cli-matrix.json'
    $summaryPath = Join-Path -Path $outputDirectory -ChildPath 'summary.md'
    $resultArray | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding utf8
    $resultArray | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding utf8

    $executed = @($resultArray | Where-Object -FilterScript { $null -ne $_.ExitCode })
    $skipped = @($resultArray | Where-Object -FilterScript { $null -eq $_.ExitCode })
    $succeeded = @($resultArray | Where-Object -FilterScript { $_.Succeeded })
    $reportCapable = @($resultArray | Where-Object -FilterScript { $_.ReportRequested -and $_.ReportCreated -and $_.Succeeded })
    $listCapable = @($resultArray | Where-Object -FilterScript { $_.Group -eq 'list' -and $_.Succeeded })
    $detecting = @($resultArray | Where-Object -FilterScript { $_.DetectionMarker })
    $survivors = @($resultArray | Where-Object -FilterScript { $_.WatchBefore -and $_.WatchAfter -and $_.DetectionMarker })

    $authCases = @($resultArray | Where-Object -FilterScript { $_.Group -eq 'auth' })
    $authBlocked = @($authCases | Where-Object -FilterScript { -not $_.Authenticated -and -not $_.Succeeded })
    $authAccepted = @($authCases | Where-Object -FilterScript { $_.Authenticated -and $_.Succeeded })
    $authRejected = @($authCases | Where-Object -FilterScript { $_.Authenticated -and $_.ExitCode -eq 1 })
    $credentialsAccepted = $authAccepted.Count -gt 0

    $loginFormVerdict = 'not tested'

    if ($credential.Supplied) {
        if ($credentialsAccepted) {
            $loginFormVerdict = 'accepted'
        }
        elseif ($authRejected.Count -gt 0) {
            $loginFormVerdict = 'rejected as an invalid parameter'
        }
        else {
            $loginFormVerdict = 'inconclusive - see the FirstLine column'
        }
    }

    $summary = [System.Collections.Generic.List[string]]::new()
    $summary.Add('# avp.com CLI behaviour matrix')
    $summary.Add('')
    $summary.Add(('Product: {0}' -f $avp))
    $summary.Add(('Selected by: {0}' -f $resolved.Source))
    $summary.Add(('Product line: {0}' -f $productLine))
    $summary.Add(('Version: {0}' -f $product.VersionInfo.FileVersion))
    $summary.Add(('Executed: {0:yyyy-MM-dd HH:mm}' -f $started))
    $summary.Add(('Cases: {0}; executed: {1}; skipped: {2}; succeeded: {3}' -f $resultArray.Count, $executed.Count, $skipped.Count, $succeeded.Count))
    $summary.Add('')
    $summary.Add('## Capability conclusions')
    $summary.Add('')
    $summary.Add(('- report option usable: {0}' -f ($reportCapable.Count -gt 0)))
    $summary.Add(('- scope list usable: {0}' -f ($listCapable.Count -gt 0)))

    if ($listCapable.Count -gt 0) {
        $summary.Add(('- list encodings that worked: {0}' -f ((@($listCapable | Select-Object -ExpandProperty Description) | Sort-Object -Unique) -join ', ')))
    }

    $summary.Add(('- cases carrying an EICAR verdict: {0}' -f $detecting.Count))
    $summary.Add(('- detected objects still present after the call: {0}' -f $survivors.Count))
    $summary.Add(('- cases not executed because protection removed the target first: {0}' -f $skipped.Count))
    $summary.Add('')
    $summary.Add('## Password protection')
    $summary.Add('')
    $summary.Add(('- auth style requested: {0}; effective: {1}' -f $credential.Requested, $credential.Style))
    $summary.Add(('- credential scope: {0}' -f $CredentialScope))
    $summary.Add(('- credentials supplied: {0}' -f $credential.Supplied))
    $summary.Add(('- login sent: {0}' -f $loginLabel))
    $summary.Add(('- credential form verdict: {0}' -f $loginFormVerdict))
    $summary.Add(('- protected commands that failed without credentials: {0}' -f $authBlocked.Count))
    $summary.Add(('- protected commands accepted with credentials: {0}' -f $authAccepted.Count))
    $summary.Add(('- credentialed calls returning invalid parameter: {0}' -f $authRejected.Count))
    $summary.Add('')
    $summary.Add('Invalid credentials are never probed: repeated failures lock the Password protection account.')
    $summary.Add('')
    $summary.Add('## Cases')
    $summary.Add('')
    $summary.Add('| Case | Group | Runner | Auth | Exit | Meaning | Report | Verdicts | Description | First line |')
    $summary.Add('| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |')

    foreach ($entry in $resultArray) {
        $firstLine = ($entry.FirstLine -replace '\|', '/')
        $exitText = if ($null -eq $entry.ExitCode) { 'n/a' } else { [string] $entry.ExitCode }
        $summary.Add(('| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} |' -f $entry.Case, $entry.Group, $entry.Runner, $entry.Authenticated, $exitText, $entry.ExitMeaning, $entry.ReportCreated, $entry.VerdictCount, $entry.Description, $firstLine))
    }

    Set-Content -LiteralPath $summaryPath -Value ($summary -join [System.Environment]::NewLine) -Encoding utf8
    Write-Line -Message ('cases: {0}; executed: {1}; skipped: {2}; succeeded: {3}' -f $resultArray.Count, $executed.Count, $skipped.Count, $succeeded.Count)

    if ($skipped.Count -gt 0) {
        Write-Line -Message ('{0} case(s) were skipped because real-time protection removed the target first. Use -SkipEicar for a syntax-only matrix.' -f $skipped.Count) -Level 'WARN'
    }

    if ($credential.Supplied) {
        Write-Line -Message ('credential form verdict: {0}; style={1}; login={2}' -f $loginFormVerdict, $credential.Style, $loginLabel)

        if ($authRejected.Count -gt 0 -and -not $credentialsAccepted) {
            Write-Line -Message 'Credentialed calls returned exit code 1. On the consumer line rerun with -AuthStyle PasswordOnly; on Endpoint Security rerun with -AuthStyle LoginAndPassword and an account that holds the required Password protection permission.' -Level 'WARN'
        }
    }

    if ($succeeded.Count -eq 0 -and $executed.Count -gt 0) {
        Write-Line -Message 'No executed case succeeded. Read the FirstLine column in the summary: it carries the message avp.com printed before exiting.' -Level 'WARN'
    }

    Write-Line -Message ('matrix csv: {0}' -f $csvPath)
    Write-Line -Message ('matrix json: {0}' -f $jsonPath)
    Write-Line -Message ('summary: {0}' -f $summaryPath)
    Write-Line -Message ('Remove the lab directory when finished: {0}' -f $labRootFull) -Level 'WARN'
    $resultArray | Format-Table -Property Case, Group, Runner, Authenticated, ExitCode, ExitMeaning, ReportCreated, VerdictCount, ElapsedMs -AutoSize
}
catch {
    $detail = 'FATAL: {0}{1}{2}' -f (Remove-Secret -Text $_.Exception.Message), [System.Environment]::NewLine, $_.ScriptStackTrace

    if ($script:LogFile) {
        try {
            Add-Content -LiteralPath $script:LogFile -Value $detail -Encoding utf8
        }
        catch {
            Write-Debug ('fatal detail not logged: {0}' -f $_.Exception.Message)
        }
    }

    throw
}
finally {
    $script:Secret = $null
    $secret = $null
    Write-Information -MessageData ('elapsed: {0:hh\:mm\:ss}' -f ((Get-Date) - $started))
}

#endregion
