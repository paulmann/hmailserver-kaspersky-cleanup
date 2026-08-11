#Requires -Version 7.2
<#
.SYNOPSIS
    Audits an hMailServer message store with the local Kaspersky console client
    (avp.com) in report-only mode and deletes confirmed infected messages through
    the hMailServer COM API.

.DESCRIPTION
    Version 6 keeps the field-measured behaviour of version 5 and changes three things:

      1. avp.com discovery is delegated to Test-AvpCli.ps1 -ResolvePathOnly, so both
         tools in this repository agree on which build is live. The harness ranks
         candidates by trustworthiness (resident process, service image, registry,
         folder scan) instead of by folder creation time. When the harness is absent,
         unusable or explicitly disabled, an equivalent internal resolver runs and the
         selected binary is health-probed with HELP either way.
      2. The invalid parenthesised 'if' expression in the UPDATE branch is replaced by
         a subexpression, which is what PowerShell actually accepts.
      3. The whole file is regionised, formatted consistently and commented.

    Behavioural rules that stay unchanged, because they were measured on a live server:

      * Verdicts come from the report body and its statistics block, never from the
         process exit code. A scan that finds an object it cannot process returns 3
         while the task completes and writes a full report, so 0, 3, 101 and 102 are
         all treated as non-fatal.
      * Credentials are never appended to SCAN or UPDATE: this product line does not
         accept /login or /password there and the invocation breaks.
      * UTF-16 scope lists are rejected by the product, so only ANSI and OEM lists plus
         direct arguments are probed, and the command line is length-bounded.
      * Kaspersky always runs with /i0. Nothing is deleted by the antivirus; deletion
         happens only in Delete mode, only from a reviewed plan, with an optional
         quarantine copy, through hMailServer's own DeleteByDBID.

.PARAMETER Mode
    Preflight - resolve avp.com, probe its capabilities and stop.
    Scan      - manifest, batched report-only scan, verdict parsing, plan generation.
    Plan      - identical to Scan; marks the run as review-only.
    Delete    - consume a plan and delete matched messages through COM.

.PARAMETER AvpPath
    Explicit path to avp.com or to a product directory. Still health-probed.

.PARAMETER KasperskyRoot
    Additional directory that contains Kaspersky product folders.

.PARAMETER HarnessPath
    Path to Test-AvpCli.ps1. Defaults to the copy next to this script. Used with
    -ResolvePathOnly as the primary avp.com locator.

.PARAMETER SkipHarness
    Do not call the harness; use the internal resolver only.

.PARAMETER DataDirectory
    hMailServer Data directory. Resolved automatically when omitted.

.PARAMETER AdminPassword
    hMailServer Administrator password as a SecureString. Prompted when needed.

.PARAMETER ReportDirectory
    Root for run directories. Must be outside the message store.

.PARAMETER QuarantineDirectory
    Root for quarantine copies. Must be outside the message store.

.PARAMETER PlanPath
    remediation-plan.json to consume in Delete mode.

.PARAMETER SinceDays
    Only consider messages newer than N days. 0 means the whole store.

.PARAMETER TimeoutMinutes
    Timeout for a single avp.com call.

.PARAMETER BatchSize
    Messages per scan call. Lowered automatically for direct-argument scope.

.PARAMETER Runner
    Cmd (cmd.exe with redirection), Direct (.NET pipes) or Auto.

.PARAMETER MaxCommandLine
    Command line budget used to bound the batch size.

.PARAMETER IncludeQueue
    Also scan loose .eml files in the root of the store.

.PARAMETER UpdateDatabases
    Run avp.com UPDATE before scanning.

.PARAMETER SkipQuarantine
    Delete without keeping a copy.

.PARAMETER DeleteOrphan
    Also remove infected files that no hMailServer message references.

.PARAMETER KeepBatchArtifacts
    Keep per-batch reports even when the run produced no findings.

.PARAMETER AllowPartialCoverage
    Accept partial coverage without the loud warning.

.EXAMPLE
    .\Invoke-HMailKasperskyCleanup.ps1 -Mode Preflight

.EXAMPLE
    .\Invoke-HMailKasperskyCleanup.ps1 -Mode Scan -SinceDays 1 -BatchSize 40

.EXAMPLE
    .\Invoke-HMailKasperskyCleanup.ps1 -Mode Delete -PlanPath 'C:\mail\reports\kaspersky\run-20260811-221500\remediation-plan.json' -WhatIf

.NOTES
    Run elevated in an interactive session with the resident Kaspersky process active.
    Back up the hMailServer database and the Data directory before using Delete mode.

.LINK
    https://github.com/paulmann/hmailserver-kaspersky-cleanup
#>

<#
    ============================================================================
    Project     : hMailServer + Kaspersky Cleanup
    Repository  : https://github.com/paulmann/hmailserver-kaspersky-cleanup
    File        : Invoke-HMailKasperskyCleanup.ps1
    Version     : 6.0
    Updated     : 2026-08-12
    Companion   : Test-AvpCli.ps1 in the same repository (avp.com locator/harness)
                  https://github.com/paulmann/hmailserver-clamav-cleanup (ClamAV twin)
    Developer   : Mikhail Deynekin <git@deynekin.com>
    Web         : https://deynekin.com/
    GitHub      : https://github.com/paulmann
    License     : MIT
    ============================================================================
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('Preflight', 'Scan', 'Plan', 'Delete')]
    [string] $Mode = 'Scan',

    [string] $AvpPath,

    [string] $KasperskyRoot = 'C:\Program Files (x86)\Kaspersky Lab',

    [string] $HarnessPath,

    [switch] $SkipHarness,

    [string] $DataDirectory,

    [securestring] $AdminPassword,

    [string] $ReportDirectory,

    [string] $QuarantineDirectory,

    [string] $PlanPath,

    [ValidateRange(0, 3650)]
    [int] $SinceDays = 0,

    [ValidateRange(1, 1440)]
    [int] $TimeoutMinutes = 60,

    [ValidateRange(1, 5000)]
    [int] $BatchSize = 40,

    [ValidateSet('Auto', 'Cmd', 'Direct')]
    [string] $Runner = 'Cmd',

    [ValidateRange(1000, 8000)]
    [int] $MaxCommandLine = 7000,

    [switch] $IncludeQueue,

    [switch] $UpdateDatabases,

    [switch] $SkipQuarantine,

    [switch] $DeleteOrphan,

    [switch] $KeepBatchArtifacts,

    [switch] $AllowPartialCoverage
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

# Constants that describe this tool rather than the host it runs on.
$script:ToolVersion  = '6.0'
$script:PlanSchema   = 5           # unchanged, so version 5 plans stay consumable
$script:RepositoryUrl = 'https://github.com/paulmann/hmailserver-kaspersky-cleanup'
$script:LogFile      = $null

if (-not $IsWindows) {
    throw 'Windows is required: this script uses avp.com, the registry and the hMailServer COM API.'
}

# Kaspersky reports are frequently written in the OEM code page; .NET Core needs the
# provider registered before those encodings can be requested by number.
try {
    [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance)
}
catch {
    Write-Debug ('code page provider not registered: {0}' -f $_.Exception.Message)
}

#region Infrastructure

function Write-RunLog {
    <#
        Single logging entry point: console plus the run log, with a stable prefix that
        is easy to grep after an incident.
    #>
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Message,

        [ValidateSet('INFO', 'WARN')]
        [string] $Level = 'INFO'
    )

    $line = '[{0:yyyy-MM-dd HH:mm:ss.fff}] [{1}] {2}' -f (Get-Date), $Level, $Message

    if ($Level -eq 'WARN') {
        Write-Warning -Message $Message
    }
    else {
        Write-Information -MessageData $line
    }

    if ($script:LogFile) {
        try {
            Add-Content -LiteralPath $script:LogFile -Value $line -Encoding utf8
        }
        catch {
            Write-Debug ('run log not written: {0}' -f $_.Exception.Message)
        }
    }
}

function Get-PlainText {
    # The COM API needs a plain string; the secret never leaves this function's caller.
    param(
        [AllowNull()]
        [securestring] $Secure
    )

    if ($null -eq $Secure) {
        return $null
    }

    return [System.Net.NetworkCredential]::new('', $Secure).Password
}

function Get-NormalPath {
    # Canonical form used for every comparison between report paths and COM filenames.
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $Path
    }

    try {
        return [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    }
    catch {
        Write-Debug ('path not normalized: {0}' -f $_.Exception.Message)
        return $Path.TrimEnd('\', '/')
    }
}

function Test-UnderRoot {
    # Containment test with a trailing separator, so C:\mailData is not "under" C:\mail.
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Root
    )

    $full = Get-NormalPath -Path $Path
    $base = (Get-NormalPath -Path $Root) + [System.IO.Path]::DirectorySeparatorChar
    return $full.StartsWith($base, [System.StringComparison]::OrdinalIgnoreCase)
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

function New-OutputDirectory {
    <#
        Creates an output directory and fails with an actionable message when the volume
        itself is missing, which is the usual mistake with -ReportDirectory.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Purpose
    )

    if (-not (Test-VolumeAvailable -Path $Path)) {
        $root = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($Path))
        $available = @(Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name | ForEach-Object -Process { '{0}:\' -f $_ })

        $detail = @(
            ('The {0} path is located on a volume that does not exist: {1}' -f $Purpose, $Path)
            ('Missing volume: {0}' -f $root)
            ('Available file system drives: {0}' -f ($available -join ', '))
            'Supply an existing volume, for example -ReportDirectory C:\mail\reports\kaspersky'
        )

        throw ($detail -join [System.Environment]::NewLine)
    }

    return (New-Item -ItemType Directory -Force -Path $Path).FullName
}

function Resolve-ExistingDirectory {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $ParameterName
    )

    if (-not (Test-VolumeAvailable -Path $Path)) {
        throw ('{0}: the volume of "{1}" does not exist on this host.' -f $ParameterName, $Path)
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw ('{0}: directory "{1}" was not found. Omit the parameter to let the script resolve it automatically.' -f $ParameterName, $Path)
    }

    return (Get-Item -LiteralPath $Path).FullName
}

function Write-JsonAtomic {
    # Write to a temporary sibling first: a killed run must not leave a half-written plan.
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [AllowNull()]
        $InputObject
    )

    $temp = '{0}.{1}.tmp' -f $Path, $PID
    ConvertTo-Json -InputObject $InputObject -Depth 8 | Set-Content -LiteralPath $temp -Encoding utf8
    Move-Item -LiteralPath $temp -Destination $Path -Force
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
    <#
        Reports arrive as UTF-8 with BOM, UTF-16 with either BOM, or raw OEM bytes.
        Sniff the BOM first, then look for the NUL density typical of UTF-16 without a
        BOM, and fall back to the OEM code page.
    #>
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

function ConvertTo-WindowsArgument {
    # Quoting for the cmd.exe runner; follows the Windows CRT backslash/quote rules.
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

function Get-AvpExitDescription {
    param(
        [Parameter(Mandatory)]
        [int] $Code
    )

    switch ($Code) {
        0 { return 'operation completed successfully' }
        1 { return 'invalid parameter value' }
        2 { return 'unknown error' }
        3 { return 'task completion error; in practice objects were detected and left unprocessed' }
        4 { return 'task cancelled' }
        101 { return 'all dangerous objects processed' }
        102 { return 'dangerous objects detected' }
        -10 { return 'undocumented -10, observed with the /@: scope list form' }
        -1 { return 'the script could not start or wait for the process' }
        default { return 'undocumented exit code' }
    }
}

function Test-AvpAcceptableCode {
    # 3 belongs here: a productive store returns it whenever something was found.
    param(
        [Parameter(Mandatory)]
        [int] $Code
    )

    return ($Code -in 0, 3, 101, 102)
}

function Get-RunnerMode {
    # Auto and Cmd both mean cmd.exe: redirection survives product self-defence better.
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Auto', 'Cmd', 'Direct')]
        [string] $Preference
    )

    if ($Preference -eq 'Direct') {
        return 'Direct'
    }

    return 'Cmd'
}

#endregion

#region avp.com runner

function Invoke-Avp {
    <#
        Runs one avp.com call and always returns an object, never throws for a non-zero
        exit code. Cmd mode redirects inside cmd.exe; Direct mode reads the pipes.
    #>
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

        [ValidateRange(1, 1440)]
        [int] $Timeout = 60,

        [switch] $Quiet
    )

    $workingDirectory = Split-Path -Path $Avp -Parent

    if (Test-Path -LiteralPath $StdOutFile) {
        Remove-Item -LiteralPath $StdOutFile -Force
    }

    if (-not $Quiet) {
        Write-RunLog -Message ('[{0}] avp.com {1}' -f $RunnerMode, (@($ArgumentList) -join ' '))
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.WorkingDirectory = $workingDirectory

    if ($RunnerMode -eq 'Cmd') {
        $quoted = @(@($ArgumentList) | ForEach-Object -Process { ConvertTo-WindowsArgument -Value $_ })
        $inner = 'cd /d {0} && {1} {2} > {3} 2>&1' -f
            (ConvertTo-WindowsArgument -Value $workingDirectory),
            (ConvertTo-WindowsArgument -Value $Avp),
            ($quoted -join ' '),
            (ConvertTo-WindowsArgument -Value $StdOutFile)

        $startInfo.FileName = Join-Path -Path $env:SystemRoot -ChildPath 'System32\cmd.exe'
        $startInfo.Arguments = '/d /s /v:off /c "{0}"' -f $inner
    }
    else {
        $startInfo.FileName = $Avp
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true

        foreach ($argument in @($ArgumentList)) {
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
            throw ('avp.com could not be started through the {0} runner.' -f $RunnerMode)
        }

        $outTask = $null
        $errTask = $null

        if ($RunnerMode -eq 'Direct') {
            # Read both pipes concurrently, otherwise a full buffer deadlocks the child.
            $outTask = $process.StandardOutput.ReadToEndAsync()
            $errTask = $process.StandardError.ReadToEndAsync()
        }

        if (-not $process.WaitForExit($Timeout * 60 * 1000)) {
            try {
                $process.Kill($true)
            }
            catch {
                $note = 'timeout; the process tree could not be terminated because of product self-defence'
            }

            if ([string]::IsNullOrWhiteSpace($note)) {
                $note = 'timeout after {0} minute(s)' -f $Timeout
            }
        }

        try {
            $process.WaitForExit(5000) | Out-Null
            $exitCode = $process.ExitCode
        }
        catch {
            $note = '{0}; exit code unavailable: {1}' -f $note, $_.Exception.Message
        }

        if ($RunnerMode -eq 'Direct') {
            $outputText = $outTask.GetAwaiter().GetResult() + $errTask.GetAwaiter().GetResult()
            [System.IO.File]::WriteAllText($StdOutFile, $outputText, [System.Text.UTF8Encoding]::new($false))
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
    }

    if (-not $Quiet) {
        Write-RunLog -Message ('[{0}] exit {1} ({2}); elapsed {3:hh\:mm\:ss}' -f $RunnerMode, $exitCode, (Get-AvpExitDescription -Code $exitCode), $stopwatch.Elapsed)
    }

    return [pscustomobject]@{
        ExitCode = [int] $exitCode
        StdOut   = $outputText
        Runner   = $RunnerMode
        Elapsed  = $stopwatch.Elapsed
        Note     = $note
    }
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
    # Rank 1 source: only the build whose resident process runs answers commands.
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
    # Rank 2 source: the image path of the Kaspersky services.
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
    # Rank 3 source: product environment keys and the Windows uninstall entries.
    $directory = [System.Collections.Generic.List[string]]::new()

    foreach ($root in @('HKLM:\SOFTWARE\WOW6432Node\KasperskyLab', 'HKLM:\SOFTWARE\KasperskyLab')) {
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

                    $folder = $null

                    if (Test-Path -LiteralPath $expanded -PathType Container) {
                        $folder = $expanded
                    }
                    elseif (Test-Path -LiteralPath $expanded -PathType Leaf) {
                        $folder = Split-Path -Path $expanded -Parent
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

            $location = ([string] $property.InstallLocation).Trim().Trim('"').TrimEnd('\')

            if (-not [string]::IsNullOrWhiteSpace($location) -and
                (Test-Path -LiteralPath $location -PathType Container) -and
                -not $directory.Contains($location)) {
                $directory.Add($location)
            }
        }
    }

    return @($directory)
}

function Get-FolderScanDirectory {
    # Rank 4 source: brute force over both Program Files trees, newest folder first.
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $ExtraRoot
    )

    $directory = [System.Collections.Generic.List[string]]::new()

    foreach ($base in @($ExtraRoot, "${env:ProgramFiles(x86)}\Kaspersky Lab", "$env:ProgramFiles\Kaspersky Lab")) {
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
    <#
        Collects avp.com candidates from every source and ranks them by trustworthiness.
        Ranking beats folder creation time: a newer directory can exist while its CLI
        refuses to run tasks, which is exactly what an interrupted upgrade leaves behind.
    #>
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

        $candidate.Add([pscustomobject]@{ Path = $full; Source = $Source; Rank = $Rank })
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
            Write-RunLog -Message ('-AvpPath does not point to an existing avp.com: {0}. Falling back to automatic discovery.' -f $Explicit) -Level 'WARN'
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

function Test-AvpHealth {
    <#
        A build is usable only when HELP answers. A stale product folder accepts the
        invocation and returns 3 with no output for every command.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Avp,

        [Parameter(Mandatory)]
        [string] $ProbeDirectory,

        [Parameter(Mandatory)]
        [ValidateSet('Cmd', 'Direct')]
        [string] $RunnerMode,

        [Parameter(Mandatory)]
        [int] $Index
    )

    $stdOut = Join-Path -Path $ProbeDirectory -ChildPath ('health-{0:d2}.out' -f $Index)
    $probe = Invoke-Avp -Avp $Avp -ArgumentList @('HELP') -RunnerMode $RunnerMode -StdOutFile $stdOut -Timeout 2 -Quiet
    $usable = ($probe.ExitCode -eq 0 -and $probe.StdOut.Length -gt 40)

    return [pscustomobject]@{
        Path      = $Avp
        Usable    = $usable
        ExitCode  = $probe.ExitCode
        Bytes     = $probe.StdOut.Length
    }
}

function Resolve-AvpFromHarness {
    <#
        Primary locator: Test-AvpCli.ps1 -ResolvePathOnly. Reusing the harness keeps both
        tools in this repository in agreement and gives this script the harness ranking,
        liveness probing and product-line detection for free.
        Returns $null when the harness is unavailable, so the caller can fall back.
    #>
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Harness,

        [AllowNull()]
        [AllowEmptyString()]
        [string] $Explicit,

        [Parameter(Mandatory)]
        [string] $ExtraRoot
    )

    $searchList = [System.Collections.Generic.List[string]]::new()

    if (-not [string]::IsNullOrWhiteSpace($Harness)) {
        $searchList.Add($Harness)
    }
    else {
        # Default: the copy shipped next to this script, plus the historical file name.
        foreach ($name in @('Test-AvpCli.ps1', 'Test-AvpCli-2.ps1')) {
            $searchList.Add((Join-Path -Path $PSScriptRoot -ChildPath $name))
        }
    }

    $script = @($searchList | Where-Object -FilterScript { Test-Path -LiteralPath $_ -PathType Leaf }) |
        Select-Object -First 1

    if (-not $script) {
        Write-RunLog -Message ('harness not found ({0}); using the internal resolver' -f ($searchList -join '; '))
        return $null
    }

    $argument = @{
        ResolvePathOnly = $true
        Quiet           = $true
        KasperskyRoot   = $ExtraRoot
    }

    if (-not [string]::IsNullOrWhiteSpace($Explicit)) {
        $argument['AvpPath'] = $Explicit
    }

    try {
        $location = & $script @argument
    }
    catch {
        Write-RunLog -Message ('harness {0} did not resolve avp.com: {1}' -f $script, $_.Exception.Message) -Level 'WARN'
        return $null
    }

    if ($null -eq $location -or [string]::IsNullOrWhiteSpace([string] $location.Path)) {
        Write-RunLog -Message ('harness {0} returned no path; using the internal resolver' -f $script) -Level 'WARN'
        return $null
    }

    if (-not (Test-Path -LiteralPath ([string] $location.Path) -PathType Leaf)) {
        Write-RunLog -Message ('harness returned a path that no longer exists: {0}' -f $location.Path) -Level 'WARN'
        return $null
    }

    # ProductLine and SupportsLogin are informational here: SCAN and UPDATE never take
    # credentials, but the value belongs in the log when a run has to be explained later.
    $productLine = ''
    $version = ''

    foreach ($name in @('ProductLine', 'Version')) {
        if ($location.PSObject.Properties.Name -contains $name) {
            if ($name -eq 'ProductLine') {
                $productLine = [string] $location.ProductLine
            }
            else {
                $version = [string] $location.Version
            }
        }
    }

    Write-RunLog -Message ('harness {0} selected avp.com: {1} (version {2}; product line {3})' -f
        (Split-Path -Path $script -Leaf), $location.Path, $version, $productLine)

    return [pscustomobject]@{
        Path        = [string] $location.Path
        Version     = $version
        ProductLine = $productLine
        Source      = 'Test-AvpCli.ps1 -ResolvePathOnly'
    }
}

function Resolve-AvpBinary {
    <#
        Harness first, internal resolver second, HELP health probe always. The selected
        binary is the one this run will use for every batch.
    #>
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Explicit,

        [Parameter(Mandatory)]
        [string] $Root,

        [AllowNull()]
        [AllowEmptyString()]
        [string] $Harness,

        [Parameter(Mandatory)]
        [string] $ProbeDirectory,

        [Parameter(Mandatory)]
        [ValidateSet('Cmd', 'Direct')]
        [string] $RunnerMode,

        [switch] $NoHarness
    )

    if (-not $NoHarness) {
        $fromHarness = Resolve-AvpFromHarness -Harness $Harness -Explicit $Explicit -ExtraRoot $Root

        if ($null -ne $fromHarness) {
            $health = Test-AvpHealth -Avp $fromHarness.Path -ProbeDirectory $ProbeDirectory -RunnerMode $RunnerMode -Index 1
            Write-RunLog -Message ('health probe of the harness selection: exit {0} ({1}); {2} byte(s); usable={3}' -f
                $health.ExitCode, (Get-AvpExitDescription -Code $health.ExitCode), $health.Bytes, $health.Usable)

            if ($health.Usable) {
                return [string] $fromHarness.Path
            }

            Write-RunLog -Message 'The harness selection failed the local health probe; continuing with the internal resolver.' -Level 'WARN'
        }
    }
    else {
        Write-RunLog -Message 'SkipHarness was supplied: the internal resolver is used.'
    }

    $candidateList = @(Get-AvpCandidate -Explicit $Explicit -ExtraRoot $Root)

    if ($candidateList.Count -eq 0) {
        throw ('avp.com was not found through the resident process, the services, the registry or a folder scan of {0}. Pass -AvpPath explicitly.' -f $Root)
    }

    $index = 1
    $probeList = [System.Collections.Generic.List[object]]::new()

    foreach ($candidate in $candidateList) {
        $index++
        $item = Get-Item -LiteralPath $candidate.Path
        $version = [string] $item.VersionInfo.FileVersion
        Write-RunLog -Message ('candidate rank {0}: {1} (version {2}; {3})' -f $candidate.Rank, $candidate.Path, $version, $candidate.Source)

        $health = Test-AvpHealth -Avp $candidate.Path -ProbeDirectory $ProbeDirectory -RunnerMode $RunnerMode -Index $index
        $probeList.Add($health)
        Write-RunLog -Message ('candidate health probe: exit {0} ({1}); {2} byte(s); usable={3}' -f
            $health.ExitCode, (Get-AvpExitDescription -Code $health.ExitCode), $health.Bytes, $health.Usable)

        if ($health.Usable) {
            Write-RunLog -Message ('selected avp.com: {0} (version {1}; {2})' -f $candidate.Path, $version, $candidate.Source)
            return [string] $candidate.Path
        }

        Write-RunLog -Message ('{0} answers nothing and is skipped; a stale product folder from an interrupted upgrade behaves exactly like this.' -f $candidate.Path) -Level 'WARN'
    }

    if ($candidateList.Count -eq 1) {
        Write-RunLog -Message 'The only avp.com candidate failed the health probe; continuing with it because no alternative exists.' -Level 'WARN'
        return [string] $candidateList[0].Path
    }

    $detail = @('No avp.com build answered the HELP command.', 'Checked builds:')

    foreach ($probe in $probeList) {
        $detail += ('  {0} (exit {1}, {2} byte(s))' -f $probe.Path, $probe.ExitCode, $probe.Bytes)
    }

    $detail += 'Verify that the resident process runs in this interactive session, or use a build whose CLI executes tasks: avp.com HELP SCAN'
    throw ($detail -join [System.Environment]::NewLine)
}

#endregion

#region hMailServer resolvers

function Get-ComProperty {
    # Late-bound property read: hMailServer versions differ in what they expose.
    param(
        [AllowNull()]
        $Object,

        [Parameter(Mandatory)]
        [string] $Name,

        [switch] $Quiet
    )

    if ($null -eq $Object) {
        return $null
    }

    try {
        return $Object.GetType().InvokeMember(
            $Name,
            [System.Reflection.BindingFlags]::GetProperty,
            $null,
            $Object,
            $null)
    }
    catch {
        if (-not $Quiet) {
            Write-RunLog -Message ('COM property {0} not readable: {1}' -f $Name, $_.Exception.Message) -Level 'WARN'
        }

        return $null
    }
}

function Get-ComCount {
    param(
        [AllowNull()]
        $Collection
    )

    if ($null -eq $Collection) {
        return 0
    }

    try {
        return [int] $Collection.Count
    }
    catch {
        Write-Debug ('COM collection has no Count: {0}' -f $_.Exception.Message)
        return 0
    }
}

function Get-ComItem {
    param(
        [AllowNull()]
        $Collection,

        [Parameter(Mandatory)]
        [int] $Index
    )

    if ($null -eq $Collection) {
        return $null
    }

    try {
        return $Collection.GetType().InvokeMember(
            'Item',
            [System.Reflection.BindingFlags]::GetProperty,
            $null,
            $Collection,
            @([int] $Index))
    }
    catch {
        Write-RunLog -Message ('COM item {0} not available: {1}' -f $Index, $_.Exception.Message) -Level 'WARN'
        return $null
    }
}

function Get-HMailDataDirectoryFromCom {
    <#
        Stage 1 of data directory resolution. Walks a short list of property paths with
        reflection instead of Invoke-Expression, so nothing is ever evaluated as code.
    #>
    param(
        [AllowNull()]
        [securestring] $Password
    )

    $application = $null

    try {
        $application = New-Object -ComObject 'hMailServer.Application'
    }
    catch {
        Write-RunLog -Message ('stage 1: hMailServer COM object unavailable: {0}' -f $_.Exception.Message)
        return $null
    }

    try {
        if ($null -ne $Password) {
            try {
                $authenticated = $application.Authenticate('Administrator', (Get-PlainText -Secure $Password))

                if ($authenticated -is [bool] -and -not $authenticated) {
                    Write-RunLog -Message 'stage 1: hMailServer COM authentication failed while resolving the data directory.' -Level 'WARN'
                    return $null
                }
            }
            catch {
                Write-RunLog -Message ('stage 1: COM authentication error: {0}' -f $_.Exception.Message)
                return $null
            }
        }

        $chainList = @(
            @('Settings', 'Directories', 'DataDirectory')
            @('Settings', 'DataDirectory')
            @('Settings', 'Directories', 'DataDir')
        )

        foreach ($chain in $chainList) {
            $current = $application

            foreach ($name in $chain) {
                $current = Get-ComProperty -Object $current -Name $name -Quiet

                if ($null -eq $current) {
                    break
                }
            }

            $value = [string] $current

            if (-not [string]::IsNullOrWhiteSpace($value) -and (Test-Path -LiteralPath $value -PathType Container)) {
                Write-RunLog -Message ('stage 1: data directory from COM property {0}: {1}' -f ($chain -join '.'), $value)
                return (Get-Item -LiteralPath $value).FullName
            }
        }

        return $null
    }
    finally {
        if ($null -ne $application) {
            try {
                $null = [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($application)
            }
            catch {
                Write-Debug ('COM object not released: {0}' -f $_.Exception.Message)
            }
        }
    }
}

function Resolve-HMailDataDirectory {
    # Explicit parameter, then COM, then hMailServer.INI, then the install location.
    param(
        [AllowEmptyString()]
        [string] $Explicit,

        [AllowNull()]
        [securestring] $Password
    )

    if (-not [string]::IsNullOrWhiteSpace($Explicit)) {
        Write-RunLog -Message 'stage 0: using the explicit DataDirectory parameter'
        return (Resolve-ExistingDirectory -Path $Explicit -ParameterName 'DataDirectory')
    }

    $fromCom = Get-HMailDataDirectoryFromCom -Password $Password

    if ($fromCom) {
        return $fromCom
    }

    $installList = [System.Collections.Generic.List[string]]::new()

    foreach ($key in @('HKLM:\SOFTWARE\WOW6432Node\hMailServer', 'HKLM:\SOFTWARE\hMailServer')) {
        $property = Get-ItemProperty -Path $key -Name 'InstallLocation' -ErrorAction SilentlyContinue
        $install = if ($null -ne $property) { [string] $property.InstallLocation } else { '' }

        if (-not [string]::IsNullOrWhiteSpace($install) -and -not $installList.Contains($install)) {
            $installList.Add($install)
            Write-RunLog -Message ('stage 2: install location from {0}: {1}' -f $key, $install)
        }
    }

    foreach ($install in $installList) {
        $ini = Join-Path -Path $install -ChildPath 'Bin\hMailServer.INI'

        if (-not (Test-Path -LiteralPath $ini -PathType Leaf)) {
            continue
        }

        $match = Select-String -LiteralPath $ini -Pattern '^\s*DataDir\s*=\s*(.+)$' -ErrorAction SilentlyContinue |
            Select-Object -First 1

        if ($null -eq $match) {
            continue
        }

        $raw = $match.Matches[0].Groups[1].Value.Trim().Trim('"')
        $expanded = [System.Environment]::ExpandEnvironmentVariables($raw)
        Write-RunLog -Message ('stage 3: DataDir from hMailServer.INI: {0}' -f $expanded)

        if (Test-Path -LiteralPath $expanded -PathType Container) {
            return (Get-Item -LiteralPath $expanded).FullName
        }
    }

    foreach ($install in $installList) {
        $fallback = Join-Path -Path $install -ChildPath 'Data'

        if (Test-Path -LiteralPath $fallback -PathType Container) {
            Write-RunLog -Message ('stage 4: data directory derived from the install location: {0}' -f $fallback)
            return (Get-Item -LiteralPath $fallback).FullName
        }
    }

    throw 'The hMailServer Data directory could not be resolved through the COM API, hMailServer.INI or the registry. Pass -DataDirectory explicitly.'
}

function Connect-HMailApplication {
    param(
        [Parameter(Mandatory)]
        [securestring] $Password
    )

    $application = $null

    try {
        $application = New-Object -ComObject 'hMailServer.Application'
    }
    catch {
        throw ('Cannot create hMailServer.Application: {0}. For 0x80040154 verify the COM registration and the process bitness.' -f $_.Exception.Message)
    }

    $authenticated = $application.Authenticate('Administrator', (Get-PlainText -Secure $Password))

    if ($authenticated -is [bool] -and -not $authenticated) {
        throw 'hMailServer authentication failed for the Administrator account.'
    }

    Write-RunLog -Message ('connected to hMailServer {0}' -f $application.Version)
    return $application
}

function Get-AdminSecret {
    param(
        [AllowNull()]
        [securestring] $Existing
    )

    if ($null -ne $Existing) {
        return $Existing
    }

    return (Read-Host -Prompt 'hMailServer Administrator password' -AsSecureString)
}

#endregion

#region Report parsing

function Get-ReportStatistic {
    # The '; Total detected:' block is authoritative; batches are summed.
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $pattern = [ordered]@{
        Processed = '(?im)^;\s*Processed objects:\s*(\d+)'
        TotalOk   = '(?im)^;\s*Total OK:\s*(\d+)'
        Detected  = '(?im)^;\s*Total detected:\s*(\d+)'
        Suspicion = '(?im)^;\s*Suspicions:\s*(\d+)'
        Skipped   = '(?im)^;\s*Total skipped:\s*(\d+)'
        Corrupted = '(?im)^;\s*Corrupted:\s*(\d+)'
        Errors    = '(?im)^;\s*Errors:\s*(\d+)'
    }

    $value = [ordered]@{}

    foreach ($key in $pattern.Keys) {
        $total = 0

        foreach ($match in [regex]::Matches($Text, $pattern[$key])) {
            $total += [int] $match.Groups[1].Value
        }

        $value[$key] = $total
    }

    return [pscustomobject]$value
}

function Get-Detection {
    <#
    .SYNOPSIS
        Extracts message level detections from an avp.com report.

    .DESCRIPTION
        Report lines describe container hierarchies, for example

            <path>.eml//attachment.rtf//equation   suspicion   HEUR:Exploit.MSOffice...
            <path>.eml//attachment.rtf//equation   skipped

        The base .eml path identifies the hMailServer message, while the remainder of
        the line identifies the object inside it. Lines that only state "ok" or describe
        an archive layer carry no verdict and are ignored. English and Russian state
        words are both recognised, because the report language follows the product UI.
    #>
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter(Mandatory)]
        [string] $Root
    )

    $pathPattern    = '(?<path>[A-Za-z]:\\[^\r\n<>|"]+?\.eml)'
    $verdictPattern = '(?i)\b(?<verdict>(?:EICAR[\w\-\.]*|HEUR:[\w\.\-]+|UDS:[\w\.\-]+|VHO:[\w\.\-]+|PDM:[\w\.\-]+|not-a-virus:[\w\.\-]+|Trojan[\w\.\-]*|Backdoor[\w\.\-]*|Exploit[\w\.\-]*|Worm[\w\.\-]*|Virus[\w\.\-]*|HackTool[\w\.\-]*|Hoax[\w\.\-]*))'
    $stateDetected  = '(?i)(\bsuspicion\b|\bdetected\b|\binfected\b|\u043e\u0431\u043d\u0430\u0440\u0443\u0436\u0435\u043d\w*|\u0437\u0430\u0440\u0430\u0436\u0435\u043d\w*)'
    $stateSkipped   = '(?i)(\bskipped\b|not\s+disinfected|\u043f\u0440\u043e\u043f\u0443\u0449\u0435\u043d\w*|\u043d\u0435\s+\u0432\u044b\u043b\u0435\u0447\u0435\u043d\w*)'
    $stateDeleted   = '(?i)(\bdeleted\b|\u0443\u0434\u0430\u043b\u0435\u043d\w*)'

    $entry = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $outside = 0

    foreach ($line in ($Text -split '\r\n|\n|\r')) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        # Lines starting with ';' are the statistics block, handled elsewhere.
        if ($line.TrimStart().StartsWith(';')) {
            continue
        }

        $hasVerdict = [regex]::Match($line, $verdictPattern)
        $isDetected = [bool] ($line -match $stateDetected)
        $isSkipped  = [bool] ($line -match $stateSkipped)
        $isDeleted  = [bool] ($line -match $stateDeleted)

        if (-not $hasVerdict.Success -and -not $isDetected -and -not $isSkipped) {
            continue
        }

        $pathMatch = [regex]::Match($line, $pathPattern)

        if (-not $pathMatch.Success) {
            continue
        }

        $basePath = Get-NormalPath -Path $pathMatch.Groups['path'].Value.Trim()

        # Anything outside the store is not ours to act on: log it and move on.
        if (-not (Test-UnderRoot -Path $basePath -Root $Root)) {
            $outside++
            continue
        }

        if (-not $entry.ContainsKey($basePath)) {
            $entry[$basePath] = [pscustomobject]@{
                Path        = $basePath
                Verdict     = 'Unknown'
                InnerObject = ''
                Detected    = $false
                Skipped     = $false
                Deleted     = $false
                ReportLine  = ''
                Occurrences = 0
            }
        }

        $record = $entry[$basePath]
        $record.Occurrences = $record.Occurrences + 1

        if ($hasVerdict.Success -and $record.Verdict -eq 'Unknown') {
            $record.Verdict = $hasVerdict.Groups['verdict'].Value
            $record.ReportLine = $line.Trim()

            $innerMatch = [regex]::Match($line, [regex]::Escape($pathMatch.Groups['path'].Value) + '(?<inner>(?://[^\t]*)+)')

            if ($innerMatch.Success) {
                $record.InnerObject = $innerMatch.Groups['inner'].Value.Trim()
            }
        }

        if ($isDetected) { $record.Detected = $true }
        if ($isSkipped)  { $record.Skipped = $true }
        if ($isDeleted)  { $record.Deleted = $true }
    }

    if ($outside -gt 0) {
        Write-RunLog -Message ('{0} verdict line(s) referenced paths outside the message store and were ignored.' -f $outside) -Level 'WARN'
    }

    return @($entry.Values |
        Where-Object -FilterScript { $_.Verdict -ne 'Unknown' -or $_.Detected } |
        Sort-Object -Property Path)
}

#endregion

#region Scan pipeline

function Get-MessageFile {
    # Loose .eml files directly in the store root are the queue; excluded unless asked.
    param(
        [Parameter(Mandatory)]
        [string] $Root,

        [int] $NewerThanDays = 0,

        [bool] $WithQueue = $false
    )

    $cutoff = if ($NewerThanDays -gt 0) { (Get-Date).AddDays(-$NewerThanDays) } else { [datetime]::MinValue }
    $normalizedRoot = Get-NormalPath -Path $Root
    $selected = [System.Collections.Generic.List[object]]::new()

    foreach ($file in @(Get-ChildItem -LiteralPath $Root -Filter '*.eml' -File -Recurse -Force -ErrorAction SilentlyContinue)) {
        if ($file.LastWriteTime -lt $cutoff) {
            continue
        }

        if (-not $WithQueue -and (Get-NormalPath -Path $file.DirectoryName) -eq $normalizedRoot) {
            continue
        }

        $selected.Add($file)
    }

    return @($selected)
}

function New-FileManifest {
    # The manifest is the evidence base: what existed, how large, and its hash.
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $File,

        [Parameter(Mandatory)]
        [string] $Path,

        [switch] $SkipHash
    )

    $entryList = [System.Collections.Generic.List[object]]::new()

    foreach ($item in @($File)) {
        $hash = $null

        if (-not $SkipHash) {
            try {
                $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
            }
            catch {
                Write-Debug ('hash not computed for {0}: {1}' -f $item.FullName, $_.Exception.Message)
            }
        }

        $entryList.Add([pscustomobject]@{
            Path             = $item.FullName
            Length           = [int64] $item.Length
            LastWriteTimeUtc = $item.LastWriteTimeUtc.ToString('o')
            SHA256           = $hash
        })
    }

    Write-JsonAtomic -Path $Path -InputObject ([pscustomobject]@{
        Schema      = 3
        ToolVersion = $script:ToolVersion
        CreatedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        Hashed      = (-not $SkipHash.IsPresent)
        Count       = $entryList.Count
        Files       = @($entryList)
    })

    return @($entryList)
}

function New-ScopeListFile {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $Path,

        [Parameter(Mandatory)]
        [string] $File,

        [Parameter(Mandatory)]
        [ValidateSet('Ansi', 'Oem')]
        [string] $Encoding
    )

    [System.IO.File]::WriteAllLines($File, [string[]] @($Path), (Get-CodePageEncoding -Name $Encoding))
    return $File
}

function Test-AvpCapability {
    <#
    .SYNOPSIS
        Determines which invocation form this build accepts, using a disposable probe file.

    .DESCRIPTION
        UTF-16 scope lists are not probed: the product rejects them with an undocumented
        code and wastes minutes doing so. A form counts as usable when the exit code is
        acceptable and the run produced parseable text, in the report file or on stdout.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Avp,

        [Parameter(Mandatory)]
        [string] $RunDirectory,

        [Parameter(Mandatory)]
        [ValidateSet('Auto', 'Cmd', 'Direct')]
        [string] $RunnerPreference
    )

    $probeRoot = New-OutputDirectory -Path (Join-Path -Path $RunDirectory -ChildPath 'preflight') -Purpose 'preflight'
    $probeTarget = New-OutputDirectory -Path (Join-Path -Path $probeRoot -ChildPath 'target') -Purpose 'preflight target'
    $probeFile = Join-Path -Path $probeTarget -ChildPath 'probe.eml'

    $probeBody = @(
        'From: probe@example.test'
        'Subject: kaspersky cli capability probe'
        ''
        'No signature is present in this probe message.'
    )

    [System.IO.File]::WriteAllLines($probeFile, [string[]] $probeBody, [System.Text.Encoding]::ASCII)
    $runnerList = if ($RunnerPreference -eq 'Auto') { @('Cmd', 'Direct') } else { @($RunnerPreference) }
    $matrix = [System.Collections.Generic.List[object]]::new()
    $index = 0

    foreach ($runnerMode in $runnerList) {
        foreach ($scope in @('ListAnsi', 'ListOem', 'Directory')) {
            foreach ($useReport in @($true, $false)) {
                $index++
                $stdOut = Join-Path -Path $probeRoot -ChildPath ('probe-{0:d2}.out' -f $index)
                $reportFile = Join-Path -Path $probeRoot -ChildPath ('probe-{0:d2}.report' -f $index)
                $argument = [System.Collections.Generic.List[string]]::new()
                $argument.Add('SCAN')

                switch ($scope) {
                    'Directory' {
                        $argument.Add($probeTarget)
                    }
                    'ListOem' {
                        $listFile = New-ScopeListFile -Path @($probeFile) -File (Join-Path -Path $probeRoot -ChildPath ('probe-{0:d2}-oem.lst' -f $index)) -Encoding 'Oem'
                        $argument.Add(('/@:{0}' -f $listFile))
                    }
                    default {
                        $listFile = New-ScopeListFile -Path @($probeFile) -File (Join-Path -Path $probeRoot -ChildPath ('probe-{0:d2}-ansi.lst' -f $index)) -Encoding 'Ansi'
                        $argument.Add(('/@:{0}' -f $listFile))
                    }
                }

                $argument.Add('/i0')

                if ($useReport) {
                    $argument.Add(('/RA:{0}' -f $reportFile))
                }

                $exitCode = -1
                $note = ''
                $reportText = ''
                $stdOutText = ''

                try {
                    $probe = Invoke-Avp -Avp $Avp -ArgumentList ([string[]] $argument) -RunnerMode $runnerMode -StdOutFile $stdOut -Timeout 3 -Quiet
                    $exitCode = $probe.ExitCode
                    $stdOutText = $probe.StdOut
                    $note = $probe.Note
                }
                catch {
                    $note = $_.Exception.Message
                }

                if ($useReport) {
                    $reportText = Get-DecodedText -Path $reportFile
                }

                $hasText = (($reportText.Length -gt 40) -or ($stdOutText -match '(?i)Scan_Objects|Processed objects|\bok\b'))
                $usable = ((Test-AvpAcceptableCode -Code $exitCode) -and $hasText)

                $entry = [pscustomobject]@{
                    Runner      = $runnerMode
                    Scope       = $scope
                    UseReport   = $useReport
                    ExitCode    = $exitCode
                    ReportBytes = $reportText.Length
                    StdOutBytes = $stdOutText.Length
                    Usable      = $usable
                    Note        = $note
                }

                $matrix.Add($entry)
                Write-RunLog -Message ('preflight: runner={0}; scope={1}; /RA={2}; exit={3} ({4}); report={5}B; stdout={6}B; usable={7}' -f
                    $entry.Runner, $entry.Scope, $entry.UseReport, $entry.ExitCode, (Get-AvpExitDescription -Code $entry.ExitCode), $entry.ReportBytes, $entry.StdOutBytes, $entry.Usable)
            }
        }
    }

    Write-JsonAtomic -Path (Join-Path -Path $RunDirectory -ChildPath 'preflight-matrix.json') -InputObject @($matrix)
    $usableList = @($matrix | Where-Object -FilterScript { $_.Usable })

    if ($usableList.Count -eq 0) {
        $detail = @(
            'No avp.com invocation form produced parseable output during preflight.'
            'Checklist:'
            '  * the resident Kaspersky process must run in the same interactive session;'
            '  * the session must be elevated;'
            '  * verify manually: avp.com HELP SCAN'
            ('  * inspect the captured output in {0}' -f $probeRoot)
        )

        throw ($detail -join [System.Environment]::NewLine)
    }

    # Preference: ANSI list, then OEM list, then direct arguments; report file preferred.
    $ordered = @($usableList | Sort-Object -Property @(
        @{ Expression = { switch ($_.Scope) { 'ListAnsi' { 0 } 'ListOem' { 1 } default { 2 } } } }
        @{ Expression = { -not $_.UseReport } }
    ))

    $selected = $ordered[0]
    Write-RunLog -Message ('preflight selection: runner={0}; scope={1}; /RA={2}' -f $selected.Runner, $selected.Scope, $selected.UseReport)

    return [pscustomobject]@{
        Runner    = [string] $selected.Runner
        Scope     = [string] $selected.Scope
        UseReport = [bool] $selected.UseReport
        Matrix    = @($matrix)
    }
}

function Get-EffectiveBatchSize {
    # Bounds the batch so a direct-argument scope cannot exceed the shell limit.
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $Path,

        [Parameter(Mandatory)]
        [int] $Requested,

        [Parameter(Mandatory)]
        [string] $Scope,

        [Parameter(Mandatory)]
        [int] $Limit
    )

    if ($Scope -ne 'Directory') {
        return $Requested
    }

    $all = @($Path)

    if ($all.Count -eq 0) {
        return $Requested
    }

    $average = ([double] (($all | Measure-Object -Property Length -Sum).Sum) / $all.Count) + 3
    $allowed = [int] [Math]::Max(1, [Math]::Floor(($Limit - 200) / $average))

    if ($allowed -lt $Requested) {
        Write-RunLog -Message ('direct-argument scope: batch size reduced from {0} to {1} to stay under a {2} character command line' -f $Requested, $allowed, $Limit) -Level 'WARN'
        return $allowed
    }

    return $Requested
}

function Invoke-BatchScan {
    <#
        Scans the store in batches with /i0. A batch counts as scanned only when the exit
        code is acceptable and its output is parseable; everything else is recorded as a
        failure so coverage stays honest.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Avp,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $Path,

        [Parameter(Mandatory)]
        $Capability,

        [Parameter(Mandatory)]
        [string] $RunDirectory,

        [Parameter(Mandatory)]
        [int] $Size,

        [ValidateRange(1, 1440)]
        [int] $Timeout = 60
    )

    $batchDirectory = New-OutputDirectory -Path (Join-Path -Path $RunDirectory -ChildPath 'batches') -Purpose 'batch'
    $all = @($Path)
    $total = [int] [Math]::Ceiling($all.Count / [double] $Size)
    $builder = [System.Text.StringBuilder]::new()
    $failed = [System.Collections.Generic.List[object]]::new()
    $detectingBatch = [System.Collections.Generic.List[object]]::new()
    $scannedPath = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $number = 0

    for ($offset = 0; $offset -lt $all.Count; $offset += $Size) {
        $number++
        $slice = @($all[$offset..([Math]::Min($offset + $Size, $all.Count) - 1)])
        $stdOutFile = Join-Path -Path $batchDirectory -ChildPath ('batch-{0:d5}.out' -f $number)
        $reportFile = Join-Path -Path $batchDirectory -ChildPath ('batch-{0:d5}.report' -f $number)
        $argument = [System.Collections.Generic.List[string]]::new()
        $argument.Add('SCAN')

        if ($Capability.Scope -eq 'Directory') {
            foreach ($item in $slice) {
                $argument.Add($item)
            }
        }
        else {
            $encoding = if ($Capability.Scope -eq 'ListOem') { 'Oem' } else { 'Ansi' }
            $listFile = New-ScopeListFile -Path $slice -File (Join-Path -Path $batchDirectory -ChildPath ('batch-{0:d5}.lst' -f $number)) -Encoding $encoding
            $argument.Add(('/@:{0}' -f $listFile))
        }

        $argument.Add('/i0')

        if ($Capability.UseReport) {
            $argument.Add(('/RA:{0}' -f $reportFile))
        }

        $scan = $null

        try {
            $scan = Invoke-Avp -Avp $Avp -ArgumentList ([string[]] $argument) -RunnerMode $Capability.Runner -StdOutFile $stdOutFile -Timeout $Timeout -Quiet
        }
        catch {
            Write-RunLog -Message ('batch {0}/{1} could not be executed: {2}' -f $number, $total, $_.Exception.Message) -Level 'WARN'
            $failed.Add([pscustomobject]@{ Batch = $number; ExitCode = -1; Count = $slice.Count; Reason = $_.Exception.Message })
            continue
        }

        $batchText = ''

        if ($Capability.UseReport) {
            $batchText = Get-DecodedText -Path $reportFile
        }

        if ([string]::IsNullOrWhiteSpace($batchText)) {
            $batchText = $scan.StdOut
        }

        $statistic = Get-ReportStatistic -Text $batchText
        $parseable = (($batchText.Length -gt 40) -and ($batchText -match '(?i)Scan_Objects|Processed objects|\bok\b|suspicion|detected'))

        if (-not (Test-AvpAcceptableCode -Code $scan.ExitCode) -or -not $parseable) {
            Write-RunLog -Message ('batch {0}/{1} failed: exit {2} ({3}); parseable={4}; {5} path(s) affected' -f
                $number, $total, $scan.ExitCode, (Get-AvpExitDescription -Code $scan.ExitCode), $parseable, $slice.Count) -Level 'WARN'
            $failed.Add([pscustomobject]@{ Batch = $number; ExitCode = $scan.ExitCode; Count = $slice.Count; Reason = 'unacceptable exit code or unparseable output' })
            continue
        }

        foreach ($item in $slice) {
            $null = $scannedPath.Add((Get-NormalPath -Path $item))
        }

        # Exit code 3 with a readable report is the classic "found something" case.
        if ($scan.ExitCode -eq 3 -or $statistic.Detected -gt 0) {
            Write-RunLog -Message ('batch {0}/{1}: exit {2}, detected={3}, skipped={4}; the report is parsed for verdicts' -f
                $number, $total, $scan.ExitCode, $statistic.Detected, $statistic.Skipped)
            $detectingBatch.Add([pscustomobject]@{ Batch = $number; ExitCode = $scan.ExitCode; Detected = $statistic.Detected })
        }

        $null = $builder.AppendLine($batchText)

        if (($number % 10) -eq 0 -or $number -eq $total) {
            Write-RunLog -Message ('batch progress: {0}/{1}' -f $number, $total)
        }
    }

    return [pscustomobject]@{
        Text           = $builder.ToString()
        BatchCount     = $number
        FailedBatch    = @($failed)
        DetectingBatch = @($detectingBatch)
        ScannedPath    = $scannedPath
        BatchDirectory = $batchDirectory
    }
}

function Get-HMailMatch {
    <#
        Walks domains, accounts, INBOX and the whole IMAP folder tree, and returns the
        messages whose backing file appears in the detection index. The live COM
        collection is carried along, because DeleteByDBID is a method on it.
    #>
    param(
        [Parameter(Mandatory)]
        $Application,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Detection
    )

    $index = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($item in @($Detection)) {
        $index[(Get-NormalPath -Path ([string] $item.Path))] = $item
    }

    if ($index.Count -eq 0) {
        return @()
    }

    $matched = [System.Collections.Generic.List[object]]::new()
    $inspected = 0
    $domains = Get-ComProperty -Object $Application -Name 'Domains'
    $domainCount = Get-ComCount -Collection $domains
    Write-RunLog -Message ('COM enumeration: {0} domain(s)' -f $domainCount)

    for ($domainIndex = 0; $domainIndex -lt $domainCount; $domainIndex++) {
        $domain = Get-ComItem -Collection $domains -Index $domainIndex

        if ($null -eq $domain) {
            continue
        }

        $accounts = Get-ComProperty -Object $domain -Name 'Accounts'
        $accountCount = Get-ComCount -Collection $accounts

        for ($accountIndex = 0; $accountIndex -lt $accountCount; $accountIndex++) {
            $account = Get-ComItem -Collection $accounts -Index $accountIndex

            if ($null -eq $account) {
                continue
            }

            $accountAddress = [string] (Get-ComProperty -Object $account -Name 'Address')
            $folderWork = [System.Collections.Generic.List[object]]::new()
            $inbox = Get-ComProperty -Object $account -Name 'Messages'

            if ($null -ne $inbox) {
                $folderWork.Add([pscustomobject]@{ Name = 'INBOX'; Items = $inbox })
            }

            # Depth-first walk of the IMAP tree without recursion.
            $pending = [System.Collections.Generic.Stack[object]]::new()
            $rootFolders = Get-ComProperty -Object $account -Name 'IMAPFolders'

            if ($null -ne $rootFolders) {
                $pending.Push([pscustomobject]@{ Prefix = ''; Folders = $rootFolders })
            }

            while ($pending.Count -gt 0) {
                $node = $pending.Pop()
                $folderCount = Get-ComCount -Collection $node.Folders

                for ($folderIndex = 0; $folderIndex -lt $folderCount; $folderIndex++) {
                    $folder = Get-ComItem -Collection $node.Folders -Index $folderIndex

                    if ($null -eq $folder) {
                        continue
                    }

                    $folderName = [string] (Get-ComProperty -Object $folder -Name 'Name')
                    $name = if ($node.Prefix) { '{0}/{1}' -f $node.Prefix, $folderName } else { $folderName }
                    $folderMessages = Get-ComProperty -Object $folder -Name 'Messages'

                    if ($null -ne $folderMessages) {
                        $folderWork.Add([pscustomobject]@{ Name = $name; Items = $folderMessages })
                    }

                    $subFolders = Get-ComProperty -Object $folder -Name 'SubFolders'

                    if ($null -ne $subFolders) {
                        $pending.Push([pscustomobject]@{ Prefix = $name; Folders = $subFolders })
                    }
                }
            }

            foreach ($work in $folderWork) {
                $collection = $work.Items
                $messageCount = Get-ComCount -Collection $collection

                for ($messageIndex = 0; $messageIndex -lt $messageCount; $messageIndex++) {
                    $message = Get-ComItem -Collection $collection -Index $messageIndex

                    if ($null -eq $message) {
                        continue
                    }

                    $inspected++
                    $fileName = [string] (Get-ComProperty -Object $message -Name 'Filename')

                    if ([string]::IsNullOrWhiteSpace($fileName)) {
                        continue
                    }

                    $key = Get-NormalPath -Path $fileName

                    if (-not $index.ContainsKey($key)) {
                        continue
                    }

                    $hit = $index[$key]
                    $size = Get-ComProperty -Object $message -Name 'Size'

                    $matched.Add([pscustomobject]@{
                        Account     = $accountAddress
                        Folder      = [string] $work.Name
                        MessageId   = [int] (Get-ComProperty -Object $message -Name 'ID')
                        Date        = [string] (Get-ComProperty -Object $message -Name 'Date')
                        From        = [string] (Get-ComProperty -Object $message -Name 'FromAddress')
                        Subject     = [string] (Get-ComProperty -Object $message -Name 'Subject')
                        SizeKB      = if ($null -ne $size) { [Math]::Round(($size / 1KB), 1) } else { 0 }
                        Verdict     = [string] $hit.Verdict
                        InnerObject = [string] $hit.InnerObject
                        Skipped     = [bool] $hit.Skipped
                        File        = $key
                        Collection  = $collection
                    })
                }
            }
        }
    }

    Write-RunLog -Message ('messages inspected through COM: {0}; matched: {1}' -f $inspected, $matched.Count)
    return @($matched)
}

#endregion

#region Main

$started = Get-Date
$stamp = $started.ToString('yyyyMMdd-HHmmss')
$systemDrive = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }

if ([string]::IsNullOrWhiteSpace($ReportDirectory)) {
    $ReportDirectory = Join-Path -Path $systemDrive -ChildPath 'mail\reports\kaspersky'
}

if ([string]::IsNullOrWhiteSpace($QuarantineDirectory)) {
    $QuarantineDirectory = Join-Path -Path $systemDrive -ChildPath 'mail\quarantine'
}

$mutex = $null
$mutexHeld = $false
$application = $null

try {
    $reportRoot = New-OutputDirectory -Path $ReportDirectory -Purpose 'report'
    $runDirectory = New-OutputDirectory -Path (Join-Path -Path $reportRoot -ChildPath ('run-{0}' -f $stamp)) -Purpose 'run'
    $script:LogFile = Join-Path -Path $runDirectory -ChildPath 'run.log'

    # One run at a time: two concurrent scans of the same store prove nothing.
    $mutex = [System.Threading.Mutex]::new($false, 'Global\Invoke-HMailKasperskyCleanup')
    $mutexHeld = $mutex.WaitOne(0)

    if (-not $mutexHeld) {
        throw 'Another instance of this script is already running.'
    }

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    $elevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    $sessionId = (Get-Process -Id $PID).SessionId

    Write-RunLog -Message ('version {0}; repository {1}' -f $script:ToolVersion, $script:RepositoryUrl)
    Write-RunLog -Message ('mode={0}; pwsh={1}; identity={2}; elevated={3}; session={4}; pid={5}' -f $Mode, $PSVersionTable.PSVersion, $identity.Name, $elevated, $sessionId, $PID)
    Write-RunLog -Message ('run directory: {0}' -f $runDirectory)

    if (-not $elevated) {
        Write-RunLog -Message 'The session is not elevated; avp.com tasks and COM operations may fail.' -Level 'WARN'
    }

    # Environment facts worth having in the log before anything is attempted.
    foreach ($name in @('avp', 'avpui', 'ksde', 'ksdeui')) {
        $processList = @(Get-Process -Name $name -ErrorAction SilentlyContinue)

        if ($processList.Count -eq 0) {
            continue
        }

        $sessions = @($processList | Select-Object -ExpandProperty SessionId | Sort-Object -Unique)
        $folders = @($processList |
            ForEach-Object -Process { Get-ProcessImagePath -Process $_ } |
            Where-Object -FilterScript { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object -Process { Split-Path -Path $_ -Parent } |
            Sort-Object -Unique)

        Write-RunLog -Message ('Kaspersky process {0}: {1} instance(s), session(s) {2}, folder(s) {3}' -f $name, $processList.Count, ($sessions -join ','), ($folders -join ' | '))

        if ($folders.Count -gt 1) {
            Write-RunLog -Message ('{0} runs from more than one product folder, which indicates an interrupted upgrade. Resolve that before trusting any result.' -f $name) -Level 'WARN'
        }
    }

    if (@(Get-Process -Name 'avp' -ErrorAction SilentlyContinue).Count -eq 0) {
        Write-RunLog -Message 'The resident Kaspersky process avp.exe is not running; avp.com cannot execute tasks.' -Level 'WARN'
    }

    $runnerMode = Get-RunnerMode -Preference $Runner
    $healthDirectory = New-OutputDirectory -Path (Join-Path -Path $runDirectory -ChildPath 'avp-health') -Purpose 'health probe'

    $avp = Resolve-AvpBinary `
        -Explicit $AvpPath `
        -Root $KasperskyRoot `
        -Harness $HarnessPath `
        -ProbeDirectory $healthDirectory `
        -RunnerMode $runnerMode `
        -NoHarness:$SkipHarness

    if ($UpdateDatabases) {
        # Fixed in version 6: a parenthesised 'if' is not an expression in PowerShell.
        $update = Invoke-Avp -Avp $avp -ArgumentList @('UPDATE') -RunnerMode $runnerMode `
            -StdOutFile (Join-Path -Path $runDirectory -ChildPath 'update.out') -Timeout 60

        if (-not (Test-AvpAcceptableCode -Code $update.ExitCode)) {
            Write-RunLog -Message ('UPDATE returned {0} ({1}); continuing with the current databases.' -f $update.ExitCode, (Get-AvpExitDescription -Code $update.ExitCode)) -Level 'WARN'
        }
    }

    if ($Mode -eq 'Preflight') {
        $null = Test-AvpCapability -Avp $avp -RunDirectory $runDirectory -RunnerPreference $Runner
        Write-RunLog -Message ('preflight matrix: {0}' -f (Join-Path -Path $runDirectory -ChildPath 'preflight-matrix.json'))
        return
    }

    $dataDirectory = Get-NormalPath -Path (Resolve-HMailDataDirectory -Explicit $DataDirectory -Password $AdminPassword)
    Write-RunLog -Message ('message store: {0}' -f $dataDirectory)

    # Writing reports or quarantine inside the store would make the scanner scan itself.
    foreach ($critical in @($reportRoot, $QuarantineDirectory)) {
        if (Test-UnderRoot -Path $critical -Root $dataDirectory) {
            throw ('Reports and quarantine must be located outside the message store, but "{0}" is inside "{1}".' -f $critical, $dataDirectory)
        }
    }

    #--------------------------------------------------------------------------
    # Delete mode: consume a reviewed plan.
    #--------------------------------------------------------------------------
    if ($Mode -eq 'Delete') {
        if ([string]::IsNullOrWhiteSpace($PlanPath) -or -not (Test-Path -LiteralPath $PlanPath -PathType Leaf)) {
            throw 'Delete mode requires -PlanPath pointing to a remediation-plan.json produced by Scan or Plan mode.'
        }

        $plan = Get-Content -LiteralPath $PlanPath -Raw | ConvertFrom-Json

        if ([int] $plan.Schema -ne $script:PlanSchema) {
            throw ('Unsupported plan schema: {0}. Re-run Scan mode with this script version.' -f $plan.Schema)
        }

        if ((Get-NormalPath -Path ([string] $plan.DataDirectory)) -ne $dataDirectory) {
            throw ('The plan was created for "{0}" but the current message store is "{1}".' -f $plan.DataDirectory, $dataDirectory)
        }

        $planMessage = @($plan.MatchedMessages)

        if ($planMessage.Count -eq 0) {
            Write-RunLog -Message 'The plan contains no matched messages; nothing to delete.'
            return
        }

        # Identity of a deletion target is the pair (MessageId, file path).
        $planKey = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $lookup = [System.Collections.Generic.List[object]]::new()

        foreach ($item in $planMessage) {
            $itemPath = Get-NormalPath -Path ([string] $item.File)

            if (-not (Test-UnderRoot -Path $itemPath -Root $dataDirectory)) {
                throw ('The plan references a path outside the message store: {0}' -f $itemPath)
            }

            $null = $planKey.Add(('{0}|{1}' -f [int] $item.MessageId, $itemPath))

            $lookup.Add([pscustomobject]@{
                Path        = $itemPath
                Verdict     = [string] $item.Verdict
                InnerObject = [string] $item.InnerObject
                Skipped     = $false
            })
        }

        $AdminPassword = Get-AdminSecret -Existing $AdminPassword
        $application = Connect-HMailApplication -Password $AdminPassword
        $current = @(Get-HMailMatch -Application $application -Detection ([object[]] $lookup))
        $quarantine = ''

        if (-not $SkipQuarantine) {
            $quarantine = New-OutputDirectory -Path (Join-Path -Path $QuarantineDirectory -ChildPath $stamp) -Purpose 'quarantine'
            Write-RunLog -Message ('quarantine directory: {0}' -f $quarantine)
        }

        $deleted = 0
        $skipped = 0

        foreach ($message in $current) {
            $key = '{0}|{1}' -f [int] $message.MessageId, (Get-NormalPath -Path ([string] $message.File))

            if (-not $planKey.Contains($key)) {
                $skipped++
                continue
            }

            $target = '{0} / {1} / id={2} [{3}]' -f $message.Account, $message.Folder, $message.MessageId, $message.Verdict

            if (-not $PSCmdlet.ShouldProcess($target, 'Delete infected message through the hMailServer COM API')) {
                continue
            }

            if ($quarantine -and (Test-Path -LiteralPath $message.File -PathType Leaf)) {
                $safeAccount = ([string] $message.Account) -replace '[^A-Za-z0-9_.-]', '_'
                $leaf = '{0}_{1}_{2}.bad' -f $safeAccount, $message.MessageId, [System.IO.Path]::GetFileName([string] $message.File)

                try {
                    Copy-Item -LiteralPath $message.File -Destination (Join-Path -Path $quarantine -ChildPath $leaf) -Force
                }
                catch {
                    # No copy, no deletion: losing evidence is worse than keeping the mail.
                    Write-RunLog -Message ('quarantine copy failed for id={0}: {1}; the message is not deleted' -f $message.MessageId, $_.Exception.Message) -Level 'WARN'
                    continue
                }
            }

            try {
                $message.Collection.DeleteByDBID([int] $message.MessageId)
                $deleted++
                Write-RunLog -Message ('deleted id={0} verdict={1} file={2}' -f $message.MessageId, $message.Verdict, $message.File)
            }
            catch {
                Write-RunLog -Message ('failed to delete id={0}: {1}' -f $message.MessageId, $_.Exception.Message) -Level 'WARN'
            }
        }

        if ($DeleteOrphan) {
            foreach ($orphan in @($plan.Orphans)) {
                $orphanPath = Get-NormalPath -Path ([string] $orphan.Path)

                if (-not (Test-UnderRoot -Path $orphanPath -Root $dataDirectory)) {
                    Write-RunLog -Message ('refusing to delete a path outside the message store: {0}' -f $orphanPath) -Level 'WARN'
                    continue
                }

                if ([System.IO.Path]::GetExtension($orphanPath) -ine '.eml') {
                    Write-RunLog -Message ('refusing to delete a non-.eml file: {0}' -f $orphanPath) -Level 'WARN'
                    continue
                }

                if (-not (Test-Path -LiteralPath $orphanPath -PathType Leaf)) {
                    continue
                }

                if (-not $PSCmdlet.ShouldProcess($orphanPath, 'Delete unmatched infected file')) {
                    continue
                }

                if ($quarantine) {
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($orphanPath)
                    $hash = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).Substring(0, 12)
                    Copy-Item -LiteralPath $orphanPath -Destination (Join-Path -Path $quarantine -ChildPath ('orphan_{0}_{1}.bad' -f $hash, [System.IO.Path]::GetFileName($orphanPath))) -Force
                }

                Remove-Item -LiteralPath $orphanPath -Force
                Write-RunLog -Message ('removed unmatched file {0}' -f $orphanPath)
            }
        }

        Write-RunLog -Message ('delete phase finished: deleted={0}; plan entries={1}; skipped because changed={2}' -f $deleted, $planMessage.Count, $skipped)
        Write-RunLog -Message 'Compact folders in mail clients, then re-run Scan mode to verify.' -Level 'WARN'
        return
    }

    #--------------------------------------------------------------------------
    # Scan / Plan mode: audit only.
    #--------------------------------------------------------------------------
    $capability = Test-AvpCapability -Avp $avp -RunDirectory $runDirectory -RunnerPreference $Runner
    $fileList = @(Get-MessageFile -Root $dataDirectory -NewerThanDays $SinceDays -WithQueue $IncludeQueue.IsPresent)
    Write-RunLog -Message ('selected .eml files: {0:N0}' -f $fileList.Count)

    if ($fileList.Count -eq 0) {
        Write-RunLog -Message 'Nothing to scan in the selected scope.'
        return
    }

    $skipHash = ($fileList.Count -gt 50000)

    if ($skipHash) {
        Write-RunLog -Message 'the scope exceeds 50000 files; the manifest is written without SHA-256 hashes for performance' -Level 'WARN'
    }

    $manifest = New-FileManifest -File ([object[]] $fileList) -Path (Join-Path -Path $runDirectory -ChildPath 'manifest-before.json') -SkipHash:$skipHash
    $pathList = [string[]] @($fileList | Select-Object -ExpandProperty FullName)
    $effectiveSize = Get-EffectiveBatchSize -Path $pathList -Requested $BatchSize -Scope $capability.Scope -Limit $MaxCommandLine

    Write-RunLog -Message ('scanning {0:N0} file(s) in batches of {1}; runner={2}; scope={3}; /RA={4}' -f
        $pathList.Count, $effectiveSize, $capability.Runner, $capability.Scope, $capability.UseReport)

    $batch = Invoke-BatchScan -Avp $avp -Path $pathList -Capability $capability -RunDirectory $runDirectory -Size $effectiveSize -Timeout $TimeoutMinutes
    Write-RunLog -Message ('batches executed: {0}; failed: {1}; batches with findings: {2}' -f $batch.BatchCount, @($batch.FailedBatch).Count, @($batch.DetectingBatch).Count)

    if (@($batch.FailedBatch).Count -eq $batch.BatchCount) {
        throw ('Every scan batch failed. Run -Mode Preflight and inspect {0}.' -f $runDirectory)
    }

    $aggregate = Join-Path -Path $runDirectory -ChildPath 'kaspersky-aggregated.txt'
    Set-Content -LiteralPath $aggregate -Value $batch.Text -Encoding utf8

    $statistic = Get-ReportStatistic -Text $batch.Text
    Write-RunLog -Message ('report statistics: processed={0}; ok={1}; detected={2}; suspicions={3}; skipped={4}; corrupted={5}; errors={6}' -f
        $statistic.Processed, $statistic.TotalOk, $statistic.Detected, $statistic.Suspicion, $statistic.Skipped, $statistic.Corrupted, $statistic.Errors)

    $detection = @(Get-Detection -Text $batch.Text -Root $dataDirectory)
    Write-RunLog -Message ('parsed message level detections: {0}' -f $detection.Count)

    if ($statistic.Detected -gt 0 -and $detection.Count -eq 0) {
        Write-RunLog -Message ('the report statistics claim {0} detected object(s) but no message path was parsed; inspect {1}' -f $statistic.Detected, $aggregate) -Level 'WARN'
    }

    # Coverage accounting: what was intended, what was scanned, what moved meanwhile.
    $unscanned = @(@($manifest) | Where-Object -FilterScript { -not $batch.ScannedPath.Contains((Get-NormalPath -Path ([string] $_.Path))) })
    $afterList = @(Get-MessageFile -Root $dataDirectory -NewerThanDays $SinceDays -WithQueue $IncludeQueue.IsPresent)
    $afterSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($item in $afterList) {
        $null = $afterSet.Add($item.FullName)
    }

    $vanished = @(@($manifest) | Where-Object -FilterScript { -not $afterSet.Contains([string] $_.Path) })

    $coverage = [pscustomobject]@{
        Intended      = @($manifest).Count
        Scanned       = $batch.ScannedPath.Count
        Unscanned     = $unscanned.Count
        VanishedAfter = $vanished.Count
        FailedBatches = @($batch.FailedBatch).Count
        Complete      = (($unscanned.Count -eq 0) -and (@($batch.FailedBatch).Count -eq 0))
    }

    Write-RunLog -Message ('coverage: intended={0}; scanned={1}; unscanned={2}; vanished during run={3}; failed batches={4}' -f
        $coverage.Intended, $coverage.Scanned, $coverage.Unscanned, $coverage.VanishedAfter, $coverage.FailedBatches)

    if (-not $coverage.Complete) {
        if (-not $AllowPartialCoverage) {
            Write-RunLog -Message 'Coverage is partial: some files were not scanned. Detections that were found remain valid, but the store is not fully audited.' -Level 'WARN'
            Write-RunLog -Message 'Pass -AllowPartialCoverage to accept partial coverage silently, or re-run for the unscanned paths listed in unscanned-files.json.' -Level 'WARN'
        }

        Write-JsonAtomic -Path (Join-Path -Path $runDirectory -ChildPath 'unscanned-files.json') -InputObject @($unscanned | Select-Object -Property Path, Length)
    }

    $matchedView = @()
    $orphanList = @()

    if ($detection.Count -gt 0) {
        $AdminPassword = Get-AdminSecret -Existing $AdminPassword
        $application = Connect-HMailApplication -Password $AdminPassword
        $matched = @(Get-HMailMatch -Application $application -Detection ([object[]] $detection))
        $matchedView = @($matched | Select-Object -Property Account, Folder, MessageId, Date, From, Subject, SizeKB, Verdict, InnerObject, Skipped, File)

        $matchedPath = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($item in $matchedView) {
            $null = $matchedPath.Add((Get-NormalPath -Path ([string] $item.File)))
        }

        # Detections with no owning message: usually leftovers of a crashed delivery.
        $orphanList = @($detection | Where-Object -FilterScript { -not $matchedPath.Contains((Get-NormalPath -Path ([string] $_.Path))) })
    }

    $plan = [pscustomobject]@{
        Schema          = $script:PlanSchema
        ToolVersion     = $script:ToolVersion
        Repository      = $script:RepositoryUrl
        CreatedUtc      = (Get-Date).ToUniversalTime().ToString('o')
        Mode            = $Mode
        DataDirectory   = $dataDirectory
        RunDirectory    = $runDirectory
        AvpPath         = $avp
        Capability      = [pscustomobject]@{ Runner = $capability.Runner; Scope = $capability.Scope; UseReport = $capability.UseReport }
        BatchSize       = $effectiveSize
        Statistics      = $statistic
        Coverage        = $coverage
        FailedBatch     = @($batch.FailedBatch)
        DetectingBatch  = @($batch.DetectingBatch)
        Detections      = @($detection | Select-Object -Property Path, Verdict, InnerObject, Detected, Skipped, Deleted, ReportLine)
        MatchedMessages = @($matchedView)
        Orphans         = @($orphanList | Select-Object -Property Path, Verdict, InnerObject)
    }

    $planFile = Join-Path -Path $runDirectory -ChildPath 'remediation-plan.json'
    Write-JsonAtomic -Path $planFile -InputObject $plan

    $csvFile = Join-Path -Path $runDirectory -ChildPath 'infected-messages.csv'

    if (@($matchedView).Count -gt 0) {
        $matchedView | Export-Csv -LiteralPath $csvFile -NoTypeInformation -Encoding utf8
    }
    else {
        # Always leave a CSV with a header, so downstream tooling has a stable contract.
        Set-Content -LiteralPath $csvFile -Value '"Account","Folder","MessageId","Date","From","Subject","SizeKB","Verdict","InnerObject","Skipped","File"' -Encoding utf8
    }

    if (-not $KeepBatchArtifacts -and $detection.Count -eq 0 -and @($batch.FailedBatch).Count -eq 0) {
        try {
            Remove-Item -LiteralPath $batch.BatchDirectory -Recurse -Force
            Write-RunLog -Message 'batch artefacts removed because the run produced no findings; use -KeepBatchArtifacts to retain them'
        }
        catch {
            Write-Debug ('batch artefacts not removed: {0}' -f $_.Exception.Message)
        }
    }

    Write-RunLog -Message ('detections={0}; matched messages={1}; unmatched files={2}' -f $detection.Count, @($matchedView).Count, @($orphanList).Count)
    Write-RunLog -Message ('plan: {0}' -f $planFile)
    Write-RunLog -Message ('csv: {0}' -f $csvFile)

    foreach ($item in @($matchedView)) {
        Write-RunLog -Message ('finding: {0} / {1} / id={2} / {3} / {4}' -f $item.Account, $item.Folder, $item.MessageId, $item.Verdict, $item.Subject)
    }

    if (@($orphanList).Count -gt 0) {
        Write-RunLog -Message 'Unmatched infected files are removed only in Delete mode with -DeleteOrphan.' -Level 'WARN'
    }

    if ($detection.Count -gt 0) {
        Write-RunLog -Message 'Review the plan and the CSV, then run Delete mode with -PlanPath to remediate.' -Level 'WARN'
    }
}
catch {
    $detail = 'FATAL: {0}{1}{2}' -f $_.Exception.Message, [System.Environment]::NewLine, $_.ScriptStackTrace

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
    if ($null -ne $application) {
        try {
            $null = [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($application)
        }
        catch {
            Write-Debug ('COM object not released: {0}' -f $_.Exception.Message)
        }
    }

    if ($null -ne $mutex) {
        if ($mutexHeld) {
            try {
                $mutex.ReleaseMutex()
            }
            catch {
                Write-Debug ('mutex not released: {0}' -f $_.Exception.Message)
            }
        }

        $mutex.Dispose()
    }

    Write-Information -MessageData ('elapsed: {0:hh\:mm\:ss}' -f ((Get-Date) - $started))
}

#endregion
