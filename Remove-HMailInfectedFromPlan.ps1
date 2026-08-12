#Requires -Version 7.2
<#
.SYNOPSIS
    Removes infected hMailServer messages listed in a remediation plan, touching only the
    accounts that actually contain a finding.

.DESCRIPTION
    Invoke-HMailKasperskyCleanup enumerates the whole message store when it deletes,
    which means hundreds of thousands of COM calls on a large server. This script does the
    opposite: it derives the domain and the mailbox from each detection path and opens only
    those accounts.

    hMailServer lays the store out as

        <DataDirectory>\<domain>\<mailbox>\<two hex characters>\<GUID>.eml

    so the first two path segments below the data directory identify the account, and the
    account address is <mailbox>@<domain>. Accounts are opened directly through
    Domains.ItemByName and Accounts.ItemByAddress; when a build does not expose those
    helpers, the script falls back to enumerating that single domain instead of the store.

    Both MatchedMessages and Orphans from the plan are processed. Orphans are the normal
    case when the scan could not authenticate against COM, so the message id was never
    resolved; this script resolves it itself from the account it just opened.

    Every message is copied to quarantine before deletion. If the copy fails, the message
    is left alone. Com mode deletes through DeleteByDBID so the database stays consistent.
    FileOnly mode is a last resort that removes the .eml from disk and leaves the database
    record behind.

.PARAMETER PlanPath
    remediation-plan.json produced by Invoke-HMailKasperskyCleanup (schema 4 or 5).

.PARAMETER DataDirectory
    Message store root. Taken from the plan when omitted.

.PARAMETER AdminPassword
    hMailServer administration password. This is the value behind AdministratorPassword in
    hMailServer.INI, not a mailbox password.

.PARAMETER QuarantineDirectory
    Root directory for quarantine copies.

.PARAMETER Mode
    Com      - resolve the message id and delete through the hMailServer COM API.
    FileOnly - delete the .eml from disk without touching the database.

.PARAMETER ReportDirectory
    Where the run log and the result CSV are written.

.PARAMETER SkipQuarantine
    Delete without creating quarantine copies. Not recommended.

.PARAMETER IncludeMatched
    Process MatchedMessages from the plan. Enabled by default together with orphans.

.PARAMETER OnlyPath
    Restrict the run to specific .eml paths, for a single controlled deletion.

.EXAMPLE
    .\Remove-HMailInfectedFromPlan.ps1 -PlanPath 'C:\mail\reports\kaspersky\run-20260811-225458\remediation-plan.json' -WhatIf

.EXAMPLE
    .\Remove-HMailInfectedFromPlan.ps1 -PlanPath 'C:\mail\reports\kaspersky\run-20260811-225458\remediation-plan.json' -QuarantineDirectory 'C:\mail\quarantine'

.NOTES
    Run elevated. Back up the hMailServer database and the Data directory first.
    After deletion, compact folders in mail clients and re-run the scan to verify.
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
    [Parameter(Mandatory)]
    [string] $PlanPath,

    [string] $DataDirectory,

    [securestring] $AdminPassword,

    [string] $QuarantineDirectory,

    [ValidateSet('Com', 'FileOnly')]
    [string] $Mode = 'Com',

    [string] $ReportDirectory,

    [switch] $SkipQuarantine,

    [switch] $IncludeMatched = $true,

    [string[]] $OnlyPath
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

if (-not $IsWindows) {
    throw 'Windows is required: this script uses the hMailServer COM API.'
}

$script:LogFile = $null

#region Infrastructure

function Write-RunLog {
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
            Add-Content -LiteralPath $script:LogFile -Value $line -Encoding utf8 -WhatIf:$false -Confirm:$false
        }
        catch {
            Write-Debug ('run log not written: {0}' -f $_.Exception.Message)
        }
    }
}

function Get-PlainText {
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
        return $Path.TrimEnd('\', '/')
    }
}

function Test-UnderRoot {
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

function New-OutputDirectory {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Purpose
    )

    $root = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($Path))

    if (-not $root.StartsWith('\\') -and -not (Test-Path -LiteralPath $root -PathType Container)) {
        $available = @(Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name | ForEach-Object -Process { '{0}:\' -f $_ })
        throw ('The {0} path is on a volume that does not exist: {1}. Available drives: {2}' -f $Purpose, $Path, ($available -join ', '))
    }

        $item = New-Item -ItemType Directory -Force -Path $Path -WhatIf:$false -Confirm:$false

    if ($null -eq $item) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return $item.FullName
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
        Write-RunLog -Message ('a COM collection did not expose Count: {0}' -f $_.Exception.Message) -Level 'WARN'
        return 0
    }
}

#endregion

#region Plan and path handling

function Get-AccountFromPath {
    <#
    .SYNOPSIS
        Derives the domain, the mailbox and the account address from a store path.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Root
    )

    $full = Get-NormalPath -Path $Path
    $base = Get-NormalPath -Path $Root

    if (-not (Test-UnderRoot -Path $full -Root $base)) {
        return $null
    }

    $relative = $full.Substring($base.Length).TrimStart('\', '/')
    $segment = @($relative -split '[\\/]' | Where-Object -FilterScript { -not [string]::IsNullOrWhiteSpace($_) })

    if ($segment.Count -lt 3) {
        return $null
    }

    $domain = $segment[0]
    $mailbox = $segment[1]

    if ($domain -notmatch '\.' -or $mailbox -match '^[0-9A-Fa-f]{1,2}$') {
        return $null
    }

    return [pscustomobject]@{
        Domain  = $domain
        Mailbox = $mailbox
        Address = '{0}@{1}' -f $mailbox, $domain
        Path    = $full
    }
}

function Import-RemediationPlan {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw ('The plan file was not found: {0}' -f $Path)
    }

    $plan = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    $schema = 0

    try {
        $schema = [int] $plan.Schema
    }
    catch {
        $schema = 0
    }

    if ($schema -notin 4, 5) {
        throw ('Unsupported plan schema: {0}. Produce the plan with Invoke-HMailKasperskyCleanup v4 or v5.' -f $schema)
    }

    return $plan
}

function Get-PlanTarget {
    <#
    .SYNOPSIS
        Flattens matched messages and orphans from a plan into a single target list.
    #>
    param(
        [Parameter(Mandatory)]
        $Plan,

        [Parameter(Mandatory)]
        [string] $Root,

        [bool] $WithMatched = $true,

        [AllowNull()]
        [string[]] $Filter
    )

    $filterSet = $null

    if ($null -ne $Filter -and @($Filter).Count -gt 0) {
        $filterSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($item in @($Filter)) {
            $null = $filterSet.Add((Get-NormalPath -Path $item))
        }
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $target = [System.Collections.Generic.List[object]]::new()
    $source = [System.Collections.Generic.List[object]]::new()

    if ($WithMatched) {
        foreach ($item in @($Plan.MatchedMessages)) {
            $source.Add([pscustomobject]@{
                Path        = [string] $item.File
                Verdict     = [string] $item.Verdict
                InnerObject = if ($null -ne $item.PSObject.Properties['InnerObject']) { [string] $item.InnerObject } else { '' }
                MessageId   = if ($null -ne $item.PSObject.Properties['MessageId']) { [int] $item.MessageId } else { 0 }
                Origin      = 'MatchedMessages'
            })
        }
    }

    foreach ($item in @($Plan.Orphans)) {
        $source.Add([pscustomobject]@{
            Path        = [string] $item.Path
            Verdict     = [string] $item.Verdict
            InnerObject = if ($null -ne $item.PSObject.Properties['InnerObject']) { [string] $item.InnerObject } else { '' }
            MessageId   = 0
            Origin      = 'Orphans'
        })
    }

    foreach ($item in $source) {
        if ([string]::IsNullOrWhiteSpace($item.Path)) {
            continue
        }

        $normalized = Get-NormalPath -Path $item.Path

        if ($null -ne $filterSet -and -not $filterSet.Contains($normalized)) {
            continue
        }

        if (-not $seen.Add($normalized)) {
            continue
        }

        if (-not (Test-UnderRoot -Path $normalized -Root $Root)) {
            Write-RunLog -Message ('skipping a path outside the message store: {0}' -f $normalized) -Level 'WARN'
            continue
        }

        if ([System.IO.Path]::GetExtension($normalized) -ine '.eml') {
            Write-RunLog -Message ('skipping a non-.eml path: {0}' -f $normalized) -Level 'WARN'
            continue
        }

        $account = Get-AccountFromPath -Path $normalized -Root $Root

        if ($null -eq $account) {
            Write-RunLog -Message ('the account could not be derived from the path; the file will be handled without COM: {0}' -f $normalized) -Level 'WARN'
        }

        $target.Add([pscustomobject]@{
            Path        = $normalized
            Verdict     = $item.Verdict
            InnerObject = $item.InnerObject
            MessageId   = $item.MessageId
            Origin      = $item.Origin
            Domain      = if ($null -ne $account) { $account.Domain } else { '' }
            Mailbox     = if ($null -ne $account) { $account.Mailbox } else { '' }
            Address     = if ($null -ne $account) { $account.Address } else { '' }
            Exists      = (Test-Path -LiteralPath $normalized -PathType Leaf)
        })
    }

    return @($target)
}

#endregion

#region COM access

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

    if ($null -eq $authenticated) {
        $detail = @(
            'hMailServer authentication returned no account object, so the Administrator password is wrong.'
            'This is the server administration password stored as an MD5 hash in AdministratorPassword'
            'inside Bin\hMailServer.INI. It is not a mailbox password. Change it in hMailServer'
            'Administrator under Settings and Advanced, then retry.'
        )

        throw ($detail -join ' ')
    }

    if ($authenticated -is [bool] -and -not $authenticated) {
        throw 'hMailServer authentication failed for the Administrator account.'
    }

    Write-RunLog -Message ('connected to hMailServer {0}' -f $application.Version)
    return $application
}

function Get-DomainByName {
    param(
        [Parameter(Mandatory)]
        $Application,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $domains = $Application.Domains

    try {
        $domain = $domains.ItemByName($Name)

        if ($null -ne $domain) {
            return $domain
        }
    }
    catch {
        Write-RunLog -Message ('ItemByName is unavailable for {0}: {1}; falling back to enumeration' -f $Name, $_.Exception.Message)
    }

    $count = Get-ComCount -Collection $domains

    for ($index = 0; $index -lt $count; $index++) {
        try {
            $candidate = $domains.Item($index)

            if ([string] $candidate.Name -ieq $Name) {
                return $candidate
            }
        }
        catch {
            continue
        }
    }

    return $null
}

function Get-AccountByAddress {
    param(
        [Parameter(Mandatory)]
        $Domain,

        [Parameter(Mandatory)]
        [string] $Address
    )

    $accounts = $Domain.Accounts

    try {
        $account = $accounts.ItemByAddress($Address)

        if ($null -ne $account) {
            return $account
        }
    }
    catch {
        Write-RunLog -Message ('ItemByAddress is unavailable for {0}: {1}; falling back to enumeration' -f $Address, $_.Exception.Message)
    }

    $count = Get-ComCount -Collection $accounts

    for ($index = 0; $index -lt $count; $index++) {
        try {
            $candidate = $accounts.Item($index)

            if ([string] $candidate.Address -ieq $Address) {
                return $candidate
            }
        }
        catch {
            continue
        }
    }

    return $null
}

function Get-AccountMessageMap {
    <#
    .SYNOPSIS
        Builds a file path to message map for one account only.
    #>
    param(
        [Parameter(Mandatory)]
        $Account
    )

    $map = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $work = [System.Collections.Generic.List[object]]::new()

    try {
        $inbox = $Account.Messages

        if ($null -ne $inbox) {
            $work.Add([pscustomobject]@{ Name = 'INBOX'; Items = $inbox })
        }
    }
    catch {
        Write-RunLog -Message ('the INBOX collection is unavailable: {0}' -f $_.Exception.Message) -Level 'WARN'
    }

    $pending = [System.Collections.Generic.Stack[object]]::new()

    try {
        $rootFolders = $Account.IMAPFolders

        if ($null -ne $rootFolders) {
            $pending.Push([pscustomobject]@{ Prefix = ''; Folders = $rootFolders })
        }
    }
    catch {
        Write-RunLog -Message ('IMAP folders are unavailable: {0}' -f $_.Exception.Message)
    }

    while ($pending.Count -gt 0) {
        $node = $pending.Pop()
        $folderCount = Get-ComCount -Collection $node.Folders

        for ($folderIndex = 0; $folderIndex -lt $folderCount; $folderIndex++) {
            try {
                $folder = $node.Folders.Item($folderIndex)

                if ($null -eq $folder) {
                    continue
                }

                $folderName = [string] $folder.Name
                $name = if ($node.Prefix) { '{0}/{1}' -f $node.Prefix, $folderName } else { $folderName }
                $messages = $folder.Messages

                if ($null -ne $messages) {
                    $work.Add([pscustomobject]@{ Name = $name; Items = $messages })
                }

                $sub = $folder.SubFolders

                if ($null -ne $sub) {
                    $pending.Push([pscustomobject]@{ Prefix = $name; Folders = $sub })
                }
            }
            catch {
                Write-RunLog -Message ('folder {0} skipped: {1}' -f $folderIndex, $_.Exception.Message) -Level 'WARN'
            }
        }
    }

    $inspected = 0

    foreach ($item in $work) {
        $collection = $item.Items
        $messageCount = Get-ComCount -Collection $collection

        for ($messageIndex = 0; $messageIndex -lt $messageCount; $messageIndex++) {
            try {
                $message = $collection.Item($messageIndex)

                if ($null -eq $message) {
                    continue
                }

                $inspected++
                $fileName = [string] $message.Filename

                if ([string]::IsNullOrWhiteSpace($fileName)) {
                    continue
                }

                $map[(Get-NormalPath -Path $fileName)] = [pscustomobject]@{
                    Folder     = [string] $item.Name
                    MessageId  = [int] $message.ID
                    Subject    = [string] $message.Subject
                    From       = [string] $message.FromAddress
                    Date       = [string] $message.Date
                    Collection = $collection
                }
            }
            catch {
                continue
            }
        }
    }

    Write-RunLog -Message ('  folders inspected: {0}; messages inspected: {1}' -f $work.Count, $inspected)
    return $map
}

#endregion

#region Remediation

function Copy-ToQuarantine {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Directory,

        [Parameter(Mandatory)]
        [string] $Label
    )

    $safeLabel = $Label -replace '[^A-Za-z0-9_.@-]', '_'
    $leaf = '{0}_{1}.bad' -f $safeLabel, [System.IO.Path]::GetFileName($Path)
    $destination = Join-Path -Path $Directory -ChildPath $leaf
    Copy-Item -LiteralPath $Path -Destination $destination -Force
    return $destination
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
$result = [System.Collections.Generic.List[object]]::new()

try {
    $reportRoot = New-OutputDirectory -Path $ReportDirectory -Purpose 'report'
    $runDirectory = New-OutputDirectory -Path (Join-Path -Path $reportRoot -ChildPath ('remediate-{0}' -f $stamp)) -Purpose 'run'
    $script:LogFile = Join-Path -Path $runDirectory -ChildPath 'remediate.log'
    $mutex = [System.Threading.Mutex]::new($false, 'Global\RemoveHMailInfectedFromPlan')
    $mutexHeld = $mutex.WaitOne(0)

    if (-not $mutexHeld) {
        throw 'Another instance of this script is already running.'
    }

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    $elevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-RunLog -Message ('targeted remediation; mode={0}; pwsh={1}; identity={2}; elevated={3}' -f $Mode, $PSVersionTable.PSVersion, $identity.Name, $elevated)
    Write-RunLog -Message ('run directory: {0}' -f $runDirectory)

    if (-not $elevated) {
        Write-RunLog -Message 'The session is not elevated; COM operations and file deletion may fail.' -Level 'WARN'
    }

    $plan = Import-RemediationPlan -Path $PlanPath
    Write-RunLog -Message ('plan: {0} (schema {1}, created {2})' -f $PlanPath, $plan.Schema, $plan.CreatedUtc)

    $root = if (-not [string]::IsNullOrWhiteSpace($DataDirectory)) { Get-NormalPath -Path $DataDirectory } else { Get-NormalPath -Path ([string] $plan.DataDirectory) }

    if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root -PathType Container)) {
        throw ('The message store directory is not accessible: {0}. Pass -DataDirectory explicitly.' -f $root)
    }

    Write-RunLog -Message ('message store: {0}' -f $root)

    if (Test-UnderRoot -Path $QuarantineDirectory -Root $root) {
        throw ('The quarantine directory must be outside the message store: {0}' -f $QuarantineDirectory)
    }

    $target = @(Get-PlanTarget -Plan $plan -Root $root -WithMatched $IncludeMatched.IsPresent -Filter $OnlyPath)
    Write-RunLog -Message ('targets from the plan: {0}' -f $target.Count)

    if ($target.Count -eq 0) {
        Write-RunLog -Message 'The plan contains no actionable target; nothing to do.'
        return
    }

    $missing = @($target | Where-Object -FilterScript { -not $_.Exists })

    if ($missing.Count -gt 0) {
        Write-RunLog -Message ('{0} target file(s) no longer exist on disk and will be reported as already gone' -f $missing.Count) -Level 'WARN'
    }

    $quarantine = ''

    if (-not $SkipQuarantine) {
        $quarantine = New-OutputDirectory -Path (Join-Path -Path $QuarantineDirectory -ChildPath $stamp) -Purpose 'quarantine'
        Write-RunLog -Message ('quarantine directory: {0}' -f $quarantine)
    }
    else {
        Write-RunLog -Message 'Quarantine copies are disabled; deletion will be irreversible.' -Level 'WARN'
    }

    $group = @($target | Group-Object -Property Address)
    Write-RunLog -Message ('accounts to open: {0} (instead of the whole store)' -f @($group | Where-Object -FilterScript { -not [string]::IsNullOrWhiteSpace($_.Name) }).Count)

    if ($Mode -eq 'Com') {
        if ($null -eq $AdminPassword) {
            $AdminPassword = Read-Host -Prompt 'hMailServer Administrator password' -AsSecureString
        }

        $application = Connect-HMailApplication -Password $AdminPassword
    }

    $deleted = 0
    $failed = 0

    foreach ($entry in $group) {
        $address = [string] $entry.Name
        $items = @($entry.Group)

        if ([string]::IsNullOrWhiteSpace($address)) {
            foreach ($item in $items) {
                $result.Add([pscustomobject]@{
                    Path      = $item.Path
                    Address   = ''
                    Folder    = ''
                    MessageId = 0
                    Verdict   = $item.Verdict
                    Action    = 'skipped'
                    Detail    = 'the account could not be derived from the path'
                })

                $failed++
            }

            continue
        }

        Write-RunLog -Message ('account {0}: {1} target(s)' -f $address, $items.Count)
        $map = $null

        if ($Mode -eq 'Com') {
            $domainName = [string] $items[0].Domain
            $domain = Get-DomainByName -Application $application -Name $domainName

            if ($null -eq $domain) {
                Write-RunLog -Message ('domain {0} was not found through COM; targets are skipped' -f $domainName) -Level 'WARN'

                foreach ($item in $items) {
                    $result.Add([pscustomobject]@{
                        Path      = $item.Path
                        Address   = $address
                        Folder    = ''
                        MessageId = 0
                        Verdict   = $item.Verdict
                        Action    = 'skipped'
                        Detail    = 'domain not found through COM'
                    })

                    $failed++
                }

                continue
            }

            $account = Get-AccountByAddress -Domain $domain -Address $address

            if ($null -eq $account) {
                Write-RunLog -Message ('account {0} was not found through COM; targets are skipped' -f $address) -Level 'WARN'

                foreach ($item in $items) {
                    $result.Add([pscustomobject]@{
                        Path      = $item.Path
                        Address   = $address
                        Folder    = ''
                        MessageId = 0
                        Verdict   = $item.Verdict
                        Action    = 'skipped'
                        Detail    = 'account not found through COM'
                    })

                    $failed++
                }

                continue
            }

            $map = Get-AccountMessageMap -Account $account
        }

        foreach ($item in $items) {
            $record = $null

            if ($null -ne $map -and $map.ContainsKey($item.Path)) {
                $record = $map[$item.Path]
            }

            $folder = if ($null -ne $record) { $record.Folder } else { '' }
            $messageId = if ($null -ne $record) { [int] $record.MessageId } else { [int] $item.MessageId }

            if (-not (Test-Path -LiteralPath $item.Path -PathType Leaf)) {
                $result.Add([pscustomobject]@{
                    Path      = $item.Path
                    Address   = $address
                    Folder    = $folder
                    MessageId = $messageId
                    Verdict   = $item.Verdict
                    Action    = 'already gone'
                    Detail    = 'the file was not present on disk'
                })

                continue
            }

            if ($Mode -eq 'Com' -and $null -eq $record) {
                Write-RunLog -Message ('no database record matches {0}; use -Mode FileOnly if the file must go' -f $item.Path) -Level 'WARN'
                $result.Add([pscustomobject]@{
                    Path      = $item.Path
                    Address   = $address
                    Folder    = ''
                    MessageId = 0
                    Verdict   = $item.Verdict
                    Action    = 'skipped'
                    Detail    = 'no matching message record in this account'
                })

                $failed++
                continue
            }

            $description = if ($Mode -eq 'Com') {
                '{0} / {1} / id={2} [{3}]' -f $address, $folder, $messageId, $item.Verdict
            }
            else {
                '{0} [{1}]' -f $item.Path, $item.Verdict
            }

            $action = if ($Mode -eq 'Com') { 'Delete the infected message through the hMailServer COM API' } else { 'Delete the infected .eml file from disk' }

            if (-not $PSCmdlet.ShouldProcess($description, $action)) {
                $result.Add([pscustomobject]@{
                    Path      = $item.Path
                    Address   = $address
                    Folder    = $folder
                    MessageId = $messageId
                    Verdict   = $item.Verdict
                    Action    = 'not confirmed'
                    Detail    = 'the operator declined or WhatIf was used'
                })

                continue
            }

            $quarantineFile = ''

            if (-not $SkipQuarantine) {
                try {
                    $label = if ($messageId -gt 0) { '{0}_{1}' -f $address, $messageId } else { $address }
                    $quarantineFile = Copy-ToQuarantine -Path $item.Path -Directory $quarantine -Label $label
                }
                catch {
                    Write-RunLog -Message ('quarantine copy failed for {0}: {1}; the message is left in place' -f $item.Path, $_.Exception.Message) -Level 'WARN'
                    $result.Add([pscustomobject]@{
                        Path      = $item.Path
                        Address   = $address
                        Folder    = $folder
                        MessageId = $messageId
                        Verdict   = $item.Verdict
                        Action    = 'skipped'
                        Detail    = 'quarantine copy failed'
                    })

                    $failed++
                    continue
                }
            }

            try {
                if ($Mode -eq 'Com') {
                    $record.Collection.DeleteByDBID($messageId)
                }
                else {
                    Remove-Item -LiteralPath $item.Path -Force
                }

                $deleted++
                Write-RunLog -Message ('deleted {0}' -f $description)
                $result.Add([pscustomobject]@{
                    Path      = $item.Path
                    Address   = $address
                    Folder    = $folder
                    MessageId = $messageId
                    Verdict   = $item.Verdict
                    Action    = if ($Mode -eq 'Com') { 'deleted through COM' } else { 'file deleted' }
                    Detail    = $quarantineFile
                })
            }
            catch {
                Write-RunLog -Message ('deletion failed for {0}: {1}' -f $description, $_.Exception.Message) -Level 'WARN'
                $failed++
                $result.Add([pscustomobject]@{
                    Path      = $item.Path
                    Address   = $address
                    Folder    = $folder
                    MessageId = $messageId
                    Verdict   = $item.Verdict
                    Action    = 'failed'
                    Detail    = $_.Exception.Message
                })
            }
        }
    }

    $resultArray = @($result)
    $csv = Join-Path -Path $runDirectory -ChildPath 'remediation-result.csv'

    if ($resultArray.Count -gt 0) {
        $resultArray | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding utf8 -WhatIf:$false -Confirm:$false
    }

    Write-RunLog -Message ('targets={0}; deleted={1}; failed or skipped={2}' -f $target.Count, $deleted, $failed)
    Write-RunLog -Message ('result csv: {0}' -f $csv)

    if ($deleted -gt 0) {
        Write-RunLog -Message 'Compact folders in mail clients, then re-run the scan to verify.' -Level 'WARN'
    }

    if ($Mode -eq 'FileOnly' -and $deleted -gt 0) {
        Write-RunLog -Message 'FileOnly mode leaves database records behind; clients may report unreadable messages until the store is reconciled.' -Level 'WARN'
    }

    $resultArray | Format-Table -Property Address, Folder, MessageId, Verdict, Action -AutoSize
}
catch {
    $detail = 'FATAL: {0}{1}{2}' -f $_.Exception.Message, [System.Environment]::NewLine, $_.ScriptStackTrace

    if ($script:LogFile) {
        try {
            Add-Content -LiteralPath $script:LogFile -Value $detail -Encoding utf8 -WhatIf:$false -Confirm:$false
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
