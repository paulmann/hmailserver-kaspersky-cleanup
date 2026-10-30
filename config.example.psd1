#
# config.example.psd1 - template for hMailServer + Kaspersky Kit.
#
# Copy to config.local.psd1 next to the scripts and edit. config.local.psd1 is ignored by git,
# so updating the toolkit with `git pull` never overwrites your settings.
#
# Every value below has a neutral default: the scripts only need the entries you actually use.
#
@{
    Kit = @{
        # Where the kit copies itself on install and writes its own state.
        InstallDirectory = 'C:\ProgramData\hMailKaspersky\kit'
        LogDirectory     = 'C:\ProgramData\hMailKaspersky\logs'
        StateDirectory   = 'C:\ProgramData\hMailKaspersky\state'
    }

    hMailServer = @{
        ServiceName = 'hMailServer'
        # Empty: the cleanup tool resolves the store over COM, then hMailServer.INI, then the install path.
        DataDirectory = ''
        TempDirectory = 'C:\Program Files (x86)\hMailServer\Temp'
        AdminUser     = 'Administrator'
        # Machine-scope DPAPI blob with the hMailServer administrator password (Set-KitStoredCredential).
        CredentialFile = 'C:\ProgramData\hMailKaspersky\hmail.cred.machine.bin'
    }

    Kaspersky = @{
        ProductRoot = 'C:\Program Files (x86)\Kaspersky Lab'
        AvpFileName = 'avp.com'
        # "Password protection" login used by EXPORT/IMPORT only. SCAN and UPDATE reject these parameters.
        Login = 'KLAdmin'
        CredentialFile = 'C:\ProgramData\hMailKaspersky\kladmin.cred.machine.bin'
        # Published path: registry key under HKLM plus a machine environment variable.
        RegistryKey = 'SOFTWARE\hMailServerKav'
        EnvironmentVariable = 'KAV_AVP_PATH'
    }

    Scanner = @{
        # The real-time scanner copies the message here first: scanning files inside Program Files
        # through a direct argument is unreliable (paths with spaces), snapshots are not.
        SnapshotDirectory = ''
        ReportsDirectory  = 'C:\ProgramData\hMailKaspersky\reports\realtime'
        DetectionsDirectory = 'C:\ProgramData\hMailKaspersky\reports\realtime\detections'
        TimeoutSeconds = 120
        MaxSnapshotMb  = 64
        # hMailServer treats exit code 2 as "infected" and blocks/quarantines the message.
        ExitCodeOnDetection = 2
        KeepSnapshots = $false
    }

    Nightly = @{
        SinceDays        = 2
        BatchSize        = 40
        TimeoutMinutes   = 20
        UpdateDatabases  = $true
        QuarantineDirectory = 'C:\ProgramData\hMailKaspersky\quarantine'
        ReportsDirectory    = 'C:\ProgramData\hMailKaspersky\reports'
        # Empty: the cleanup tool is looked up next to the kit scripts.
        CleanupToolPath  = ''
        # Delete confirmed infected messages through hMailServer COM after the scan.
        # Keep it false until you have reviewed at least one plan yourself.
        AutoRemediate    = $false
        DryRun           = $false
    }

    Maintenance = @{
        UpdateTime        = '06:05'
        RebootTimes       = @('06:15', '06:40')
        RebootDelaySeconds = 180
        # Reboot only when the system (or Kaspersky) actually asks for it.
        RebootOnPendingOnly = $true
        RebootSkipWhileScanning = $true
    }

    Tasks = @{
        Nightly     = 'hMailKasperskyNightly'
        PathRefresh = 'hMailKasperskyPathRefresh'
        Update      = 'KasperskyUpdateWindow'
        Reboot      = 'MailServerRebootWindow'
    }

    Logging = @{
        # DEBUG, INFO, WARN, ERROR
        Level = 'INFO'
        RetentionDays = 30
    }
}
