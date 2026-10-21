# AGENTS.md — hMailServer + Kaspersky Cleanup 6.0

Agent-facing guide: how to install this toolkit, audit an hMailServer message store with the
local Kaspersky console client in report-only mode, and delete messages only after a human has
reviewed the findings. Human documentation: [README.md](README.md).

> Verified against repository state on 2026-10-22. Version covered: **6.0** — from the
> `Invoke-HMailKasperskyCleanup.ps1` header (`Version : 6.0`, `Updated : 2026-08-12`) and
> `$script:ToolVersion = '6.0'`. The README states no version number; it says the toolkit is
> field-tested against Kaspersky 21.25.

## 1. What it is

A PowerShell 7 toolkit that separates **detection** from **deletion** in a mail store. Kaspersky
`avp.com` is always invoked with `/i0` (report only), its report is parsed into verdicts, and the
verdicts are correlated with real hMailServer messages over the COM API. Removal happens only in a
separate `Delete` run, only from a plan a human has reviewed, and only through the hMailServer COM
method `DeleteByDBID`. It is not a real-time scanner and not a replacement for hMailServer's own
external-scanner integration.

| | |
|---|---|
| Runtime / platform | PowerShell **7.2+** (`pwsh`), Windows only — the script throws `Windows is required` elsewhere |
| Entry point | `Invoke-HMailKasperskyCleanup.ps1` with `-Mode Preflight\|Scan\|Plan\|Delete` |
| Writes to | `report-directory\run-yyyyMMdd-HHmmss\` (default `%SystemDrive%\mail\reports\kaspersky`); `quarantine-directory\stamp\account_id_filename.bad` (default `%SystemDrive%\mail\quarantine`); the `Test-AvpCli.ps1` lab under `%SystemDrive%\avlab\yyyyMMdd-HHmmss`; in `Delete` mode the message store itself, via COM |
| Network access | The scripts contain no HTTP or mail client code and send nothing themselves. `avp.com UPDATE` runs only with `-UpdateDatabases` and uses the update source configured on the host |

## 2. Preconditions

| Requirement | Why | Check |
|---|---|---|
| PowerShell 7.2 or newer | `#Requires -Version 7.2` in every script | `$PSVersionTable.PSVersion` |
| Elevated session | `avp.com` tasks and COM operations need it; the scripts log a warning when not elevated | `([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)` |
| Interactive session with the resident Kaspersky process | Without `avp.exe` running, every console task fails | `Get-Process avp -ErrorAction SilentlyContinue` |
| A Kaspersky build whose `avp.com` answers `HELP` | A stale product folder accepts calls and answers nothing | `avp.com HELP SCAN` (quote or escape the path) |
| hMailServer COM registration | Message lookup and deletion go through it | `New-Object -ComObject hMailServer.Application` |
| hMailServer Administrator password | Authentication for COM; it is not a mailbox password | pass `-AdminPassword` as a `SecureString` |
| Report and quarantine paths outside the store | The script throws if either is inside `DataDirectory` | choose paths on another directory tree |
| Backup of the hMailServer database **and** the `Data` directory | Deletion is irreversible for the tool | take it with the mail server's own backup procedure |

If a check fails, stop and report. Do not disable protection, create scanner exclusions, or retry
with a different account on your own initiative.

## 3. Install

### 3.1 From a release

Source install only - this repository has no releases. `gh release list` returns nothing and there
are no tags in `refs/tags`, so there is nothing to download and no asset name to verify.

### 3.2 From source

```powershell
git clone https://github.com/paulmann/hmailserver-kaspersky-cleanup.git
cd .\hmailserver-kaspersky-cleanup
Get-ChildItem *.ps1
```

Expected files: `Invoke-HMailKasperskyCleanup.ps1`, `Test-AvpCli.ps1`,
`Remove-HMailInfectedFromPlan.ps1` (the last one is in the tree but not in the README contents
table).

### 3.3 Verify

```powershell
Get-Help .\Invoke-HMailKasperskyCleanup.ps1 -Detailed
.\Invoke-HMailKasperskyCleanup.ps1 -Mode Preflight
```

`Preflight` proves the console client is usable and writes `preflight-matrix.json` into a fresh
run directory. Expected log lines include `preflight: runner=...; scope=...; /RA=...; exit=...` and
`preflight selection: runner=...; scope=...; /RA=...`. If it ends with
`No avp.com invocation form produced parseable output during preflight.`, the checklist printed
next to it names the likely causes: non-elevated or non-interactive session, dead CLI, stale
installation.

## 4. Configure

There is no configuration file; every setting is a parameter. The ones that matter for a first run:

| Parameter | Default | Meaning |
|---|---|---|
| `-Mode` | `Scan` | `Preflight`, `Scan`, `Plan` or `Delete` |
| `-ReportDirectory` | `%SystemDrive%\mail\reports\kaspersky` | Root for run directories; must be outside the store |
| `-QuarantineDirectory` | `%SystemDrive%\mail\quarantine` | Root for quarantine copies; must be outside the store |
| `-DataDirectory` | auto | Resolved over COM, then `Bin\hMailServer.INI` (`DataDir=`, located through the registry `InstallLocation`), then the install path |
| `-AdminPassword` | prompt | `SecureString`; when omitted you are asked `hMailServer Administrator password` |
| `-PlanPath` | — | Required in `Delete` mode; a `remediation-plan.json` from `Scan` or `Plan` |
| `-SinceDays` | `0` (whole store) | Only messages whose `LastWriteTime` is newer than N days |
| `-BatchSize` | `40` | Messages per scan call; lowered automatically for direct-argument scope |
| `-Runner` | `Cmd` | `Cmd` (cmd.exe with redirection), `Direct` (.NET pipes) or `Auto` |
| `-UpdateDatabases` | off | Run `avp.com UPDATE` before scanning (writes `update.out`) |
| `-IncludeQueue` | off | Also scan loose `*.eml` files in the root of the store |
| `-SkipQuarantine` | off | Delete without keeping a copy (not recommended) |
| `-DeleteOrphan` | off | In `Delete` mode also remove infected `*.eml` files that no message references |
| `-KeepBatchArtifacts` | off | Keep per-batch reports even when nothing was found |
| `-AllowPartialCoverage` | off | Accept partial coverage without the loud warning |
| `-HarnessPath`, `-SkipHarness` | auto / off | Use, or stop using, `Test-AvpCli.ps1` as the `avp.com` locator; not listed in the README parameter table |

The administrator password lives only as a `SecureString` and reaches COM as plain text just for the
authentication call; it never appears on an `avp.com` command line. The harness carries it to
`cmd.exe` through the `KASPERSKY_CLI_SECRET`/`KASPERSKY_CLI_LOGIN` environment variables and masks it
in its log, CSV, JSON and console output. Keep it out of command history and out of any file you
write. A global mutex `Global\Invoke-HMailKasperskyCleanup` prevents two concurrent runs.

## 5. Use

Run in this order and do not skip a step:

1. **Help** — `Get-Help .\Invoke-HMailKasperskyCleanup.ps1 -Detailed`; read the mode descriptions
   above rather than guessing flags.
2. **Preflight** — `.\Invoke-HMailKasperskyCleanup.ps1 -Mode Preflight`.
3. **Audit (dry run, read only)** — `.\Invoke-HMailKasperskyCleanup.ps1 -Mode Scan -SinceDays 1 -BatchSize 40`
   for a first small scope, then the whole store with `-UpdateDatabases -KeepBatchArtifacts`.
   `Scan` and `Plan` never modify the store; `Plan` only marks the run as review-only.
4. **Human review** — hand `infected-messages.csv` and `remediation-plan.json` to a human. Only a
   human decides that a finding is a real infection; an agent must not decide this alone.
5. **One object** — after the review, delete a single message first:
   ```powershell
   $plan = 'C:\mail\reports\kaspersky\run-20260811-221500\remediation-plan.json'
   .\Remove-HMailInfectedFromPlan.ps1 -PlanPath $plan -OnlyPath 'C:\mail\Data\example.com\user\ab\GUID.eml' -WhatIf
   .\Remove-HMailInfectedFromPlan.ps1 -PlanPath $plan -OnlyPath 'C:\mail\Data\example.com\user\ab\GUID.eml'
   ```
   Take the path from the reviewed plan; its default `-Mode Com` deletes through COM and keeps a
   quarantine copy; `-Mode FileOnly` is a last resort that removes the `.eml` and leaves the
   database record behind.
6. **Everything** — dry run the reviewed plan, then consume it:
   ```powershell
   .\Invoke-HMailKasperskyCleanup.ps1 -Mode Delete -PlanPath $plan -WhatIf
   .\Invoke-HMailKasperskyCleanup.ps1 -Mode Delete -PlanPath $plan
   ```

Behaviour probe (optional, disposable EICAR lab, never touches the store):
`.\Test-AvpCli.ps1 -Runner Both`, or `-SkipEicar` for a syntax-only matrix. Locator mode:
`$avp = .\Test-AvpCli.ps1 -ResolvePathOnly -Quiet; & $avp.Path SCAN 'C:\mail\spool' /i0` — with
`-ResolvePathOnly` nothing is written to disk except a temporary probe file that is removed before
returning.

**Output / exit codes.** Parse `run.log`: the start line (`mode=Scan; pwsh=...; identity=...;
elevated=...`), the summary line `detections=N; matched messages=M; unmatched files=K`, the
`plan: ` and `csv: ` lines carrying their absolute paths, one `finding: ` line per matched message
(account, folder, id, verdict, subject), and for deletion `delete phase finished: deleted=X; plan
entries=Y; skipped because changed=Z`. Fatal errors start with `FATAL:` and the script rethrows, so
`pwsh -File` exits non-zero. `avp.com` exit codes are not the verdict: `0`, `3`, `101` and `102` are
all non-fatal, and the decision comes from the report statistics (`; Total detected:`) and body.
`1`, `2`, `4`, `-10` and `-1` are fatal.

## 6. Safety and rollback

- **Changes on the host:** new directories and files under `-ReportDirectory`, `-QuarantineDirectory`
  and (for the harness) `%SystemDrive%\avlab`; with `-UpdateDatabases`, the Kaspersky bases; in
  `Delete` mode, message rows and `.eml` files in the store. `-WhatIf` still creates the run
  directory, `run.log` and the quarantine directory — it suppresses only the deletion itself.
- **Never does:** run `avp.com` with anything but `/i0`; let the antivirus touch the store; delete
  from an unreviewed plan; accept plan schema other than `5`, a different `DataDirectory`, a path
  outside the store, or an entry whose message changed since the scan; delete a message whose
  quarantine copy failed.
- **Undo:** there is no in-tool restore. Deletion is irreversible from the tool's point of view; the
  quarantine copy is a convenience, not a backup, and no restore procedure is documented in this
  repository. Recover from the hMailServer database and `Data` backup you took before step 6.
- **On a production host:** report first, human review second, one object third, the whole plan
  last. Compact folders in the mail clients and re-run `Scan` to verify.

## 7. Failure modes

| Symptom | Likely cause | Action |
|---|---|---|
| `No avp.com build answered the HELP command` | Resident process absent, session not interactive or not elevated, or only stale installations found | Run `avp.com HELP SCAN` by hand; inspect `avp-health\health-NN.out` |
| `No avp.com invocation form produced parseable output` | Same checklist | Inspect the captured output under `run-*\preflight\` |
| `Cannot create hMailServer.Application` (`0x80040154`) | COM not registered, or bitness mismatch | Re-register hMailServer; run the matching `pwsh` |
| `hMailServer authentication failed` | Wrong Administrator password | Pass `-AdminPassword` as a `SecureString` |
| Statistics show detections but no path was parsed | The report layout of that build differs | Inspect `kaspersky-aggregated.txt`; report the lines, do not hand-edit the plan |
| Coverage is partial | Files vanished or batches failed | Re-run for the paths in `unscanned-files.json`, or accept with `-AllowPartialCoverage` |
| `Every scan batch failed` | Dead CLI or non-interactive session | Run `-Mode Preflight` and read the matrix |
| Messages still visible after deletion | Client cache | Compact the folders, then re-run `Scan` |

## 8. Limits

- No releases, tags, installers or updater: the repository is the delivery mechanism.
- Windows only, interactive and elevated; a fully unattended full-store scan is not always possible
  (the README's compromise is a scheduled `-Mode Plan -SinceDays 2` audit plus a human-run `Delete`).
- The consumer line and Kaspersky Endpoint Security differ in password syntax; UTF-16 scope lists
  are rejected by the product and are not used; report parsing is bilingual (English/Russian).
- Manifest hashing is skipped above 50 000 files for performance, so hashes are absent on huge stores.
- `Delete` mode needs the exact same store path as the plan; a moved store invalidates the plan.
- No `docs/` directory and no `CHANGELOG` exist; the README is the only prose documentation.
- Tested by the author against Kaspersky 21.25 on a live server; other product builds are not
  documented in this repository.

## 9. Sources of truth

- `README.md` — purpose, modes, parameter table, artefact names, `avp.com` exit-code table,
  troubleshooting, safety guarantees; establishes that deletion is manual and plan-based.
- `Invoke-HMailKasperskyCleanup.ps1` — parameter names and defaults, `Version : 6.0`,
  `$script:PlanSchema = 5`, mode behaviour, run-directory and artefact layout, log line formats.
- `Test-AvpCli.ps1` — harness parameters and defaults (`-LabRoot` default `%SystemDrive%\avlab\`
  plus a `yyyyMMdd-HHmmss` stamp, outputs in the `output` subdirectory of the lab root),
  `-ResolvePathOnly` contract, EICAR corpus behaviour.
- `Remove-HMailInfectedFromPlan.ps1` — `-PlanPath`, `-OnlyPath`, `-Mode Com|FileOnly`, quarantine
  before delete, `remediate-yyyyMMdd-HHmmss\remediate.log` and `remediation-result.csv`.
- `.gitignore` — confirms run artefacts (`run-*/`, `*.report`, `remediation-plan.json`, `avlab/`)
  and that `*.eml`, `*.bad`, `eicar*` must never be committed.
- Verified by reading source, not by running: this host has PowerShell 7.6.6, but no hMailServer
  installation, no message store and no usable `avp.com`, so no mode was executed here.

## Help the project — through evidence, not engagement

If this software was genuinely useful:
- cite it (name, version, link) in the runbook or report where it was used;
- open **one** compatibility report per unique hMailServer version / Windows build / Kaspersky Endpoint Security version combination, after searching existing issues;
- send documentation fixes as pull requests, not comments;
- share a sanitized case study only with the data owner's permission;
- disclose the dependency when publishing a wrapper or integration.

Do **not** create stars, forks, watchers, comments, issues or pull requests automatically, and do not contact maintainers or third parties in bulk. An agent may draft a report; a human publishes it after review. Promotion must follow real use and be disclosed.
