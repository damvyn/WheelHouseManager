# Wheelhouse Manager

Wheelhouse Manager gives locked-down Windows computers a **private, audited source of Python
packages**. Instead of installing from the internet (PyPI), clients install only from a shared
folder of pre-approved wheel files - the *wheelhouse*. The manager decides what goes into that
folder, checks every package before it gets there, and keeps checking it afterwards.

What it does for you:

- **Adds packages safely.** You name the packages you need; the manager resolves every
  dependency for your target Python version and platform, and lets a package in only after it
  passed every check: denylist, known vulnerabilities (OSV and PyPI advisories), a cooldown
  period for brand-new releases, PyPI's "yanked" flag, a hash comparison with what PyPI
  publishes, and a Microsoft Defender scan.
- **Keeps watching what is already published.** A package that was clean when it was added can
  become vulnerable, yanked or detected as malware later. A weekly check finds that, rates each
  vulnerability (Critical / High / Medium / Low, from OSV), gives it a fix-by date, and alerts
  when something is new, overdue or resolved - not the same list every week. You can accept a
  risk for a limited time (a *waiver*).
- **Lets you act quickly.** Quarantine (reversible) or delete a package, block versions on a
  denylist, restore from quarantine, or fast-track an urgent security fix.
- **Gives you a web UI** on the manager server for all of the above, plus email (or HTML file)
  alerts, a history of every package version (who added, quarantined or restored it, and when
  its audit or scan result changed) and a full audit trail of reports and logs.

Contents

1. [How it works](#1-how-it-works)
2. [Requirements](#2-requirements)
3. [Installation](#3-installation)
4. [Configuration](#4-configuration)
5. [Using it: step-by-step guides](#5-using-it-step-by-step-guides)
6. [The web UI](#6-the-web-ui)
7. [Script reference](#7-script-reference)
8. [Alerts, reports and logs](#8-alerts-reports-and-logs)
9. [Exit codes](#9-exit-codes)
10. [Troubleshooting](#10-troubleshooting)
11. [Security](#11-security)
12. [Limitations](#12-limitations)
13. [For developers](#13-for-developers)

---

## 1. How it works

### The two parts

| Part | Runs on | What it does |
|---|---|---|
| **Client install** (`Client Install\`) | Every client computer | Installs `uv` and configures it, through Group Policy, so the wheelhouse is its **only** package source. Users cannot change this. |
| **Manager** (`Setup.ps1`, `whm.ps1`, `Jobs\`) | One manager / build server | Prepares, checks, publishes and monitors the wheelhouse. Has the web UI. |

The two parts only share the wheelhouse folder: the manager writes it, clients read it.

```
  You                      Manager server                                 Wheelhouse share         Clients
  ---                      --------------                                 ----------------         -------
  requirements.in  --->  resolve (uv) ---> review ---> checks + publish  --->  *.whl            ---> uv pip install ...
  ("numpy", "pandas>=2")  requirements.txt              (see below)            requirements-N.txt
                                                                               manifest.json
                         weekly check (Scheduled Task) <-- re-checks everything published
                         web UI (localhost)
```

### The life of a package

1. **Requested.** You add `numpy` (or `pandas>=2`) to `Input\requirements.in`, by hand or in the
   UI.
2. **Resolved.** `Update-Requirement.ps1` turns that into exact pins (`numpy==2.3.1` plus every
   dependency) in `Input\requirements.txt`, using only versions that have a wheel for your target
   Python and platform and that are older than the cooldown.
3. **Reviewed.** You (or whoever approves changes) read `requirements.txt`.
4. **Checked and published.** `Update-Wheelhouse.ps1` takes each new pin through these checks,
   in order. A package that fails one is **rejected with the reason** and never reaches the
   wheelhouse; the others carry on:

   | Check | Rejected when |
   |---|---|
   | Denylist | The name/version is blocked (`config\denylist.json`). |
   | Vulnerability audit | `pip-audit` (OSV and PyPI) knows a vulnerability, or the audit could not be completed. |
   | Yanked | The release was withdrawn ("yanked") on PyPI. |
   | Cooldown | The release is newer than `MinimumPackageAgeDays` (default 10). The reason says when it becomes eligible. |
   | Download | No wheel exists for the target Python / platform. |
   | Verification | The downloaded file is not one PyPI lists for the release, its sha256 differs from PyPI's, or the file itself is yanked or newer than the cooldown. |
   | Defender | Microsoft Defender detects something in the download. |

   Downloads wait in a staging folder on the manager server until they passed everything. Only
   then are they copied to the share, so clients never see an unchecked file.
5. **Published.** The wheel is in the wheelhouse, recorded with its SHA256 in `manifest.json`, and
   its pin is listed in a group file. Clients can install it. The package catalog
   (`catalog.json`) marks the version *Published* and its history records who published it.
6. **Monitored.** Every week `Test-Wheelhouse.ps1` re-checks everything that is published:
   files unchanged (hash), new vulnerabilities, yanked on PyPI since, denylisted since, and -
   wheels the file server's antivirus removed or changed. Every result is recorded in the catalog -
   the UI shows it, and a change (for example *Passed* -> *Vulnerable*) appears in the package's
   history.
7. **Flagged (if a vulnerability appears).** Each vulnerability becomes a *finding* with a
   severity and a fix-by date (Critical 3 days, High 7, Medium 30, Low 90 - adjustable). The alert
   goes out once when it is new, again when it becomes **overdue** (then weekly as a reminder), and
   once when it is resolved. If you decide the risk is acceptable, you can **waive** that one
   advisory for that one version until a date (at most 90 days); it is alerted again when the
   waiver ends.
8. **Taken out (if needed).** You quarantine or delete the package. Its pin is removed and the
   version is denylisted so it is not downloaded again. Quarantine can be undone.

**Findings are not acted on automatically** - a package flagged as vulnerable, yanked or
denylisted stays installable until an administrator acts on the alert. The exceptions, all under
the `AutoQuarantine` switch (on by default) and all alerted:

- a wheel that was **removed or changed on the share** by something else, typically the file
  server's antivirus: a missing wheel is taken out of the group files and the manifest, a changed
  one is quarantined as evidence, and both are denylisted;
- a published version that OSV lists as a **malicious package** (advisory `MAL-...`) is
  quarantined and denylisted;
- wheel files that appear in the share **without having been published by the manager** (copied
  in by hand) are moved to `<wheelhouse>\_untracked\`, where clients cannot see them.

If the weekly check stops running, the UI shows a warning and `Update-Wheelhouse.ps1` logs one; a
version whose audits have not completed for `AuditFreshnessDays` (8) is alerted as *Unverified*.

**Virus scanning of the share is not this tool's job** - the file server's own antivirus does
that. This manager scans every *new* download with Microsoft Defender before it is published, and
can scan published wheels on demand (from hash-checked local copies).

### Key terms

| Term | Meaning |
|---|---|
| **Wheelhouse** | The shared folder of `.whl` files clients install from (a UNC path such as `\\server\share\wheelhouse`). |
| **Pin** | An exact `name==version`, e.g. `numpy==2.3.1`. |
| **Group file** | `requirements-1.txt`, `requirements-2.txt`, ... in the wheelhouse. Each lists pins; one file never holds two versions of the same package, so a second version of a package goes into another group. The manager uses them to audit what is published. |
| **Manifest** | `manifest.json` in the wheelhouse: every published wheel with its SHA256. Any change to a wheel is detected. |
| **Cooldown** | Minimum age of a release before it is accepted (`MinimumPackageAgeDays`). Protects against freshly published malicious or broken releases. |
| **Denylist** | `config\denylist.json`: versions (or `*` for all versions) that must never enter the wheelhouse. |
| **Quarantine** | `<wheelhouse>\_quarantine\`: removed packages kept for later restore. |
| **Catalog** | `catalog.json` in the wheelhouse: each package version's state (*Published*, *Quarantined*, *Removed*) and its latest audit, Defender and PyPI results. Rebuilt automatically from the other files if it is missing. |
| **History** | `events.jsonl` in the wheelhouse: who did what to which version, and when a check result changed. |
| **Finding** | One vulnerability advisory reported for one published version, with its severity, fix-by date and alert status. |
| **Overdue** | A finding still open after its fix-by date. |
| **Waiver** | An accepted risk: one advisory, one exact version, until a date (`config\waivers.json`). Waived findings are not alerted. |
| **Unverified** | A published version whose audits have not completed for `AuditFreshnessDays` - its status is no longer known to be current. |

---

## 2. Requirements

**Manager server** (Windows):

- Windows PowerShell 5.1 or PowerShell 7.
- Python matching the clients' target version (default 3.14), with `pip`. `pip-audit` is
  installed automatically if missing.
- `uv` (used only to resolve requirements): `python -m pip install --upgrade uv`.
- Write access to the wheelhouse share.
- Network access to `pypi.org` and `files.pythonhosted.org` (metadata and downloads) and
  `api.osv.dev` (vulnerability data).
- **Administrator rights for Microsoft Defender scans** (`Start-MpScan`). Everything else works
  without elevation; without it, downloads are published with a warning instead of being scanned
  (see `RequireDefenderScanAtIntake`).
- Optional: an SMTP relay for email alerts. Without one, alerts are saved as HTML files.

**Clients** (Windows): a deployment tool for `UV_Installer.ps1`, Group Policy for
`Startup_UV.ps1`, and read access to the wheelhouse share. Python itself must already be
installed on the clients (uv is not allowed to download interpreters).

---

## 3. Installation

### 3.1 Prepare the manager server

```powershell
python -m pip install --upgrade pip
python -m pip install --upgrade uv pip-audit
python --version; uv --version; pip-audit --version
```

The manager keeps `pip` and `pip-audit` up to date itself on every run; it does not update `uv`.

### 3.2 Deploy the manager - `Setup.ps1`

From a copy of this repository:

```powershell
.\Setup.ps1 -WheelhousePath "\\server\share\wheelhouse"

# Another destination (default: C:\WheelHouseManager)
.\Setup.ps1 -DestinationPath "D:\WheelHouseManager" -WheelhousePath "\\server\share\wheelhouse"

# Also register the weekly check (asks for the account's password)
.\Setup.ps1 -WheelhousePath "\\server\share\wheelhouse" -RegisterScheduledTask -TaskDays Sunday -TaskTime 02:00
```

`Setup.ps1` is safe to re-run - do so to deploy a newer version. It always replaces the code in
`Jobs\`, but never overwrites your settings, denylist or `Input\` files. At the end it checks the
installation (`whm doctor`, see [5.0](#50-whm---one-command-for-everything)) and lists anything
still missing - the wheelhouse share not writable, Python or uv not found, PyPI or OSV not
reachable, the weekly check not scheduled, no mail server - each with what to do.

Result:

```
C:\WheelHouseManager\
    whm.ps1                         one command for everything (whm help)
    Jobs\                           the scripts and the WheelhouseManager module (keep together)
    config\
        settings.psd1               your settings
        denylist.json               blocked packages (created on first use)
    Input\
        requirements.in             what you ask for
        requirements.txt            resolved pins, waiting to be published
    staging\                        downloads waiting for their checks (emptied after each run)
    logs\ui\                        output of jobs started from the web UI
```

The wheelhouse share gets `manifest.json`, `catalog.json`, `events.jsonl`, `advisories.json`, the
group files, `reports\` and `_quarantine\` as they are needed. After an upgrade from a version without a
catalog, the first run that changes or checks the wheelhouse creates `catalog.json` from what is
there (including the latest audit and scan results); nothing needs to be done by hand.

### 3.3 Schedule the weekly check - `Test-Wheelhouse.ps1`

This is the job that notices when a published package fails a check later. It never downloads
anything, so it is safe to run unattended.

**From the UI (easiest):** **Schedule** tab -> *Weekly check (Scheduled Task)*: choose the days and
time, enter the account (`DOMAIN\user`) and its password, and click **Register the task**. The card
then shows the task's state, last run with its result, next run and when a check last completed;
**Run now** starts it at once, **Remove the task** deletes it. The password goes to Windows Task
Scheduler only - the manager does not store or log it. Registering a task for another account
than your own needs the UI started as administrator. If the wheelhouse folder is set to a mapped
drive (`Z:\`), the card warns you and offers to switch to the UNC path: a Scheduled Task does not
see the drive mappings of your session.

**Or with PowerShell:**

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\WheelHouseManager\Jobs\Test-Wheelhouse.ps1"'
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2:00AM
$principal = New-ScheduledTaskPrincipal -UserId "DOMAIN\svc-wheelhouse" -LogonType Password
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable

Register-ScheduledTask -TaskName "Wheelhouse Weekly Check" `
    -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description "Weekly wheelhouse integrity, vulnerability, yanked and denylist check with alerts."
```

Or in the Task Scheduler GUI: **Create Task** -> *Run whether user is logged on or not* -> weekly
trigger -> action `powershell.exe` with the arguments above -> under Settings, *Run task as soon
as possible after a scheduled start is missed*.

The account needs network access and read/write access to the share (to take out wheels the file
server's antivirus removed). No administrator rights are needed. Virus scanning of the share is
left to the file server's own antivirus.

Task Scheduler's *Last Run Result*: `0` all good, `1` findings (an alert was sent), `2` a check
could not be completed (also alerted) - see [Exit codes](#9-exit-codes).

### 3.4 Set up the clients

**`Client Install\UV_Installer.ps1`** - deploy it as a normal application package (e.g. with
your software deployment tool), with `uv-x86_64-pc-windows-msvc.zip` next to it. It extracts uv
to `C:\Program Files\astral.sh\uv` and creates hardlinks for `uv.exe`, `uvw.exe` and `uvx.exe` in
`C:\Windows\System32` (already on everybody's `PATH`). It skips the install if the same version is
already there and logs to `%WinDir%\Logs\Astral-uv-<version>_Script.txt`.

**`Client Install\Startup_UV.ps1`** - a Group Policy **computer startup script**. It runs as
SYSTEM before anyone logs on, so users cannot override it. It sets, for the whole machine:

| Setting | Value | Purpose |
|---|---|---|
| `UV_PYTHON_DOWNLOADS` | `never` | uv may not download Python interpreters |
| `UV_PYTHON_PREFERENCE` | `only-system` | Only pre-installed Python is used |
| `UV_LINK_MODE` | `copy` | Cache and virtual environments are on different drives (local cache vs. roaming profile) |
| `UV_CACHE_DIR` | `C:\uv-cache` | Local cache, not on the roaming profile |
| `UV_NO_INDEX` | `true` | PyPI is blocked |
| `%ProgramData%\uv\uv.toml` | flat index at the wheelhouse | The **only** package source |

Steps:

1. Edit the placeholder in `Startup_UV.ps1` - replace `\\server\pathToWheelHouse` in
   `'url = "\\\\server\\pathToWheelHouse"'` with your wheelhouse UNC path (backslashes doubled).
2. In Group Policy Management, edit a GPO linked to the clients' OU: **Computer Configuration >
   Policies > Windows Settings > Scripts (Startup/Shutdown) > Startup > PowerShell Scripts**, add
   `Startup_UV.ps1`.
3. Make sure `UV_Installer.ps1` is deployed to the same machines.
4. On a test client, run `gpupdate /force` (or reboot), then check:
   ```powershell
   Test-Path "C:\Windows\System32\uv.exe"
   $env:UV_NO_INDEX
   Get-Content "$env:ProgramData\uv\uv.toml"
   ```

Users then install packages as usual, for example `uv venv` and `uv pip install numpy`; uv only
sees the wheels in the wheelhouse.

To install a known-good, already audited set in one go, users can also point uv at one of the
group files on the share:

```powershell
uv pip install -r \\server\share\wheelhouse\requirements-2.txt
```

Each group file lists exact versions that were checked together. Pick the group that has the
versions your project needs (a second version of a package lives in a different group, see
[5.3](#53-keep-several-versions-of-one-package)). Group files only list pins whose wheel is in the
wheelhouse, so such an install never fails for a missing file. A package that is later
quarantined or deleted is removed from its group file too.

**What is in the wheelhouse - for everyone.** The manager keeps a read-only page on the share,
`\\server\share\wheelhouse\index.html`, up to date: every available package and version and the
group files that list it, the versions **not to use** (vulnerable, overdue, yanked, quarantined)
with the version to install instead, how to install, and when the wheelhouse was last checked.
It is plain HTML without scripts, so it opens straight from the share; send your users the link.

**Optional - check an environment on a client.** `Client Install\Test-PythonEnvironment.ps1`
(a separate script; `Startup_UV.ps1` is unchanged) tells a user whether anything installed in an
environment has since been found vulnerable, yanked, quarantined or removed, and what to install
instead. It works offline: it reads `advisories.json` from the wheelhouse share - found through
the machine-wide uv configuration - and the environment's package list.

```powershell
.\Test-PythonEnvironment.ps1                              # the .venv in the current folder
.\Test-PythonEnvironment.ps1 -Project C:\Work\analysis    # another project's .venv
.\Test-PythonEnvironment.ps1 -Python C:\envs\x\Scripts\python.exe
```

Exit code 0 nothing affected, 1 something affected, 2 the check could not run. Copy it to the
clients the way you deploy other tools (it needs nothing else from this repository).

---

## 4. Configuration

Settings live in `C:\WheelHouseManager\config\settings.psd1` and can be edited by hand or in the
UI's **Settings** tab (which validates them). Every script parameter falls back to this file, so
you rarely need to pass parameters. Order of precedence: **a parameter you pass** > **the
settings file** > **the built-in default**. A key missing from the file uses its default.

| Setting | Default | What it controls |
|---|---|---|
| `WheelhousePath` | (none - required) | The wheelhouse share, e.g. `\\server\share\wheelhouse`. |
| `RequirementsInPath` | `Input\requirements.in` | What you ask for. |
| `LocalRequirementsPath` | `Input\requirements.txt` | The resolved pins that `Update-Wheelhouse.ps1` publishes. |
| `PythonVersion` | `3.14` | Target Python version of the clients. |
| `Platform` | `win_amd64` | Target platform (`win_amd64`, `win_arm64`, `win32`). |
| `MinimumPackageAgeDays` | `10` | Cooldown: minimum age of a release before it is accepted. |
| `VulnerabilityServices` | `osv`, `pypi` | Vulnerability databases used by every audit. |
| `ReportRetentionMonths` | `6` | Logs, reports and saved alerts older than this are deleted. |
| `SmtpServer` | (empty) | SMTP relay (`host` or `host:port`). Empty: alerts are saved as HTML files instead of emailed. |
| `MailTo` / `MailFrom` | `servicedesk@company.com` / `NoReply@company.com` | Alert recipient and sender. |
| `RequireDefenderScanAtIntake` | `$false` | When a download cannot be scanned (not elevated, Defender missing): `$false` publishes with a warning, `$true` rejects it. A detection always rejects. |
| `AutoQuarantine` | `$true` | A published wheel that disappeared from the share (e.g. moved to the file server antivirus' quarantine) is taken out of the group files and denylisted; one whose content changed is quarantined as evidence. The same switch quarantines a published version with a malicious-package advisory (`MAL-...`) and moves wheels nobody published to `_untracked\`. `$false`: only reported, and updates stop on a missing/changed wheel until someone acts. Override per run with `-AutoQuarantine On|Off`. An alert is sent either way. |
| `DueDaysCritical` / `DueDaysHigh` / `DueDaysMedium` / `DueDaysLow` | `3` / `7` / `30` / `90` | Days a vulnerability of that severity may stay open before it is overdue. An advisory without a published severity counts as High. |
| `WaiverMaxDays` | `90` | Longest allowed waiver. |
| `AuditFreshnessDays` | `8` | A published version without a completed audit for this long is alerted as *Unverified*; the UI warns when the weekly check has not completed for this long. |
| `OverdueReminderDays` | `7` | How often an overdue vulnerability is alerted again. |
| `EventLog` | `$false` | Also write run results and actions to the Windows Event Log (Application, source `WheelhouseManager`) - see [8](#8-alerts-reports-and-logs). Turn on with `Setup.ps1 -EnableEventLog` (as administrator, once). |
| `ApprovalMode` | `SamePersonAllowed` | Who may approve a resolved `requirements.txt` or a fix before it is published. `SamePersonAllowed`: anyone, also the requester (publishing approves; recorded). `SeparateApprover`: another account than the requester. |

Example:

```powershell
@{
    WheelhousePath               = '\\server\share\wheelhouse'
    PythonVersion                = '3.14'
    Platform                     = 'win_amd64'
    MinimumPackageAgeDays        = 10
    VulnerabilityServices        = @('osv', 'pypi')
    SmtpServer                   = 'smtp.company.local'
    MailTo                       = 'python-admins@company.com'
    RequireDefenderScanAtIntake  = $true
    AutoQuarantine               = $true
}
```

---

## 5. Using it: step-by-step guides

All commands assume `cd C:\WheelHouseManager\Jobs` unless noted. Each guide also says how to do
it in the [web UI](#6-the-web-ui).

### 5.0 whm - one command for everything

`C:\WheelHouseManager\whm.ps1` covers the everyday work; the scripts in `Jobs\` keep working as
before (whm runs them, with the same options).

```powershell
cd C:\WheelHouseManager
.\whm.ps1 status                   # what needs attention now
.\whm.ps1 doctor                   # check the installation end to end
.\whm.ps1 list -Vulnerable         # published packages with their audit status
.\whm.ps1 info requests            # one package: state, vulnerabilities, history
.\whm.ps1 resolve                  # requirements.in -> requirements.txt
.\whm.ps1 approve                  # approve the current proposal (or: whm reject <reason>)
.\whm.ps1 publish                  # check and publish it
.\whm.ps1 fix requests==2.19.0     # prepare the fix of a vulnerable version
.\whm.ps1 quarantine six==1.16.0 -Reason "not needed"
.\whm.ps1 waive attrs==23.1.0 GHSA-xxxx 30 "code path not used"
.\whm.ps1 check                    # the weekly check now
.\whm.ps1 schedule                 # the weekly check's Scheduled Task
.\whm.ps1 ui                       # the web UI
.\whm.ps1 help                     # every command
```

`status` and `doctor` exit with 0 (all good), 1 (something to review) or 2 (act now).

### 5.1 Add packages (the normal workflow)

1. **Ask for packages.** Add one requirement per line to `Input\requirements.in` - a name
   (`numpy`) or a range (`pandas>=2.0`). Keep everything you have ever asked for in the file; it
   is the full list, not just the new lines.
2. **Resolve them.**
   ```powershell
   .\Update-Requirement.ps1
   ```
   This writes `Input\requirements.txt` with exact pins for every package and dependency. If a
   package has no wheel for your Python/platform, nothing is changed: the problem packages are
   listed, the attempt is saved as `Input\requirements.rejected.txt`, and you fix
   `requirements.in` (remove the package or constrain its version) and run it again.
3. **Review and approve.** Resolving records a **proposal** for exactly this `requirements.txt`
   (who requested it, when; `Input\proposal.json`, history in `Input\proposal-history.jsonl`).
   Only an approved proposal is published. Who may approve depends on `ApprovalMode`:
   - `SamePersonAllowed` (default): anyone, including the requester - publishing approves it, and
     the publisher is recorded as the approver.
   - `SeparateApprover`: another account than the requester must approve it first (UI: **Add
     packages** -> **Approve**). Until then `Update-Wheelhouse.ps1` stops with exit code 1 and
     changes nothing.

   A rejected proposal is never published; change `requirements.in` and resolve again. If you
   edit `requirements.txt` by hand, it no longer matches its proposal: with `SamePersonAllowed`
   publishing proposes and approves it as you; with `SeparateApprover` propose it again (UI:
   **Propose this requirements.txt**) and have it approved.
4. **Publish.**
   ```powershell
   .\Update-Wheelhouse.ps1
   ```
   Pins already in the wheelhouse are skipped. Each new pin goes through every check (see
   [the life of a package](#the-life-of-a-package)). The log ends with what was accepted and what
   was rejected, and why; the rejections are also saved in
   `<wheelhouse>\reports\Report_Rejected_<timestamp>.json`.

   Prefer `.\Invoke-WheelhousePipeline.ps1` (or `whm pipeline`) instead if you also want an alert for whatever the
   run found (vulnerable candidates, Defender detections, ...).

In the UI: **Add packages** tab -> enter the packages -> **Add and resolve** -> check the
**Review and publish** card -> **Approve** (or **Approve and publish**) -> **Publish**. The card
shows the proposal, who requested and approved it, and only the buttons you are allowed to use.

### 5.2 Handle rejected packages

Every rejection has a reason. What to do:

| Reason starts with | Meaning | What to do |
|---|---|---|
| `cooldown: published ... (eligible <date>)` | Too new. | Nothing - run `Update-Wheelhouse.ps1` again after that date; the pin stays in `requirements.txt`. For an urgent fix, see 5.6. |
| `cooldown: could not verify the publish date on PyPI` | PyPI could not be reached, so nothing about the release can be verified. | Check access to `pypi.org`, run again. |
| `known vulnerability` | An advisory exists for this version. | Change the version in `requirements.in` (e.g. `pkg>=<fixed version>`), resolve again, publish. |
| `vulnerability audit could not be completed` | Network or tool problem during the audit. | Check access to `pypi.org` / `api.osv.dev`, run again. |
| `yanked on PyPI` | The release was withdrawn by its authors. | Choose another version. |
| `no downloadable wheel` | No wheel for your Python/platform. | Choose another version, or drop the package. |
| `sha256 of ... does not match PyPI` / `not one of the files PyPI lists` | The download differed from what PyPI publishes. **Security event** - an alert is raised. | Do not retry blindly. Check proxies/caches between the server and PyPI. |
| `Microsoft Defender detected` | Malware detection in the download. **Security event.** | Do not use this version. Review the detection in Defender. |
| `denylist` | The version is blocked. | Remove the entry from the denylist if the block is no longer wanted. |
| `the Defender scan could not be completed` | `RequireDefenderScanAtIntake` is on and the run was not elevated. | Run from an elevated PowerShell. |

A rejected **new** pin is simply tried again on the next run. A rejected pin that a group file
**already lists** (e.g. a hand-edited group file) is reported as "still listed without a wheel" -
fix or remove that line in the group file.

### 5.3 Keep several versions of one package

Pin the second version in `requirements.in` (for example `numpy==1.26.4` while `numpy==2.3.1` is
published). It goes into another group file automatically (`requirements-2.txt`, ...), because one
group file cannot list two versions of a package. Both wheels are then in the wheelhouse.

### 5.4 Check the wheelhouse on demand

```powershell
.\Test-Wheelhouse.ps1                   # the weekly check now, with alert
.\Test-Wheelhouse.ps1 -AutoQuarantine Off   # only report wheels missing/changed on the share
.\Test-WheelhousePackage.ps1                                   # audit everything, no alert
.\Test-WheelhousePackage.ps1 -Package numpy==2.3.1,pandas==2.2.3   # audit chosen packages
.\Invoke-WheelhouseScan.ps1                                    # Defender scan of every wheel (elevated; local copies)
.\Invoke-WheelhouseScan.ps1 -File numpy-2.3.1-cp314-cp314-win_amd64.whl
```

In the UI: **Packages** tab -> **Audit all / Audit selected**, **Scan all / Scan selected**. The
table shows each package's latest audit and scan result; a vulnerable package shows its worst
severity and fix-by date (or *overdue*).

### 5.5 Respond to an alert

An alert (email, or `<wheelhouse>\reports\Alert_<timestamp>.html`) can contain three sections:

**Packages that need attention** - each row has a recommended action:

| Kind | What happened | What to do |
|---|---|---|
| `Yanked` | A published version was withdrawn on PyPI. | Read the yank reason. Pin another version, resolve, publish, then quarantine this one. |
| `Denylisted` | A published version is on the denylist (blocked after it was published). | Quarantine or delete it - the denylist only stops new downloads. |
| `FileMissing` | A published wheel disappeared from the share - usually the file server's antivirus moved it to its quarantine. With AutoQuarantine on, the version was taken out of the group files and denylisted. | Check the file server's antivirus log. False positive: remove the version from the denylist and run `Update-Wheelhouse.ps1` (it downloads a verified copy). Otherwise keep it blocked and pin another version. |
| `FileModified` | A published wheel's content changed. With AutoQuarantine on, it was quarantined as evidence and denylisted. | Find out what changed it; do not restore it. |
| `IntakeBlocked` | A download did not match PyPI or was detected - nothing was published. | Investigate before trying that version again. |
| `Malicious` | OSV lists a published version as a malicious package. With AutoQuarantine on, it was quarantined and denylisted. | Treat every client that installed it as compromised (`uv pip list`). Do not restore it unless the advisory is withdrawn. |
| `Unverified` | No audit of this version has completed for `AuditFreshnessDays` - new vulnerabilities in it would go unnoticed. | Find out why the audits fail (network, proxy) in `Log_Audit_*.txt`. |
| `Untracked` | Wheel files appeared in the share that the manager never published (never checked). With AutoQuarantine on, they were moved to `_untracked\<time>\`. | Find out who copied them in; publish the packages you need through `requirements.in`, then delete the folder. |

**Vulnerability findings** - package, version, advisory ID (CVE/GHSA), description, fix
version, the group file(s) that list it and the exact wheel file(s). In the weekly check's alert
each finding also has a **severity**, a **fix-by** date and a **status**: `NEW`, `OVERDUE`,
`OVERDUE (reminder)`, `waiver ended`, or `open` (already alerted, listed again for completeness).
Overdue ones come first; resolved findings are listed in a short section of their own. The weekly
check alerts only when there is something new to say (a new, newly overdue, reminded, unwaived or
resolved finding, a notice, or a failed check). A finding marked *Blocked before download* was a
candidate that never reached the wheelhouse - just change `requirements.in`. For a published
package, **fix it** (see 5.14): UI **Packages** -> **History** of the version -> **Fix** on the
vulnerability, then approve and publish the fix proposal. The fixed version takes the old one's
place in the group files clients install from, and the old one is quarantined.

To do it by hand instead: quarantine (or delete) the version on the **Packages** tab, put the
fixed version in `requirements.in` (e.g. `requests>=2.32.4`), resolve, approve and publish. Note
that the fixed version then goes to a *new* group file if the old one is still listed - the fix
helper avoids that.

If you decide not to fix it now - for example the vulnerable code path is not used - **accept the
risk** for a limited time: UI **Packages** -> **History** of that version -> **Accept risk** on the
advisory, with a reason and a number of days (at most `WaiverMaxDays`). The finding is no longer
alerted and no longer makes the weekly check exit with code 1. When the waiver expires (or you
remove it on the **Denylist** tab, under *Accepted risks*), it is alerted again. A waiver covers
one advisory for one version only; the reason, the user and the dates are kept in the history.

**Audits or checks that could not be completed** - the affected packages were *not* checked. Look
at the run log (`<wheelhouse>\reports\Log_Audit_*.txt`), fix the cause (usually network) and run
`Test-Wheelhouse.ps1` again.

A wheel that **disappeared** from the share or whose **content changed** is listed as `FileMissing`
/ `FileModified` (see the table above). With `AutoQuarantine` off, `Update-Wheelhouse.ps1` refuses
to run until you quarantine or delete that version. Any other **integrity failure** (a wheel that
cannot be read, a broken manifest record) is not alerted by email: the script stops immediately,
exit code 2, details in `Report_Integrity_*.json`. Fix access to the share, or the manifest, and run
again.

### 5.6 Publish an urgent security fix (skip the cooldown for one package)

```powershell
.\Update-Requirement.ps1 -MinimumPackageAgeDays 0      # only if the fix is newer than the cooldown
.\Update-Wheelhouse.ps1 -ExpeditePackage requests==2.32.4 -ExpediteReason "CVE-2026-1234 fix"
```

Only the expedited pin skips the cooldown (your user name and the reason are logged); every other
check still applies, and any other too-new pin is rejected and retried later. Don't use
`Update-Wheelhouse.ps1 -MinimumPackageAgeDays 0` - it lifts the cooldown for every package in
the run.

### 5.7 Quarantine, delete or restore a package

In the UI, **Packages** tab: select rows -> **Quarantine** (reversible) or **Delete** (permanent,
asks for confirmation). Both remove the pin from every group file and the manifest first - so
clients never see a pin without a wheel - then move or delete the file, and add the version to the
denylist. If a step fails, the earlier steps are undone; if the server crashes part-way, the next
operation finishes the job (see 5.13). You can quarantine while an update is running - only the
few seconds in which an update writes files make you wait.

**Restore**: **Quarantine** tab -> **Restore**. The file's hash must be unchanged; the package goes
back into the manifest and its group files, and the denylist entry that quarantining created is
removed (an entry you added by hand stays).

### 5.8 Block a package

UI **Denylist** tab -> name, version (or `*` for all versions) and reason -> **Add**. Or edit
`config\denylist.json`. A blocked version:

- is refused by the UI's Add tab (when you enter that exact pin, or the entry blocks every version),
- is steered around when resolving (exact versions are passed to uv as `name!=version`),
- is rejected first at intake.

A blocked version that is already published stays installable until you quarantine it; the weekly
check reports it as `Denylisted`.

### 5.9 Use the update and the alert together - `Invoke-WheelhousePipeline.ps1`

```powershell
cd C:\WheelHouseManager\Jobs
.\Invoke-WheelhousePipeline.ps1
.\Invoke-WheelhousePipeline.ps1 -SmtpServer 10.0.0.25
..\whm.ps1 pipeline                # the same
```

It used to live in the manager root; `Setup.ps1` removes that old copy, so point any Scheduled
Task that runs it to `Jobs\Invoke-WheelhousePipeline.ps1`.

Runs `Update-Wheelhouse.ps1`, then sends one alert. Like the weekly check, it alerts published
packages only when there is something new to say (new, overdue, waiver ended, resolved), so a
known, already-alerted finding does not mail you on every update; candidates this run blocked
before publishing, notices and failed checks are always included. It takes the same parameters as
`Update-Wheelhouse.ps1` plus the alert ones.

### 5.10 Only retry what is pending, without merging anything new

```powershell
.\Update-Wheelhouse.ps1 -LocalRequirementsPath ""
```

Skips `Input\requirements.txt` and only (re)processes pins the group files already list but whose
wheel is missing - for example after a network problem.

### 5.11 Change the target Python version or platform

Change `PythonVersion` / `Platform`, then run `Update-Requirement.ps1` and `Update-Wheelhouse.ps1`.
Pins whose wheel does not fit the new target are treated as missing and downloaded for it.

### 5.12 Upgrade the manager

Get the new version of this repository and run `Setup.ps1` again with the same
`-DestinationPath`. Your settings, denylist, `Input\` files and the wheelhouse are not touched.

### 5.13 See a package's history - and what happens after a crash

In the UI's **Packages** tab, **History** on a row shows the version's state, its latest audit,
Defender and PyPI results, and every recorded event: published (and by whom, with the expedite
reason if the cooldown was skipped), quarantined or deleted (with the reason), restored, audit
or scan result changed, yanked on PyPI. The same history is in `<wheelhouse>\events.jsonl`, one
line per event.

Publishing, quarantining, deleting and restoring each write a small *journal* file
(`<wheelhouse>\.journal\`) before they start and delete it when they are done. If the server or
the process dies in between, the next operation that changes the wheelhouse finishes the job first
(logged as *Finishing an interrupted ...* and recorded as *Recovered* in the history). You do not
need to do anything, unless that repair itself fails - see [Troubleshooting](#10-troubleshooting).

### 5.14 Fix a vulnerable package (remediation)

```powershell
.\Invoke-WheelhouseRemediation.ps1 -Package requests==2.19.0
.\Invoke-WheelhouseRemediation.ps1 -Package requests==2.32.3 -ExpediteReason "CVE-2026-1234 is exploited"
.\Update-Wheelhouse.ps1      # after approval (with SamePersonAllowed this approves it)
```

1. **Plan.** From the version's open vulnerabilities the helper takes the lowest version that
   fixes them all, and checks PyPI for releases at or above it that are not yanked and old enough
   for the cooldown. A vulnerability without any known fix stays open (consider a waiver).
2. **Change `requirements.in`.** The package's line becomes `name>=fix` (upper bounds such as
   `<3` are kept), or is added when the package is only a dependency. When no fixed release has
   passed the cooldown yet, it pins the lowest fixed release instead, and you must give
   `-ExpediteReason` - only that package skips the cooldown, and the reason is recorded.
3. **Resolve.** `Update-Requirement.ps1` runs, keeping every other version where it still fits,
   so only what has to change changes. If it fails, `requirements.in` is put back.
4. **Propose.** A *fix proposal* lists each pin that changes and the version to quarantine.
5. **Approve and publish.** The update checks the new versions like any other, writes them in
   place of the old ones in the group files that list the vulnerable version (no new group
   file), and then quarantines and denylists the vulnerable version. If the replacement is
   rejected, the vulnerable version stays published and the run needs attention.

In the UI: **Packages** -> **History** -> **Fix** shows the plan first (and asks for the reason
when the fix is too new); when the job finishes, the message leads to the **Add packages** tab,
where the fix proposal waits for approval.

---

## 6. The web UI

```powershell
C:\WheelHouseManager\Jobs\Start-WheelhouseUI.ps1                     # opens the browser
C:\WheelHouseManager\Jobs\Start-WheelhouseUI.ps1 -Port 9000 -NoBrowser
```

The UI runs on the manager server only (`http://localhost:8765/`). Keep the PowerShell window open
while you use it; stop it with Ctrl+C or the **Stop UI** button. Start it from an **elevated**
PowerShell to use Defender scans. The top bar shows the wheelhouse path, the target Python, and
whether Defender is available and the session is elevated, and whether Python, pip-audit and uv
can be found. A banner at the top names anything that stops something from working - for example
*The wheelhouse folder is not set*, or *uv was not found ... Adding packages does not work* - and
what to do about it.

| Tab | What you can do |
|---|---|
| **Overview** (opens first) | The state at a glance - packages, open and overdue vulnerabilities, waived, yanked, unverified, quarantined (click a tile to see them) - a **Needs attention** list where each item leads to the place to handle it, and the weekly check's last run and task. |
| **Packages** | See every published wheel with its groups, latest audit (for a vulnerable one: worst severity and fix-by date, or *overdue*) and Defender result, a *yanked* badge if PyPI withdrew it, and the denylist flag; filter by name or status (vulnerable, fix overdue, risk accepted, threat, never audited/scanned, yanked, denylisted, file missing). Select rows to **Audit**, **Scan**, **Quarantine** or **Delete**; **History** shows one version's state, checks, vulnerabilities (with **Accept risk** / **Remove waiver**) and history. The toolbar stays in place and only the table scrolls. A banner warns when the weekly check has not run for `AuditFreshnessDays`. |
| **Add packages** | **1. Add**: enter packages; they are added to `requirements.in` and resolved - nothing is downloaded. The result (what was added and what was not, with the reason) appears inside step 1 in a scrolling list that **Hide list** / **Show list** folds away. **2. Review and publish**: lists only the resolved pins that are **not yet in the wheelhouse** (pins already published are only counted; the whole `requirements.txt` is behind *Show the whole requirements.txt*), each marked *new* or *rejected last time* with the reason. A pin the latest publish rejected has a **Remove** button (when it is listed in `requirements.in`) that takes it out of `requirements.in` and resolves again; a rejected pin marked *dependency* is needed by another requirement and goes away only with it. Then **Publish** (runs every check, then publishes). *Also publish right away* does both at once. When resolving succeeds, the page scrolls to step 2 and highlights it. A running job does not open its log by itself: a softly pulsing pill in the top bar (*Running: Add packages - view log*: the action only, not the package list) shows it, and clicking it opens the log panel at the bottom of the window (click again, or **Close**, to hide it). When the job ends the pill shows the result. The panel takes its own space, so it never covers the page. The card at the bottom lists the latest rejected packages with their reasons. Long lists scroll inside their card. |
| **Quarantine** | Quarantined packages; **Restore** one. |
| **Denylist** | Add or remove blocked versions; shows whether a blocked version is still published. Below it, **Accepted risks** lists every waiver with its reason and expiry, and lets you remove one. |
| **Schedule** | Register, update, run or remove the weekly check's Scheduled Task (see 3.3). |
| **Settings** | Edit `settings.psd1` with validation. The **Save settings** bar stays at the top of the page; it turns yellow and lists the changed settings until you save or discard them, and leaving the tab with unsaved changes asks first. |
| **Jobs** | Long actions run as background jobs, one at a time, named by their action (*Add packages*, *Publish packages*, *Audit packages*, ...); a small *show (N)* link under the name lists the packages or files the job worked on. Each job has a live log (**Open log**, or the pill in the top bar) and **Cancel**. A job ends as *Succeeded*, *Needs attention* (findings or rejected packages) or *Failed*. The message shown when a job ends is clickable: it takes you to what needs attention - the rejected packages, the vulnerable packages or Defender threats in the table, or the log. Important notices (the weekly check is not running, Defender scans unavailable) appear the same way, once per page load, and stay until you click them; the first one takes you to the **Schedule** tab. |

The UI does the same as the scripts - it runs them in the background - so the reports and logs
are the same.

---

## 7. Script reference

Every parameter is optional when it is set in `settings.psd1`. `Get-Help .\<script>.ps1 -Full`
shows the details.

| Script | Purpose | Main parameters |
|---|---|---|
| `Setup.ps1` (repo) | Deploy or upgrade the manager, check it, optionally schedule the weekly check | `-DestinationPath`, `-WheelhousePath`, `-RegisterScheduledTask`, `-TaskCredential`, `-TaskDays`, `-TaskTime`, `-SkipDoctor` |
| `whm.ps1` (root) | One command for everything (5.0) | `whm help` |
| `Client Install\Test-PythonEnvironment.ps1` | Optional, on clients: is anything installed affected? (3.4) | `-Project`, `-Python`, `-AdvisoriesPath`, `-InstalledJson` |
| `Jobs\Update-Requirement.ps1` | `requirements.in` -> `requirements.txt` | `-RequirementsInPath`, `-RequirementsTxtPath`, `-PythonVersion`, `-Platform`, `-MinimumPackageAgeDays` |
| `Jobs\Update-Wheelhouse.ps1` | Check and publish new pins; audit what is published; take out wheels missing/changed on the share | `-LocalRequirementsPath` (`""` = no merge), `-ExpeditePackage`, `-ExpediteReason`, `-AutoQuarantine On|Off`, `-MinimumPackageAgeDays`, `-PythonVersion`, `-Platform`, `-VulnerabilityServices` |
| `Jobs\Invoke-WheelhousePipeline.ps1` | `Update-Wheelhouse.ps1` + one alert | as above, plus `-SmtpServer`, `-To`, `-From`, `-OutputHtmlPath` |
| `Jobs\Test-Wheelhouse.ps1` | Weekly check of everything published, with alert | `-AutoQuarantine On|Off`, `-VulnerabilityServices`, `-SmtpServer`, `-MailTo`, `-MailFrom` |
| `Jobs\Test-WheelhousePackage.ps1` | Audit all or chosen pins, no alert | `-Package name==ver,...` |
| `Jobs\Invoke-WheelhouseRemediation.ps1` | Prepare the fix of a vulnerable published version as a proposal (5.14) | `-Package name==ver`, `-ExpediteReason` |
| `Jobs\Invoke-WheelhouseScan.ps1` | On-demand Defender scan of all or chosen wheels - copied locally and hash-checked first, never scanned on the share (elevated) | `-File name.whl,...` |
| `Jobs\Send-VulnerabilityAlert.ps1` | Build and send/save an alert (used by the scripts above) | `-ReportPaths`, `-Findings`, `-AuditErrors`, `-Notices`, `-SmtpServer`, `-To`, `-From`, `-OutputHtmlPath` |
| `Jobs\Start-WheelhouseUI.ps1` | Start the web UI | `-Port`, `-NoBrowser` |

Changes to the wheelhouse are serialized, but only for the seconds in which files are written:
quarantine, delete and restore work while an update runs, and the update and the checks wait (up
to 5 minutes) for each other's write steps. Only one `Update-Wheelhouse.ps1` runs at a time - a
second one stops with "Another Update-Wheelhouse run is already in progress" (exit code 3). A UI
action that meets a write step in progress is refused with "Another wheelhouse operation is
already running" - just try again a moment later.

---

## 8. Alerts, reports and logs

Alerts are emailed when `SmtpServer` is set, otherwise saved as
`<wheelhouse>\reports\Alert_<timestamp>.html`.

**Windows Event Log (optional).** With `EventLog` on (`Setup.ps1 -EnableEventLog`, run once as
administrator - it creates the event source), every script also writes to the manager server's
*Application* log, source `WheelhouseManager`, so your central monitoring (SCOM, Splunk, Sentinel,
Windows Event Forwarding) can pick it up:

| Event ID | Level | When |
|---|---|---|
| 1000 | Information | A run finished OK |
| 1001 | Warning | A run needs attention (findings, rejected packages) |
| 1002 | Error | A run failed, a check could not be completed, or the alert could not be sent |
| 1003 | Warning | An automatic action: a wheel missing or changed on the share taken out, a malicious package quarantined, untracked wheels moved |
| 1004 | Information | A change by someone: published, quarantined, deleted, restored, proposal approved / rejected / published |

Each entry names the run's log file and the user. If writing fails (the source was never
created), the run warns once and carries on without the Event Log. Everything below is in `<wheelhouse>\reports\` and
is deleted after `ReportRetentionMonths`.

| File | Written by | Content |
|---|---|---|
| `Log_<ts>.txt`, `Log_Audit_<ts>.txt`, `Log_PackageAudit_<ts>.txt`, `Log_Scan_<ts>.txt` | Update-Wheelhouse, Test-Wheelhouse, Test-WheelhousePackage, Invoke-WheelhouseScan | Full console log of the run |
| `Report_<Stage>-<set>-<OSV\|PYPI>_<ts>.json` | Every audit | pip-audit result. Stage: `PreDownload` (candidates, set `<group>-candidates`), `Deployed` (Update-Wheelhouse), `Scheduled` (Test-Wheelhouse), `Manual` (Test-WheelhousePackage). Published packages are audited in as few runs as possible - set `published-1`, `published-2`, ... (one version per package each; the audited lists are in `reports\audit-sets\`) - not once per group file. |
| `Report_PackageAge-<group>_<ts>.json` | Update-Wheelhouse | Cooldown/yanked data per candidate, with the eligible date |
| `Report_Rejected_<ts>.json` | Update-Wheelhouse | Every rejected pin with category and reason |
| `Report_Scan_<ts>.json` | Every Defender scan (intake and on-demand) | Status, scanned paths, detections |
| `Report_Integrity_<ts>.json` | Integrity check | What did not match the manifest |

**Integrity check speed.** The weekly check hashes every wheel. An update only hashes wheels
whose size or modification time changed since they were last verified (kept in
`C:\WheelHouseManager\state\`, not on the share), so it holds the write lock for seconds even
for a large wheelhouse; a missing wheel is always noticed. A change that keeps size and timestamp
is caught by the next weekly check.
| `Alert_<ts>.html` | Send-VulnerabilityAlert | Saved alert (no SMTP server) |

Next to `reports\`, the wheelhouse holds `catalog.json` (current state, latest check results and
vulnerability findings per package version) and `events.jsonl` (history). Neither is deleted by the
retention setting, nor is `reports\osv-cache.json` (severities looked up on OSV, refreshed weekly).
Waivers are kept on the manager server in `config\waivers.json`. `advisories.json` (every version
that needs attention, for the client check) is rewritten whenever the catalog changes.

Jobs started from the UI also keep their console output in `C:\WheelHouseManager\logs\ui\`.

---

## 9. Exit codes

All scripts use the same codes - useful for Task Scheduler and your own automation:

| Code | Meaning |
|---|---|
| `0` | OK. |
| `1` | Finished, but **needs attention**: vulnerabilities (not waived), rejected packages, threats or other findings - or the change still **waits for approval** (nothing was published). |
| `2` | **Error**: the run aborted, or a check could not be completed (never reported as clean). |
| `3` | **Busy**: another wheelhouse operation holds the lock. Try again later. |

---

## 10. Troubleshooting

| Message or symptom | Cause and fix |
|---|---|
| `WheelhousePath was not supplied and is not set in config\settings.psd1` | Run `Setup.ps1 -WheelhousePath ...`, or set it in the UI's Settings tab. |
| `Wheelhouse path does not exist or is not reachable` | Check the share path and the account's access to it. |
| `Another wheelhouse operation is already running (lock file in use: ...)` | Another operation is writing right now (usually for a few seconds). Try again. The lock is released automatically, even after a crash. |
| `Another Update-Wheelhouse run is already in progress` | Only one update runs at a time. Wait for it to finish. |
| `Waiting up to 300 s for another wheelhouse operation to finish` | Informational: an update or check waits for another operation's write step. |
| `A journal of an interrupted operation could not be read` / `An interrupted ... could not be finished` | A crash left a half-done change that cannot be finished automatically (the message says why). Check the files it names by hand, then delete the journal file named in the message; every change to the wheelhouse is refused until then. |
| `catalog.json exists but could not be parsed` | Restore it from a backup, or delete it: the next run rebuilds it from the manifest, group files and quarantine (the check results start again; the history in `events.jsonl` is kept). |
| `The results could not be recorded in the package catalog` | The check ran, but its results are not visible in the UI (usually the write lock stayed busy for 5 minutes). The run exits with code 2 - run the check again. |
| `Wheelhouse integrity check failed - refusing to continue ...` | A published wheel changed or disappeared. See `Report_Integrity_*.json` and section 5.5. |
| `manifest.json exists but could not be parsed` / `denylist.json exists but could not be parsed` / `quarantine.json could not be parsed` | The file is damaged; it is never treated as empty. Restore it from backup or fix the JSON by hand. |
| `Wheelhouse has no requirement group files yet, and no local requirements were supplied` | First run: add packages to `requirements.in`, run `Update-Requirement.ps1`, then `Update-Wheelhouse.ps1`. |
| `Update-Requirement.ps1` writes `requirements.rejected.txt` | A package has no wheel for your Python/platform (or its `Requires-Python` excludes it). Remove it or constrain its version in `requirements.in`. |
| `Python was not found on this machine` | Install Python on the manager server and make sure `python` is on `PATH`. |
| `Start-MpScan is not available` / Defender scan result `Error` | Run elevated; check that Microsoft Defender is active. |
| `-ExpeditePackage needs -ExpediteReason` | Add `-ExpediteReason "..."`. |
| A package is "still listed without a wheel" | A group file lists a pin that could not be published. Fix the cause shown, or remove the line from the group file. |
| UI: `Open the address printed by Start-WheelhouseUI.ps1 (it contains the session token)` | Use the full URL from the console; it changes at every start. |
| UI: `Cannot listen on port 8765` | The UI is already running, or the port is used - use `-Port`. |
| `Proposal ... is waiting for approval` / `Not approved: ... has no proposal` | `ApprovalMode` is `SeparateApprover`: another person approves it (UI: Add packages -> Approve), then publish again. A hand-edited `requirements.txt` needs a new proposal first. |
| `... changed after proposal ... was made` | `requirements.txt` was edited after it was proposed. Resolve again, or propose the file as it is now. |
| Fix: `No fixed version of ... is known` | No release fixes that advisory yet. Accept the risk for a while (waiver), pin another package, or remove it. |
| Fix: `No fixed release ... is older than the cooldown` | Wait for the date shown, or give an expedite reason (UI asks for it). |
| UI: *Task Scheduler refused the account or password* | Wrong password, or the account may not log on as a batch job (a domain policy). Check both, or ask for the *Log on as a batch job* right. |
| UI: *Windows denied the change ... needs an elevated PowerShell* | You registered the task for another account, or someone else created it. Start `Start-WheelhouseUI.ps1` as administrator. |
| Weekly check *Last run*: *the account could not log on (password changed?)* | The account's password changed. Enter the new one and click **Update the task**. |
| UI banner: *Python was not found* / *uv was not found* | The account running `Start-WheelhouseUI.ps1` cannot find the tool on its `PATH`. Install it (or add it to `PATH`) and restart the UI. A missing pip-audit is only a warning: the first audit or update installs it. |
| UI: job *Needs attention* | Normal outcome with findings or rejections - open the log. |
| No alert email arrives | Check `SmtpServer`; without it, alerts are saved as HTML in `reports\`. `Send-MailMessage` does not support authentication - use an internal relay. The weekly check alerts only when something changed: a finding that was already alerted and is not yet due is not alerted again (exit code 1 still shows it is open). |
| `OSV lookup failed: ... severities not in the cache count as High in this run` | The manager server cannot reach `api.osv.dev`. Nothing else is affected; severities are looked up again next run. |
| UI banner *The scheduled check is not running* | `Test-Wheelhouse.ps1` has not completed within `AuditFreshnessDays`. Check its Scheduled Task and its last log (`Log_Audit_*.txt`). |
| `waivers.json exists but could not be parsed` | The file is damaged; it is never treated as empty. Fix the JSON or restore it. |

---

## 11. Security

- **Clients** can only install from the wheelhouse (machine-wide uv configuration, applied before
  logon).
- **Every published file** passed the denylist, vulnerability audit, yanked, cooldown, PyPI hash
  and Defender checks, and is recorded with its SHA256; any later change is detected.
- **Fail closed**: a check that cannot be completed never counts as passed, and a damaged
  manifest, denylist or quarantine record stops the run.
- **Web UI**: listens on `localhost` / `127.0.0.1` only, needs the random session token from the
  start URL, refuses foreign `Host`/`Origin` headers and non-JSON requests, and validates every
  package and file name against the manifest. Use it on the manager server itself - do not expose
  the port.
- Changes to the wheelhouse are serialized by a lock; removal steps are undone if one fails, and
  every multi-step change is journaled, so a crash part-way is finished by the next operation.
- Every change and every changed check result is recorded with user and time in `events.jsonl`.

---

## 12. Limitations

- Wheels only (no source packages), for **one** Python version and platform per manager.
- Vulnerable, yanked or denylisted packages are not quarantined automatically - an administrator
  decides. Only wheels removed or changed on the share, malicious-package advisories and wheels
  nobody published are acted on automatically (`AutoQuarantine`).
- The share is not virus-scanned by this tool; that is the file server antivirus' job.
- Severities come from OSV. An advisory rated only with CVSS 4 and no database rating counts as
  High.
- Email uses `Send-MailMessage` (no SMTP authentication).
- Planned improvements are listed in [REFACTOR_PLAN.md](REFACTOR_PLAN.md).

---

## 13. For developers

How the code is built, its rules and how to extend it: **[ARCHITECTURE.md](ARCHITECTURE.md)**.

```powershell
Invoke-Pester -Path .\Tests                     # needs Pester 5+ (not the 3.4 that ships with Windows)
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
```
