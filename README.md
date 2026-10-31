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
  become vulnerable, yanked or detected as malware later. A weekly check finds that and sends one
  alert that says what is affected and what to do.
- **Lets you act quickly.** Quarantine (reversible) or delete a package, block versions on a
  denylist, restore from quarantine, or fast-track an urgent security fix.
- **Gives you a web UI** on the manager server for all of the above, plus email (or HTML file)
  alerts and a full audit trail of reports and logs.

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
| **Manager** (`Setup.ps1`, `Invoke-WheelhousePipeline.ps1`, `Jobs\`) | One manager / build server | Prepares, checks, publishes and monitors the wheelhouse. Has the web UI. |

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
   its pin is listed in a group file. Clients can install it.
6. **Monitored.** Every week `Test-Wheelhouse.ps1` re-checks everything that is published:
   files unchanged (hash), new vulnerabilities, yanked on PyPI since, denylisted since, and -
   optionally - Defender with the latest signatures. Anything it finds goes into one alert.
7. **Taken out (if needed).** You quarantine or delete the package. Its pin is removed and the
   version is denylisted so it is not downloaded again. Quarantine can be undone.

**Nothing is removed automatically.** A package flagged by the weekly check stays installable
until an administrator acts on the alert. The one exception: a wheel that Microsoft Defender
deletes or quarantines itself is cleaned out of the manifest and group files by the next
`Update-Wheelhouse.ps1` run (and denylisted).

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
```

`Setup.ps1` is safe to re-run - do so to deploy a newer version. It always replaces the code in
`Jobs\`, but never overwrites your settings, denylist or `Input\` files.

Result:

```
C:\WheelHouseManager\
    Invoke-WheelhousePipeline.ps1   update + alert in one call
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

The wheelhouse share gets `manifest.json`, the group files, `reports\` and `_quarantine\` as
they are needed.

### 3.3 Schedule the weekly check - `Test-Wheelhouse.ps1`

This is the job that notices when a published package fails a check later. It only reads and
alerts - it never downloads or changes anything - so it is safe to run unattended.

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

The account needs network access and read access to the share. To also re-scan with Defender
every week, set `DefenderScanInScheduledCheck = $true` and run the task with highest privileges
(administrator).

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
| `DefenderScanInScheduledCheck` | `$false` | The weekly check also re-scans the whole wheelhouse with Defender (needs an elevated task). |

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
    DefenderScanInScheduledCheck = $true
}
```

---

## 5. Using it: step-by-step guides

All commands assume `cd C:\WheelHouseManager\Jobs` unless noted. Each guide also says how to do
it in the [web UI](#6-the-web-ui).

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
3. **Review** `Input\requirements.txt` and get it approved if your process requires that.
4. **Publish.**
   ```powershell
   .\Update-Wheelhouse.ps1
   ```
   Pins already in the wheelhouse are skipped. Each new pin goes through every check (see
   [the life of a package](#the-life-of-a-package)). The log ends with what was accepted and what
   was rejected, and why; the rejections are also saved in
   `<wheelhouse>\reports\Report_Rejected_<timestamp>.json`.

   Prefer `..\Invoke-WheelhousePipeline.ps1` instead if you also want an alert for whatever the
   run found (vulnerable candidates, Defender detections, ...).

In the UI: **Add packages** tab -> enter the packages -> **Add and resolve** -> check the
**Review and publish** card -> **Publish**.

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
.\Test-Wheelhouse.ps1 -DefenderScan     # ... and a Defender re-scan (elevated PowerShell)
.\Test-WheelhousePackage.ps1                                   # audit everything, no alert
.\Test-WheelhousePackage.ps1 -Package numpy==2.3.1,pandas==2.2.3   # audit chosen packages
.\Invoke-WheelhouseScan.ps1                                    # Defender scan of everything (elevated)
.\Invoke-WheelhouseScan.ps1 -File numpy-2.3.1-cp314-cp314-win_amd64.whl
```

In the UI: **Packages** tab -> **Audit all / Audit selected**, **Scan all / Scan selected**. The
table shows each package's latest audit and scan result.

### 5.5 Respond to an alert

An alert (email, or `<wheelhouse>\reports\Alert_<timestamp>.html`) can contain three sections:

**Packages that need attention** - each row has a recommended action:

| Kind | What happened | What to do |
|---|---|---|
| `Yanked` | A published version was withdrawn on PyPI. | Read the yank reason. Pin another version, resolve, publish, then quarantine this one. |
| `Denylisted` | A published version is on the denylist (blocked after it was published). | Quarantine or delete it - the denylist only stops new downloads. |
| `DefenderThreat` | Defender detects a published wheel. | Quarantine it now, then review the detection. |
| `DefenderRemoved` | Defender removed a published wheel itself. | Review the detection. `Update-Wheelhouse.ps1` cleans up the pin and denylists the version. |
| `IntakeBlocked` | A download did not match PyPI or was detected - nothing was published. | Investigate before trying that version again. |

**Vulnerability findings** - package, version, advisory ID (CVE/GHSA), description, fix
version, the group file(s) that list it and the exact wheel file(s). A finding marked *Blocked
before download* was a candidate that never reached the wheelhouse - just change
`requirements.in`. For a published package:

1. Quarantine (or delete) it - UI **Packages** tab. This removes the pin, the manifest entry and
   the file, and denylists that version.
2. Put the fixed version in `requirements.in` (e.g. `requests>=2.32.4`), run
   `Update-Requirement.ps1`, review, run `Update-Wheelhouse.ps1`.
3. If the fix is newer than the cooldown, see 5.6.

**Audits or checks that could not be completed** - the affected packages were *not* checked. Look
at the run log (`<wheelhouse>\reports\Log_Audit_*.txt`), fix the cause (usually network) and run
`Test-Wheelhouse.ps1` again.

An **integrity failure** (a wheel's hash changed, or a file disappeared without a Defender
detection) is not alerted by email: the script stops immediately, exit code 2, details in
`Report_Integrity_*.json`. Treat it as possible tampering: compare the file, restore it from
quarantine or backup, or remove the package and publish it again.

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
denylist. If a step fails, the earlier steps are undone.

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
cd C:\WheelHouseManager
.\Invoke-WheelhousePipeline.ps1
.\Invoke-WheelhousePipeline.ps1 -SmtpServer 10.0.0.25
```

Runs `Update-Wheelhouse.ps1`, then sends one alert for exactly this run's findings. It takes the
same parameters as `Update-Wheelhouse.ps1` plus the alert ones.

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

---

## 6. The web UI

```powershell
C:\WheelHouseManager\Jobs\Start-WheelhouseUI.ps1                     # opens the browser
C:\WheelHouseManager\Jobs\Start-WheelhouseUI.ps1 -Port 9000 -NoBrowser
```

The UI runs on the manager server only (`http://localhost:8765/`). Keep the PowerShell window open
while you use it; stop it with Ctrl+C or the **Stop UI** button. Start it from an **elevated**
PowerShell to use Defender scans. The top bar shows the wheelhouse path, the target Python, and
whether Defender is available and the session is elevated.

| Tab | What you can do |
|---|---|
| **Packages** | See every published wheel with its groups, latest audit and Defender result, and denylist flag; filter by name or status. Select rows to **Audit**, **Scan**, **Quarantine** or **Delete**. |
| **Add packages** | **1. Add**: enter packages; they are added to `requirements.in` and resolved - nothing is downloaded. **2. Review and publish**: read the resolved `requirements.txt`, then **Publish** (runs every check, then publishes). *Also publish right away* does both at once. The card at the bottom lists the latest rejected packages with their reasons. |
| **Quarantine** | Quarantined packages; **Restore** one. |
| **Denylist** | Add or remove blocked versions; shows whether a blocked version is still published. |
| **Settings** | Edit `settings.psd1` with validation. |
| **Jobs** | Long actions run as background jobs, one at a time, with a live log and **Cancel**. A job ends as *Succeeded*, *Needs attention* (findings or rejected packages - read the log) or *Failed*. |

The UI does the same as the scripts - it runs them in the background - so the reports and logs
are the same.

---

## 7. Script reference

Every parameter is optional when it is set in `settings.psd1`. `Get-Help .\<script>.ps1 -Full`
shows the details.

| Script | Purpose | Main parameters |
|---|---|---|
| `Setup.ps1` (repo) | Deploy or upgrade the manager | `-DestinationPath`, `-WheelhousePath` |
| `Jobs\Update-Requirement.ps1` | `requirements.in` -> `requirements.txt` | `-RequirementsInPath`, `-RequirementsTxtPath`, `-PythonVersion`, `-Platform`, `-MinimumPackageAgeDays` |
| `Jobs\Update-Wheelhouse.ps1` | Check and publish new pins; audit what is published; Defender scan | `-LocalRequirementsPath` (`""` = no merge), `-ExpeditePackage`, `-ExpediteReason`, `-MinimumPackageAgeDays`, `-PythonVersion`, `-Platform`, `-VulnerabilityServices` |
| `Invoke-WheelhousePipeline.ps1` (root) | `Update-Wheelhouse.ps1` + one alert | as above, plus `-SmtpServer`, `-To`, `-From`, `-OutputHtmlPath` |
| `Jobs\Test-Wheelhouse.ps1` | Weekly check of everything published, with alert | `-DefenderScan`, `-VulnerabilityServices`, `-SmtpServer`, `-MailTo`, `-MailFrom` |
| `Jobs\Test-WheelhousePackage.ps1` | Audit all or chosen pins, no alert | `-Package name==ver,...` |
| `Jobs\Invoke-WheelhouseScan.ps1` | Defender scan of all or chosen wheels (elevated) | `-File name.whl,...` |
| `Jobs\Send-VulnerabilityAlert.ps1` | Build and send/save an alert (used by the scripts above) | `-ReportPaths`, `-AuditErrors`, `-SmtpServer`, `-To`, `-From`, `-OutputHtmlPath` |
| `Jobs\Start-WheelhouseUI.ps1` | Start the web UI | `-Port`, `-NoBrowser` |

Only one operation at a time may change the wheelhouse (`Update-Wheelhouse.ps1`, quarantine,
delete, restore). A second one is refused with "Another wheelhouse operation is already
running" (exit code 3) - just try again later.

---

## 8. Alerts, reports and logs

Alerts are emailed when `SmtpServer` is set, otherwise saved as
`<wheelhouse>\reports\Alert_<timestamp>.html`. Everything below is in `<wheelhouse>\reports\` and
is deleted after `ReportRetentionMonths`.

| File | Written by | Content |
|---|---|---|
| `Log_<ts>.txt`, `Log_Audit_<ts>.txt`, `Log_PackageAudit_<ts>.txt`, `Log_Scan_<ts>.txt` | Update-Wheelhouse, Test-Wheelhouse, Test-WheelhousePackage, Invoke-WheelhouseScan | Full console log of the run |
| `Report_<Stage>-<group>-<OSV\|PYPI>_<ts>.json` | Every audit | pip-audit result. Stage: `PreDownload` (candidates), `Deployed` (Update-Wheelhouse), `Scheduled` (Test-Wheelhouse), `Manual` (Test-WheelhousePackage) |
| `Report_PackageAge-<group>_<ts>.json` | Update-Wheelhouse | Cooldown/yanked data per candidate, with the eligible date |
| `Report_Rejected_<ts>.json` | Update-Wheelhouse | Every rejected pin with category and reason |
| `Report_Scan_<ts>.json` | Every Defender scan | Status, scanned paths, detections |
| `Report_Integrity_<ts>.json` | Integrity check | What did not match the manifest |
| `Alert_<ts>.html` | Send-VulnerabilityAlert | Saved alert (no SMTP server) |

Jobs started from the UI also keep their console output in `C:\WheelHouseManager\logs\ui\`.

---

## 9. Exit codes

All scripts use the same codes - useful for Task Scheduler and your own automation:

| Code | Meaning |
|---|---|
| `0` | OK. |
| `1` | Finished, but **needs attention**: vulnerabilities, rejected packages, threats or other findings. |
| `2` | **Error**: the run aborted, or a check could not be completed (never reported as clean). |
| `3` | **Busy**: another wheelhouse operation holds the lock. Try again later. |

---

## 10. Troubleshooting

| Message or symptom | Cause and fix |
|---|---|
| `WheelhousePath was not supplied and is not set in config\settings.psd1` | Run `Setup.ps1 -WheelhousePath ...`, or set it in the UI's Settings tab. |
| `Wheelhouse path does not exist or is not reachable` | Check the share path and the account's access to it. |
| `Another wheelhouse operation is already running (lock file in use: ...)` | Wait for the other run (or UI job) to finish. The lock is released automatically, even after a crash. |
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
| UI: job *Needs attention* | Normal outcome with findings or rejections - open the log. |
| No alert email arrives | Check `SmtpServer`; without it, alerts are saved as HTML in `reports\`. `Send-MailMessage` does not support authentication - use an internal relay. |

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
- Changes to the wheelhouse are serialized by a lock, and removal steps are undone if one fails.

---

## 12. Limitations

- Wheels only (no source packages), for **one** Python version and platform per manager.
- Nothing is quarantined automatically when the weekly check finds a problem - an administrator
  decides.
- Wheels found in the share that the manager did not publish ("untracked") are reported, but are
  still visible to clients until removed by hand.
- Email uses `Send-MailMessage` (no SMTP authentication).
- Planned improvements are listed in [REFACTOR_PLAN.md](REFACTOR_PLAN.md).

---

## 13. For developers

How the code is built, its rules and how to extend it: **[ARCHITECTURE.md](ARCHITECTURE.md)**.

```powershell
Invoke-Pester -Path .\Tests                     # needs Pester 5+ (not the 3.4 that ships with Windows)
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
```
