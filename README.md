# Wheelhouse Automation - README

This project has two independent parts:

1. **Client-side uv installation** on non-persistent Windows VDI hosts (`Client Install/`),
   which locks clients to a single, internal, audited package source.
2. **Wheelhouse Manager** (`Setup.ps1`, `Invoke-WheelhousePipeline.ps1`, `Jobs/`), which
   prepares, approves, populates, and continuously audits that internal package source
   (the "wheelhouse").

## Repository layout

```
Client Install/
    UV_Installer.ps1              # Installs the uv binaries (Cetegra package)
    Startup_UV.ps1                 # Locks down uv configuration (GPO computer startup script)

Setup.ps1                          # Deploys the manager to a local folder (run once, safe to re-run)
Invoke-WheelhousePipeline.ps1      # Orchestrator: Update-Wheelhouse.ps1 + Send-VulnerabilityAlert.ps1

Jobs/
    functions.ps1                  # All shared/helper functions - dot-sourced by every script below
    Update-Requirement.ps1         # Resolves Input\requirements.in -> Input\requirements.txt
    Update-Wheelhouse.ps1          # Merge (opt-in) + per-group audit/cooldown/download/manifest/Defender
    Test-Wheelhouse.ps1            # Audit-only check - this is what the Scheduled Task runs
    Send-VulnerabilityAlert.ps1    # Parses audit reports, emails or saves an HTML alert
```

`Setup.ps1` and `Invoke-WheelhousePipeline.ps1` live at the project root; everything in
`Jobs/` must stay together in one folder (they locate `functions.ps1` and each other via
`$PSScriptRoot`). The two files in `Client Install/` are deployed through a different
mechanism entirely (see section 1) and are unrelated to the manager's own folder layout.

---

## 1. Installing uv on client machines

Two scripts, from `Client Install/`, each with a different deployment mechanism.

### 1.1 `Client Install/UV_Installer.ps1` - installs the uv binaries

Packaged as a Cetegra software deployment script (see the `.cetegra-version` stamp file and
`<AppVersion>` placeholder, which Cetegra's packaging tooling fills in at build time). It:

- Extracts `uv-x86_64-pc-windows-msvc.zip` (must sit next to the script) into
  `C:\Program Files\astral.sh\uv`.
- Skips reinstalling if a version stamp file already matches the target version.
- Creates **hardlinks** for `uv.exe`, `uvw.exe`, `uvx.exe` into `C:\Windows\System32` instead of
  modifying the system `PATH` - `System32` is already on `PATH` for every user, and hardlinks
  work here because both locations are on the same volume.
- Logs to `%WinDir%\Logs\Astral-uv-<version>_Script.txt`.

Deploy this through Cetegra as a standard application package targeting the VDI golden image
or machine pool.

### 1.2 `Client Install/Startup_UV.ps1` - locks down configuration via Group Policy

**Runs as a Group Policy Computer Startup Script**, not a login script or a manually-run tool:

- Computer startup scripts run as **SYSTEM**, at boot, **before any user logs on** - so the
  environment variables and `uv.toml` are guaranteed to be in place before any user session ever
  touches `uv`.
- Because it's a *machine* policy, a standard user cannot override it - `Startup_UV.ps1` writes
  to `%ProgramData%\uv\uv.toml`, which ordinary users can't modify.

What it sets, all at machine scope:

| Setting | Value | Purpose |
|---|---|---|
| `UV_PYTHON_DOWNLOADS` | `never` | Blocks `uv python install` from ever downloading a Python interpreter |
| `UV_PYTHON_PREFERENCE` | `only-system` | Never resolve to a uv-managed Python; only pre-installed interpreters |
| `UV_LINK_MODE` | `copy` | Cache and target venv are on different filesystems (local cache vs. FSLogix/network profile) |
| `UV_CACHE_DIR` | `C:\uv-cache` | Local, ephemeral cache (not on the roaming/FSLogix profile) |
| `UV_NO_INDEX` | `true` | Blocks the default PyPI index entirely |
| `%ProgramData%\uv\uv.toml` | flat index pointing at the wheelhouse | The **only** package source clients can use |

**Before deploying:** edit the placeholder in `Startup_UV.ps1`:

```powershell
'url = "\\\\server\\pathToWheelHouse"',
```

Replace `\\server\pathToWheelHouse` with your actual wheelhouse UNC path.

### GPO deployment steps

1. Edit the wheelhouse path placeholder in `Client Install\Startup_UV.ps1`.
2. Open **Group Policy Management Console**, create or edit a GPO linked to the VDI OU.
3. **Computer Configuration → Policies → Windows Settings → Scripts (Startup/Shutdown) → Startup**,
   add `Startup_UV.ps1` under the **PowerShell Scripts** tab.
4. Ensure `UV_Installer.ps1` (via Cetegra) is deployed to the same machines.
5. Run `gpupdate /force` on a test machine (or reboot it) and confirm:
   ```powershell
   Test-Path "C:\Windows\System32\uv.exe"
   $env:UV_NO_INDEX
   Get-Content "$env:ProgramData\uv\uv.toml"
   ```

---

## 2. Installing dependencies on the build server

The build server (separate from the VDI clients) needs Python, pip, uv (as a resolver only),
and pip-audit.

```powershell
python -m pip install --upgrade pip
python -m pip install --upgrade uv pip-audit
```

Confirm: `python --version`, `uv --version`, `pip-audit --version`.

The wheelhouse scripts self-check and self-update `pip` and `pip-audit` on every run (see
`Confirm-PythonAndTooling` in `Jobs\functions.ps1`), but don't self-update `uv`.

---

## 3. Deploying the manager - `Setup.ps1`

Run once to deploy everything into a working folder, and again any time you want to redeploy
an updated script package. **Idempotent**: always refreshes the code in `Jobs\` and the root
scripts, but never touches your `config\settings.psd1` values or your `Input\requirements.in`/
`.txt` - those are your data, not code.

```powershell
.\Setup.ps1 -WheelhousePath "\\server\share\wheelhouse"
```

```powershell
# Custom destination folder (default is C:\WheelHouseManager)
.\Setup.ps1 -DestinationPath "D:\WheelHouseManager" -WheelhousePath "\\server\share\wheelhouse"
```

Result:

```
C:\WheelHouseManager\
    config\
        settings.psd1
    Input\
        requirements.in
        requirements.txt
    Jobs\
        functions.ps1
        Update-Requirement.ps1
        Update-Wheelhouse.ps1
        Test-Wheelhouse.ps1
        Send-VulnerabilityAlert.ps1
    Invoke-WheelhousePipeline.ps1
```

### `config\settings.psd1`

Every script's optional parameters fall back to this file if not passed explicitly, so you
don't need to repeat `-WheelhousePath` (or anything else) on every call.

```powershell
@{
    WheelhousePath        = '\\server\share\wheelhouse'
    PythonVersion          = '3.14'
    Platform                = 'win_amd64'
    MinimumPackageAgeDays   = 10
    VulnerabilityServices   = @('osv', 'pypi')
    SmtpServer              = ''
    MailTo                  = 'servicedesk@company.com'
    MailFrom                = 'NoReply@company.com'
}
```

Precedence everywhere: **explicit `-Parameter`** > **this file** > **the script's own hardcoded
fallback**. Edit it directly, or let `Setup.ps1 -WheelhousePath ...` update just that one key
without touching the rest.

---

## 4. Preparing packages - `Update-Requirement.ps1`

Edit `Input\requirements.in` (unpinned names, or version ranges), then resolve it:

```powershell
cd C:\WheelHouseManager\Jobs
.\Update-Requirement.ps1
```

Defaults to `Input\requirements.in` / `Input\requirements.txt` under the manager root, and to
the `PythonVersion`/`MinimumPackageAgeDays` from `settings.psd1`. Internally runs:

```powershell
uv pip compile Input\requirements.in --exclude-newer "10 days" --python 3.14 -o Input\requirements.txt
```

Review the resulting `Input\requirements.txt` and get it approved before the next step.

---

## 5. Merging into the wheelhouse - `Update-Wheelhouse.ps1`

**Manual, deliberate action** - taken after `Input\requirements.txt` is approved. Never runs
unattended (see section 6 for what the Scheduled Task actually runs instead).

```powershell
cd C:\WheelHouseManager\Jobs
.\Update-Wheelhouse.ps1 -LocalRequirementsPath "C:\WheelHouseManager\Input\requirements.txt"
```

### Why "merge" instead of "replace"

The wheelhouse can hold **multiple versions of the same package** side by side - one user's
project may need `numpy==2.5.3`, another's `numpy==1.26.4`. Since a single `requirements.txt`
can't contain two versions of the same package name, the wheelhouse instead holds several
**group files**: `requirements-1.txt`, `requirements-2.txt`, etc. Merging decides, per package:

| Situation | Result |
|---|---|
| Exact duplicate (same name==version already present anywhere) | Skipped, logged |
| New package name | Added to the first group that doesn't already use that name |
| Same name, different version, already used everywhere | A brand-new group file is created |

`-LocalRequirementsPath` is **opt-in with no default** - omit it and the script just processes
the wheelhouse's existing group files as-is, without merging anything.

### What it does, in order

1. Integrity check (SHA256 vs. `manifest.json`) - stops immediately on any mismatch.
2. Merge (only if `-LocalRequirementsPath` was passed).
3. For **each** group file: compare against the manifest, audit (OSV + PyPI), cooldown check
   on new/changed packages, conditional download.
4. One manifest rebuild covering every group's downloads (direct + transitive dependencies).
5. One Microsoft Defender scan of the whole wheelhouse folder.

---

## 6. Scheduled Task - `Test-Wheelhouse.ps1`

**This, not `Update-Wheelhouse.ps1`, is what the Scheduled Task runs.** It only detects and
alerts - no merge, no download, no manifest changes, no Defender scan - so it's safe to leave
completely unattended on a schedule without risking a silent merge of an unapproved
`Input\requirements.in` edit.

### What it does

1. Integrity check (same as above) - aborts on mismatch.
2. Runs `pip-audit` against **every** group file, on every configured vulnerability service.
3. If anything is found, calls `Send-VulnerabilityAlert.ps1` once with every failing report.

### Manual setup (Task Scheduler GUI)

1. **Create Task** (not "Create Basic Task").
2. **General**: name it, **Run whether user is logged on or not**.
3. **Triggers**: Weekly, e.g. Sunday 02:00.
4. **Actions** → **Start a program**:
   - Program/script: `powershell.exe`
   - Arguments:
     ```
     -NoProfile -ExecutionPolicy Bypass -File "C:\WheelHouseManager\Jobs\Test-Wheelhouse.ps1"
     ```
   (No `-WheelhousePath` needed if `config\settings.psd1` already has it.)
5. **Settings**: check "Run task as soon as possible after a scheduled start is missed".
6. Save with an account that has whatever rights `pip-audit`/network access to the wheelhouse
   requires (no admin rights needed here, unlike a Defender scan - `Test-Wheelhouse.ps1` never
   runs one).

### PowerShell setup

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\WheelHouseManager\Jobs\Test-Wheelhouse.ps1"'
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2:00AM
$principal = New-ScheduledTaskPrincipal -UserId "DOMAIN\svc-wheelhouse" -LogonType Password
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable

Register-ScheduledTask -TaskName "Wheelhouse Weekly Audit" `
    -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description "Weekly wheelhouse integrity check and vulnerability audit, alerting on findings."
```

---

## 7. Manual runs, end to end

```powershell
cd C:\WheelHouseManager\Jobs

# 1. Edit Input\requirements.in, then resolve it
.\Update-Requirement.ps1

# 2. Review/approve Input\requirements.txt, then merge + process
.\Update-Wheelhouse.ps1 -LocalRequirementsPath "C:\WheelHouseManager\Input\requirements.txt"

# Optional: run just the audit + alert combo on demand, same as the Scheduled Task
.\Test-Wheelhouse.ps1

# Optional: run Update-Wheelhouse.ps1 AND automatically alert on whatever it finds, in one call
cd C:\WheelHouseManager
.\Invoke-WheelhousePipeline.ps1
```

`Invoke-WheelhousePipeline.ps1` auto-discovers whatever `Report_*-OSV_*.json` /
`Report_*-PYPI_*.json` files `Update-Wheelhouse.ps1` just wrote (by timestamp) and feeds them
into `Send-VulnerabilityAlert.ps1` automatically - it does **not** take a
`-LocalRequirementsPath` parameter itself; if you need to merge, run `Update-Wheelhouse.ps1`
directly with that parameter instead.

---

## 8. What happens when a vulnerability is detected

1. The relevant `pip-audit` step exits non-zero; findings are written to
   `Report_<...>-<group>-<OSV|PYPI>_<timestamp>.json`.
2. **During `Update-Wheelhouse.ps1`'s per-group processing**: that group's download is skipped
   entirely - nothing vulnerable is ever added to the wheelhouse.
3. **During `Test-Wheelhouse.ps1`'s scheduled check**: nothing is downloaded or removed (it
   never downloads anything at all) - this is purely detection.
4. Either way, `pip-audit --fix --dry-run` output is captured too (suggested safe versions,
   informational only - never applied automatically, since that would bypass the cooldown
   policy and change a requirements file without review).
5. `Send-VulnerabilityAlert.ps1` emails an HTML summary (if `SmtpServer` is configured) or saves
   it as `<wheelhouse>\reports\Alert_<timestamp>.html` - each finding includes the CVE/GHSA ID,
   description, suggested fix version, and the exact wheel filename(s) to quarantine (resolved
   from `manifest.json`).
6. **Nothing is quarantined or deleted automatically.** An admin reviews the alert and decides
   whether to update `Input\requirements.in`, re-resolve, get it approved, and re-run
   `Update-Wheelhouse.ps1` - subject to the same cooldown policy, or an explicit low
   `-MinimumPackageAgeDays` override for urgent cases.

An integrity-check failure (tampering/corruption) is a **separate** failure mode from a
vulnerability finding - it stops the relevant script immediately and is only visible via the
console log / `Report_Integrity_*.json` / the Scheduled Task's failure status, not via
`Send-VulnerabilityAlert.ps1` (which only understands `pip-audit`'s report format).

---

## 9. Design note: `functions.ps1` and future scripts

`Jobs\functions.ps1` holds every helper function used across the project, grouped by which
script owns each one (see the block comments inside the file). Many are entirely generic -
`Invoke-PipAudit`, `Get-RequirementsPackages`, `Confirm-PythonAndTooling`,
`Get-PipAuditReport` - and don't depend on `manifest.json` or the wheelhouse concept at all.
Others - `Save-Manifest`, `Test-ManifestIntegrity`, `Compare-RequirementsAgainstManifest`,
`Merge-LocalRequirements` - are wheelhouse-specific.

A future script (e.g. one that scans individual users' dev project folders for vulnerable
dependencies, once their storage location is confirmed) can dot-source the same
`functions.ps1` and reuse the generic functions directly, ignoring the wheelhouse-specific
ones - `Test-Wheelhouse.ps1` was itself built this way, adding no new shared functions of its
own beyond what `Update-Wheelhouse.ps1` had already established.
