# Wheelhouse Automation - README

This repository covers two related but separate parts of the same deployment:

1. **Client-side uv installation** on non-persistent Windows VDI hosts (`UV_Installer.ps1` +
   `Startup_UV.ps1`), which locks clients to a single, internal, audited package source.
2. **Server-side wheelhouse automation** (`Wheelhouse-Common.ps1`, `Update-Wheelhouse.ps1`,
   `Send-VulnerabilityAlert.ps1`, `Invoke-WheelhousePipeline.ps1`), which populates and audits
   that internal package source (the "wheelhouse").

---

## 1. Installing uv on client machines

Two scripts are involved, each with a different deployment mechanism.

### 1.1 `UV_Installer.ps1` - installs the uv binaries

Packaged as a  software deployment script (see the `.version` stamp file and
`<AppVersion>` placeholder, which packaging tooling fills in at build time). It:

- Extracts `uv-x86_64-pc-windows-msvc.zip` (must sit next to the script) into
  `C:\Program Files\astral.sh\uv`.
- Skips reinstalling if a version stamp file already matches the target version.
- Creates **hardlinks** for `uv.exe`, `uvw.exe`, `uvx.exe` into `C:\Windows\System32` instead of
  modifying the system `PATH` - `System32` is already on `PATH` for every user, and hardlinks
  work here because both locations are on the same volume.
- Logs to `%WinDir%\Logs\Astral-uv-<version>_Script.txt`.

Deploy this through software distribution tool your organization uses as
a standard application package targeting the VDI golden image or machine pool.

### 1.2 `Startup_UV.ps1` - locks down configuration via Group Policy

**This script runs as a Group Policy Computer Startup Script**, not as a login script or a
manually-run tool. That placement matters:

- Computer startup scripts run as **SYSTEM**, at boot, **before any user logs on** - so the
  environment variables and `uv.toml` are guaranteed to be in place before any user session ever
  touches `uv`.
- Because it's a *machine* policy (not a per-user one), a standard user cannot override it by
  setting their own environment variables or editing their own `uv.toml` - `Startup_UV.ps1`
  writes to `%ProgramData%\uv\uv.toml`, which ordinary users can't modify.

What it sets, all at machine scope:

| Setting | Value | Purpose |
|---|---|---|
| `UV_PYTHON_DOWNLOADS` | `never` | Blocks `uv python install` from ever downloading a Python interpreter |
| `UV_PYTHON_PREFERENCE` | `only-system` | Never resolve to a uv-managed Python; only pre-installed interpreters |
| `UV_LINK_MODE` | `copy` | Cache and target venv are on different filesystems (local cache vs. FSLogix/network profile), so hardlinking isn't possible anyway |
| `UV_CACHE_DIR` | `C:\uv-cache` | Local, ephemeral cache (not on the roaming/FSLogix profile) |
| `UV_NO_INDEX` | `true` | Blocks the default PyPI index entirely |
| `%ProgramData%\uv\uv.toml` | flat index pointing at the wheelhouse | The **only** package source clients can use |

**Before deploying:** edit the placeholder in `Startup_UV.ps1`:

```powershell
'url = "\\\\server\\pathToWheelHouse"',
```

Replace `\\server\pathToWheelHouse` with your actual wheelhouse UNC path (the quadrupled
backslashes are PowerShell/TOML escaping - keep that pattern, just change the path itself).

### GPO deployment steps

1. Edit the wheelhouse path placeholder in `Startup_UV.ps1` (see above).
2. Open **Group Policy Management Console** and create or edit a GPO linked to the VDI OU.
3. Navigate to **Computer Configuration → Policies → Windows Settings → Scripts (Startup/Shutdown) → Startup**.
4. Add `Startup_UV.ps1` as a PowerShell Script (**PowerShell Scripts** tab, not the legacy Scripts tab).
5. Ensure `UV_Installer.ps1` is deployed to the same machines - order doesn't
   strictly matter between the two, since the startup script only configures environment/config
   and doesn't depend on `uv.exe` already existing, but both must be present before a user
   actually tries to run `uv`.
6. Run `gpupdate /force` on a test machine (or reboot it) and confirm:
   ```powershell
   Test-Path "C:\Windows\System32\uv.exe"
   $env:UV_NO_INDEX
   Get-Content "$env:ProgramData\uv\uv.toml"
   ```

---

## 2. Installing dependencies on the build server

The build server (separate from the VDI clients - this is the machine that populates the
wheelhouse) needs Python, pip, uv (as a resolver only), and pip-audit.

### Manual installation

1. Download and run the Python installer from [python.org](https://www.python.org/downloads/)
   (check "Add python.exe to PATH" during setup).
2. Open a new PowerShell window and confirm:
   ```powershell
   python --version
   ```
3. Install `uv` and `pip-audit` via pip:
   ```powershell
   python -m pip install --upgrade pip
   python -m pip install uv pip-audit
   ```
4. Confirm:
   ```powershell
   uv --version
   pip-audit --version
   ```

### PowerShell (scripted) installation

```powershell
# Assumes Python is already installed and on PATH; installs/updates the rest
python -m pip install --upgrade pip
python -m pip install --upgrade uv pip-audit
```

Wrap this in a scheduled maintenance task of its own if you want `uv`/`pip-audit` kept current
automatically - the wheelhouse scripts already self-check and self-update `pip` and `pip-audit`
on every run (see `Confirm-PythonAndTooling` in `Wheelhouse-Common.ps1`), but they don't
currently self-update `uv` itself.

---

## 3. Installing the wheelhouse script package

Four files, and **all four must live in the same folder** (they locate each other via
`$PSScriptRoot`):

```
Wheelhouse-Common.ps1
Update-Wheelhouse.ps1
Send-VulnerabilityAlert.ps1
Invoke-WheelhousePipeline.ps1
```

### Manual installation

1. Create a folder on the build server, e.g. `C:\WheelhouseScripts`.
2. Copy all four `.ps1` files into it (drag-and-drop in Explorer, or however you normally
   transfer files to this server).
3. Unblock them if they were downloaded from the internet or copied from another machine:
   ```powershell
   Get-ChildItem "C:\WheelhouseScripts\*.ps1" | Unblock-File
   ```

### PowerShell installation

```powershell
$destination = "C:\WheelhouseScripts"
New-Item -ItemType Directory -Path $destination -Force | Out-Null

Copy-Item -Path @(
    "Wheelhouse-Common.ps1",
    "Update-Wheelhouse.ps1",
    "Send-VulnerabilityAlert.ps1",
    "Invoke-WheelhousePipeline.ps1"
) -Destination $destination -Force

Get-ChildItem "$destination\*.ps1" | Unblock-File
```

---

## 4. Creating the Scheduled Task

The recommended cadence is **weekly**, running `Invoke-WheelhousePipeline.ps1` (which chains
`Update-Wheelhouse.ps1` and, when needed, `Send-VulnerabilityAlert.ps1` automatically).

### Manual setup (Task Scheduler GUI)

1. Open **Task Scheduler** → **Create Task** (not "Create Basic Task" - you need the extra tabs).
2. **General** tab: name it (e.g. `Wheelhouse Weekly Maintenance`), select **Run whether user is
   logged on or not**, and **Run with highest privileges** (required for the Microsoft Defender
   scan step).
3. **Triggers** tab → **New** → Weekly, pick a day/time (e.g. Sunday 02:00).
4. **Actions** tab → **New** → **Start a program**:
   - Program/script: `powershell.exe`
   - Add arguments:
     ```
     -NoProfile -ExecutionPolicy Bypass -File "C:\WheelhouseScripts\Invoke-WheelhousePipeline.ps1" -WheelhousePath "\\server\share\wheelhouse"
     ```
5. **Conditions** tab: uncheck "Start the task only if the computer is on AC power" if this is a
   server (usually irrelevant, but worth checking).
6. **Settings** tab: check "Run task as soon as possible after a scheduled start is missed" so a
   missed week (server down, etc.) still catches up.
7. Save, entering credentials for an account with local admin rights on this server (needed for
   `Start-MpScan`).

### PowerShell setup

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\WheelhouseScripts\Invoke-WheelhousePipeline.ps1" -WheelhousePath "\\server\share\wheelhouse"'

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2:00AM

$principal = New-ScheduledTaskPrincipal -UserId "DOMAIN\svc-wheelhouse" -LogonType Password -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable

Register-ScheduledTask -TaskName "Wheelhouse Weekly Maintenance" `
    -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description "Weekly wheelhouse audit, cooldown check, download, and vulnerability alert."
```

You'll be prompted for the service account's password when registering with `-LogonType
Password`. The account needs local admin rights on this server for the Defender scan step.

---

## 5. Using `requirements.in` and `requirements.txt`

These are **two different files with two different purposes** - don't confuse them.

| File | Contains | Who reads it |
|---|---|---|
| `requirements.in` | Unpinned package names (optionally with version ranges) | You, when resolving - never fed directly to the wheelhouse scripts |
| `requirements.txt` | Exact pins (`name==version`), resolved from the `.in` file | Placed inside the wheelhouse root; read by `Update-Wheelhouse.ps1` |

### Example `requirements.in`

```
numpy
pandas
scipy
pyyaml
jupyter
```

### Resolving it into `requirements.txt`

Run this on the build server, using `uv` purely as a resolver (nothing gets installed locally):

```powershell
uv pip compile requirements.in `
    --exclude-newer "10 days" `
    --python 3.14 `
    -o requirements.txt
```

- `--exclude-newer "10 days"` enforces the cooldown policy at resolution time - only versions
  published more than 10 days ago are even considered candidates.
- `--python 3.14` targets the same Python version the wheelhouse itself is standardized on
  (**major.minor only** - never a full patch version like `3.14.7`, since wheel compatibility
  tags don't encode the patch level).

### Example resulting `requirements.txt`

```
numpy==2.5.3
pandas==3.0.5
scipy==1.18.1
pyyaml==6.0.3
jupyter==1.1.1
```

### Where it goes

```powershell
Copy-Item requirements.txt "\\server\share\wheelhouse\requirements.txt"
```

`Update-Wheelhouse.ps1` always reads `requirements.txt` from inside the wheelhouse root - it
never looks at `requirements.in`, which exists purely as your own working/source file.

---

## 6. Manual run

You can trigger the exact same pipeline the scheduled task uses, in two ways:

### Via the Scheduled Task itself

```powershell
Start-ScheduledTask -TaskName "Wheelhouse Weekly Maintenance"
```

Useful when you've just edited `requirements.txt` and don't want to wait for the weekly trigger,
while still running under the task's configured account/permissions and logging the same way.

### Directly from the command line

```powershell
cd C:\WheelhouseScripts
.\Invoke-WheelhousePipeline.ps1 -WheelhousePath "\\server\share\wheelhouse"
```

Or, to run just the maintenance step without the alert step (e.g. for debugging):

```powershell
.\Update-Wheelhouse.ps1 -WheelhousePath "\\server\share\wheelhouse"
```

Both accept the same optional parameters (`-PythonVersion`, `-Platform`,
`-MinimumPackageAgeDays`, `-VulnerabilityServices`) if you need to override a default for a
one-off run.

---

## 7. What actually happens

### On every run (manual or scheduled), the sequence is the same

1. **Integrity check** - every file tracked in `manifest.json` is re-hashed (SHA256) and compared
   against the recorded value. Any mismatch or missing file **stops the run immediately** -
   nothing else executes until this is investigated manually.
2. **Compare `requirements.txt` against the manifest** - checks that every required
   package/version has a manifest entry matching the target Python/platform tag (`abi3` wheels
   are accepted regardless of their specific `cp3xx` tag, since they're forward-compatible by
   design).
3. **Branch automatically:**
   - **Nothing changed** → lightweight audit-only pass: re-run `pip-audit` (both configured
     vulnerability services) against the existing `requirements.txt`, no download, no Defender
     scan.
   - **Something changed** (new/updated packages, or first-time setup with an empty wheelhouse)
     → full pipeline: pre-download audit → 10-day cooldown check on the new/changed packages
     only → conditional `pip download` → manifest rebuild (direct + transitive dependencies,
     fresh SHA256 hashes) → Microsoft Defender scan of the wheelhouse folder.
4. Full console output is saved to `<wheelhouse>\reports\Log_<timestamp>.txt` (logs older than 6
   months are cleaned up automatically). Audit/age/integrity results are saved as separate
   `Report_*.json` files in the same folder.

### Manual run specifically

Identical behavior to the scheduled task - there is no separate "manual mode." The only
practical differences are: you see the console output live, and you can override parameters
(e.g. a lower `-MinimumPackageAgeDays` for an urgent fix) for that one invocation without
touching the scheduled task's configuration.

### Scheduled task run specifically

Same pipeline, unattended:

- Runs as the configured service account, with highest privileges (needed for the Defender scan).
- Nobody is watching the console, so the transcript log (`Log_*.txt`) and the `Report_*.json`
  files are the only record - check the reports folder after each run if you're not otherwise
  notified.
- `Invoke-WheelhousePipeline.ps1` additionally auto-discovers any `Report_*-OSV_*.json` /
  `Report_*-PYPI_*.json` files written during that specific run (by timestamp) and feeds them
  straight into `Send-VulnerabilityAlert.ps1` - no manual step needed to trigger the alert.

### When a vulnerability is detected

1. The relevant `pip-audit` step exits non-zero; the affected package(s) and vulnerability
   ID(s) are written to `Report_<...>-<OSV|PYPI>_<timestamp>.json`.
2. **If this happened during the full pipeline** (new/changed packages): the download step is
   **skipped entirely** - nothing vulnerable is ever added to the wheelhouse. The run ends with a
   non-zero exit code.
3. **If this happened during the audit-only pass** (already-deployed packages, re-audited
   periodically): nothing is removed or downloaded automatically - the wheelhouse continues
   serving what it already has. This is a detection-only path; remediation is manual.
4. Either way, `pip-audit --fix --dry-run` output is also captured, showing suggested safe
   versions (informational only - never applied automatically, since an automatic version bump
   would bypass the cooldown policy and change `requirements.txt` without review).
5. `Send-VulnerabilityAlert.ps1` parses the audit report(s) and either emails an HTML summary
   (if `-SmtpServer` is configured) or saves it as `<wheelhouse>\reports\Alert_<timestamp>.html`
   for manual review - each finding includes the CVE/GHSA ID, description, suggested fix version
   (if any), and the exact wheel filename(s) to move into quarantine, resolved from
   `manifest.json`.
6. **Nothing is quarantined or deleted automatically.** An admin reviews the alert, decides
   whether to update `requirements.txt` to a fixed version (subject to the same cooldown policy,
   or with an explicit low `-MinimumPackageAgeDays` override for urgent cases), and re-runs the
   pipeline to pick up the fix.
