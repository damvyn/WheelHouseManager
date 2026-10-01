# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A PowerShell tool that maintains an offline, audited pip/uv "wheelhouse" (a folder of `.whl` files on a share) for locked-down Windows clients. There are two independent parts:
- `Client Install/`: scripts that install uv and lock clients to the wheelhouse through GPO. They are deployed separately. **Leave `Startup_UV.ps1` unchanged.**
- The manager: `Setup.ps1`, `Invoke-WheelhousePipeline.ps1` and `Jobs/`. `Setup.ps1` deploys it to `C:\WheelHouseManager` (by default) alongside `config\settings.psd1` (and `config\denylist.json`, created on first use) and `Input\`.

## Commands

Tests use Pester 5+ (CI installs the latest, currently 6.x). The Pester 3.4 that ships with Windows can't run them.

```powershell
Invoke-Pester -Path .\Tests                                              # all tests
Invoke-Pester -Path .\Tests -FullNameFilter '*Invoke-CandidateIntake*'   # single Context/It (Pester 5)
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
```

CI (`.github/workflows/powershell-tests.yml`) runs on `windows-latest` under **both Windows PowerShell 5.1 and PowerShell 7**. It runs these checks:
- Pester;
- that every name in `FunctionsToExport` is actually exported;
- a parse check of every `.ps1`/`.psm1`;
- PSScriptAnalyzer at Warning/Error severity, with no findings allowed.

## Architecture

**The `Jobs/WheelhouseManager` module holds all logic.** `WheelhouseManager.psm1` dot-sources `Functions/*.ps1`, which are split by domain:
- `Common`: logging, atomic writes, `Invoke-NativeCommand`;
- `Settings`;
- `Requirements`;
- `Manifest`;
- `Audit`;
- `Intake`;
- `Alert`;
- `Run`: start/stop, transcript, report retention;
- `Denylist`: `config\denylist.json` (blocked name/version, `*` = every version);
- `Package`: inventory with audit/scan status, remove/quarantine/restore, `Add-RequirementInLine`;
- `Scan`: Defender scan (`Invoke-WheelhouseDefenderScan`);
- `Ui`: the HTTP API (`Invoke-WheelhouseUiApi`), background jobs and the `HttpListener` loop.

Static UI files live in `Jobs/WheelhouseManager/Web/` (plain HTML/JS/CSS, no build step) and deploy with the module folder.

A new function must also be added to `FunctionsToExport` in `WheelhouseManager.psd1`.

**Scripts are thin.** Each script in `Jobs/` imports the module via `$PSScriptRoot`. Every script follows the same shape:
1. `Resolve-WheelhouseParameter`, which applies the precedence explicit `-Param` > `config\settings.psd1` > `Get-WheelhouseDefaultSetting`. All defaults live only in that one function.
2. `Start-WheelhouseRun`, then `try`, then `finally { Stop-WheelhouseRun }`.

Functions `throw`; only scripts `exit`.

Script roles:
- `Update-Requirement.ps1`: `uv pip compile` turns `Input\requirements.in` into a candidate file. It is then checked with a `pip install --dry-run` against the target Python version and platform (`Test-RequirementWheelAvailability`), and only then becomes `Input\requirements.txt`. uv on its own accepts sdist-only packages and ignores the upper `Requires-Python` bound, which is why the pip check exists.
- `Update-Wheelhouse.ps1` (the worker) does:
  1. an integrity check against `manifest.json`;
  2. an in-memory merge plan of `Input\requirements.txt` into the `requirements-N.txt` groups;
  3. per group, `Invoke-CandidateIntake`: audit → cooldown (`MinimumPackageAgeDays`) → download;
  4. an audit-only pass over existing groups;
  5. a manifest update and a Defender scan.

  It emits `Wheelhouse.AuditResult` objects and **sends no alerts**.
- `Invoke-WheelhousePipeline.ps1` (repo root, the orchestrator) runs `Update-Wheelhouse.ps1`, keeps its `Wheelhouse.AuditResult` output, and calls `Send-VulnerabilityAlert.ps1` once for any `Vulnerable`/`Error` result.
- `Test-Wheelhouse.ps1` is what the Scheduled Task runs. It only checks integrity, audits and alerts: no merge, no download.
- `Test-WheelhousePackage.ps1` (audit the whole index or `-Package name==ver`, no alert) and `Invoke-WheelhouseScan.ps1` (Defender, whole folder or `-File`) back the UI's buttons.
- `Start-WheelhouseUI.ps1` starts the local web UI (`Start-WheelhouseUiServer`, `localhost` only, session token in the URL). It is a third thin layer: it runs the scripts above as child processes and calls module functions for reads and for remove/quarantine/restore, settings and denylist edits.

Invariants to preserve:
- **Group files only ever list pins whose wheel was actually downloaded.** Intake is transactional per package. A rejected package is written to `Report_Rejected_*.json` and never reaches a group file. Pins already in a group file but missing a wheel are fed back through intake as candidates.
- Groups are pinned and downloaded with `--no-deps --only-binary=:all:`. pip stops at the first unresolvable pin, so `Invoke-PipPinRetry` parses "No matching distribution found for X", drops X, and retries.
- The manifest only gains files downloaded in the current run. New group numbers are max+1.
- Audit status is `Passed`/`Vulnerable`/`Error`. A failed audit is never reported as clean.
- Module functions must never invoke `Jobs\*.ps1` scripts. A script run from inside a module function executes in module scope and breaks `$script:` variables. Instead, the module builds parameters (`Get-VulnerabilityAlertParameter`) and the calling script runs `Send-VulnerabilityAlert.ps1`.
- Native commands (python, pip, uv) go through `Invoke-NativeCommand`. It merges stderr into stdout as text, because 5.1's `Start-Transcript` doesn't capture native stderr.
- **Denylist.** `Invoke-CandidateIntake` rejects a denylisted package first (before the audit). `Remove-WheelhousePackage` adds the removed/quarantined `name==version` automatically; `Restore-WheelhousePackage` lifts only the entry quarantining created. A damaged `denylist.json` throws - it is never read as empty.
- **Lock.** Whatever rewrites the manifest or group files holds `Enter-WheelhouseLock` (`<wheelhouse>\.wheelhouse.lock`, delete-on-close): `Update-Wheelhouse.ps1`, `Remove-WheelhousePackage`, `Restore-WheelhousePackage`. Remove/quarantine undo their earlier steps if a later one fails; deleting the file is always last.
- **UI jobs run as child processes** started with `Start-Process` (never `& script` inside the module), one at a time. Package names and file names from a request are validated against the manifest and a strict pattern before they reach a command line. State-changing API calls need the session token, a JSON content type and a same-origin `Origin`.
- Restrictions (cooldown, audit, wheel-only) apply to wheelhouse packages only. Self-updating pip/pip-audit in `Confirm-PythonAndTooling` is intended.

## Windows PowerShell 5.1 compatibility

The scripts target 5.1, so watch for these pitfalls:
- **Keep every source file ASCII.** 5.1 reads a BOM-less `.ps1` as ANSI.
- **`ConvertFrom-Json` in 5.1 emits a JSON array as a single object.** Flatten it with `foreach`, not `@()`.
- **Enable TLS 1.2 explicitly** via `[Net.ServicePointManager]` before any web request.
- **Avoid `@(...)` around a function that returns `Write-Output -NoEnumerate`**, because it double-wraps the array. Assign it to a `[string[]]` variable instead.
- **Use `$PSBoundParameters.ContainsKey()`, not `.Contains()`.**
- **PowerShell 7's `ConvertFrom-Json` turns ISO date strings into `[datetime]`**; 5.1 keeps text. Use `ConvertTo-IsoTimestamp` before sending a date to the UI.
- **A one-element array inside `$(if ...)` is unrolled to a scalar** and becomes a JSON string. Build lists with plain assignments before putting them in an object the UI serializes.
- **Don't wrap the `-NoEnumerate` readers in `@()`** (`Read-WheelhouseManifest`, `Get-WheelhouseGroupFile`, `Get-UntrackedWheelFile`, `Test-ManifestIntegrity`) - assign them to a variable first. The newer `Read-WheelhouseDenylist` / `Read-QuarantineRecord` return plain arrays and are fine inside `@()`.

## Tests

All tests live in `Tests/WheelhouseManager.Tests.ps1`.
- Mock bodies execute in module scope, so they cannot see helper functions defined in the test. Tests pass data to and from mocks through `$global:Whm*` variables, which `AfterAll` cleans up.
- Don't use `Assert-MockCalled` (removed in Pester 6). Record calls in globals and assert on those instead.
- A global `python` stub is added when python isn't installed, because Pester can only mock commands that exist.
- UI job tests start real child PowerShell processes from throw-away scripts; API tests call `Invoke-WheelhouseUiApi` directly with a temp manager root (and mock `Start-WheelhouseUiJob`). Defender is faked through `Test-WheelhouseDefenderAvailable` / `Invoke-MpScan` / `Get-WheelhouseThreatDetection`.
