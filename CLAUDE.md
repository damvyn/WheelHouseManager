# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`ARCHITECTURE.md` is the full developer reference (invariants, every function, core flows, data contracts, test conventions, how to extend); `README.md` is the user guide. Update both when behaviour changes.

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
- `Common`: logging, atomic writes, `Invoke-NativeCommand`, name/version/pin validation, locks (`Open-WheelhouseWrite`), exit codes;
- `Settings`;
- `Requirements`;
- `Manifest`;
- `Catalog`: `<wheelhouse>\catalog.json` (per-version state + latest audit/scan/PyPI results) and `events.jsonl` (history);
- `Journal`: `<wheelhouse>\.journal\` crash safety for publish/remove/restore;
- `Audit`;
- `Intake`: `Invoke-CandidateIntake` (checks, no lock) and `Publish-CandidateIntake` (write lock);
- `Sync`: `Invoke-WheelhouseSync`, the whole update run;
- `Alert`;
- `Run`: start/stop, transcript, report retention;
- `Denylist`: `config\denylist.json` (blocked name/version, `*` = every version);
- `Package`: inventory with audit/scan status, remove/quarantine/restore, `Add-RequirementInLine`;
- `Scan`: Defender scan (`Invoke-WheelhouseDefenderScan`);
- `Ui`: the HTTP API (route table `Get-WheelhouseUiRoute`, dispatcher `Invoke-WheelhouseUiApi`), background jobs and the `HttpListener` loop.

Static UI files live in `Jobs/WheelhouseManager/Web/` (plain HTML/JS/CSS, no build step) and deploy with the module folder.

A new function must also be added to `FunctionsToExport` in `WheelhouseManager.psd1`.

**Scripts are thin.** Each script in `Jobs/` imports the module via `$PSScriptRoot`. Every script follows the same shape:
1. `Resolve-WheelhouseParameter`, which applies the precedence explicit `-Param` > `config\settings.psd1` > `Get-WheelhouseDefaultSetting`. All defaults live only in that one function.
2. `Start-WheelhouseRun`, then `try`, then `finally { Stop-WheelhouseRun }`.

Functions `throw`; only scripts `exit`.

Script roles:
- `Update-Requirement.ps1`: `uv pip compile` turns `Input\requirements.in` into a candidate file. It is then checked with a `pip install --dry-run` against the target Python version and platform (`Test-RequirementWheelAvailability`), and only then becomes `Input\requirements.txt`. uv on its own accepts sdist-only packages and ignores the upper `Requires-Python` bound, which is why the pip check exists.
- `Update-Wheelhouse.ps1` frames the run (transcript, tooling check, exit code); `Invoke-WheelhouseSync` does the work:
  1. under the write lock: journal repair, integrity check against `manifest.json`, take out wheels removed/changed on the share (`Resolve-WheelhouseIntegrityProblem`, `AutoQuarantine`), catalog reconcile, group snapshot;
  2. an in-memory merge plan of `Input\requirements.txt` into the `requirements-N.txt` groups;
  3. per group, `Invoke-CandidateIntake` (no lock): denylist → audit → PyPI release data (yanked, cooldown `MinimumPackageAgeDays`, `-ExpeditePackage` skips it per pin) → download into `<manager root>\staging\` → sha256/yanked/upload-date check of each file against PyPI → Defender scan of the staged files; then `Publish-CandidateIntake` (write lock): denylist re-check → journal → `Publish-StagedWheel` (`.partial` copy, then rename) → manifest, then pins → catalog + history;
  4. an audit-only pass over existing groups;
  5. all audit results into the catalog (write lock). The share is never virus-scanned by this tool - the file server's antivirus does that; new wheels are scanned at intake, on-demand scans use hash-checked local copies (`Invoke-WheelhouseCopyScan`).

  It emits `Wheelhouse.AuditResult` and `Wheelhouse.Notice` objects and **sends no alerts**.
- `Invoke-WheelhousePipeline.ps1` (repo root, the orchestrator) runs `Update-Wheelhouse.ps1`, keeps its `Wheelhouse.AuditResult` and `Wheelhouse.Notice` output, and calls `Send-VulnerabilityAlert.ps1` once for any `Vulnerable`/`Error` result or notice.
- `Test-Wheelhouse.ps1` is what the Scheduled Task runs. It re-checks what is already published (integrity, denylist and PyPI yanked flag via `Get-DeployedPackageNotice`, audits, wheels missing/changed on the share), records the results in the catalog (`Update-WheelhouseCatalog`) and alerts: no merge, no download, no change to wheels, manifest or group files.
- `Test-WheelhousePackage.ps1` (audit the whole index or `-Package name==ver`, no alert) and `Invoke-WheelhouseScan.ps1` (Defender, whole folder or `-File`) back the UI's buttons.
- `Start-WheelhouseUI.ps1` starts the local web UI (`Start-WheelhouseUiServer`, `localhost` only, session token in the URL). It is a third thin layer: it runs the scripts above as child processes and calls module functions for reads and for remove/quarantine/restore, settings and denylist edits.

Invariants to preserve:
- **Group files only ever list pins whose wheel was actually downloaded.** Intake is transactional per package. A rejected package is written to `Report_Rejected_*.json` and never reaches a group file. Pins already in a group file but missing a wheel are fed back through intake as candidates.
- Groups are pinned and downloaded with `--no-deps --only-binary=:all:`. pip stops at the first unresolvable pin, so `Invoke-PipPinRetry` parses "No matching distribution found for X", drops X, and retries.
- **Nothing reaches the wheelhouse folder unchecked.** Downloads go to the staging folder (under the manager root, not `%TEMP%`: 8.3 short paths would not match Defender's detection paths) and are published only after every check. The manifest only gains the entries `Publish-CandidateIntake` returns as `Published` (verified against PyPI's sha256); the one exception is first-time setup, which adopts the wheels already there. New group numbers are max+1.
- Audit status is `Passed`/`Vulnerable`/`Error`. A failed audit is never reported as clean.
- **Wheels changed or removed on the share** (e.g. by the file server's antivirus): `Assert-WheelhouseIntegrity -AllowChangedFiles` returns Missing/Modified problems; `Resolve-WheelhouseIntegrityProblem -AutoQuarantine` takes a missing version out (pins + manifest, denylisted) and quarantines a modified one as evidence, emitting FileMissing/FileModified notices. With AutoQuarantine off the update stops, the scheduled check only reports. Unreadable/Malformed still fail closed.
- **Never assign to a script variable named like a validated parameter** (names are case-insensitive; a `ValidateSet` parameter rejects the value). A test checks this.
- **Exit codes** (`Get-WheelhouseExitCode`): 0 OK, 1 needs attention (findings, rejections), 2 error or a check could not be completed, 3 lock busy. UI jobs map 1 to the `Attention` status.
- Module functions must never invoke `Jobs\*.ps1` scripts. A script run from inside a module function executes in module scope and breaks `$script:` variables. Instead, the module builds parameters (`Get-VulnerabilityAlertParameter`) and the calling script runs `Send-VulnerabilityAlert.ps1`.
- Native commands (python, pip, uv) go through `Invoke-NativeCommand`. It merges stderr into stdout as text, because 5.1's `Start-Transcript` doesn't capture native stderr.
- **Denylist.** `Invoke-CandidateIntake` rejects a denylisted package first (before the audit). `Remove-WheelhousePackage` adds the removed/quarantined `name==version` automatically; `Restore-WheelhousePackage` lifts only the entry quarantining created. A damaged `denylist.json` throws - it is never read as empty.
- **Locks.** Every change to the manifest, group files, catalog, quarantine or history holds the write lock (`<wheelhouse>\.wheelhouse.lock`, delete-on-close), taken with `Open-WheelhouseWrite` (lock + `Repair-WheelhouseJournal`) and held only while files change; code that already holds it passes `-LockHeld`. Whatever was read before is re-read under the lock. `Invoke-WheelhouseSync` also holds the sync lock (`.wheelhouse-sync.lock`) for the whole run. UI actions fail at once on a busy lock; the update and checks wait up to 300 s. Remove/quarantine undo their earlier steps if a later one fails; deleting the file is always last.
- **Journal.** Publish, remove and restore write `<wheelhouse>\.journal\*.json` before their first step and delete it after the last; `Repair-WheelhouseJournal` rolls a leftover forward with the idempotent `Complete-*` functions (the same ones the normal publish/restore use). An unreadable or unfinishable journal stops every writer.
- **Catalog.** `catalog.json` is derived: `Sync-WheelhouseCatalog` rebuilds state, files and groups from manifest, group files and quarantine on every write; group files stay the source of group membership (clients install from them, so they are never regenerated). Only check results and history live in catalog/events alone. A failed audit or scan never refreshes a status, `last_run` or `last_ok`. A damaged catalog throws. Write history with `Write-WheelhouseEvent` / `Set-WheelhouseCatalogState`, under the write lock.
- **UI jobs run as child processes** started with `Start-Process` (never `& script` inside the module), one at a time. Package names and file names from a request are validated against the manifest and the shared patterns (`Test-WheelhousePackageName`, `Test-WheelhousePackageVersion`, `Test-WheelhouseWheelFileName`, `ConvertTo-WheelhousePin`) before they reach a command line. A new endpoint is an entry in `Get-WheelhouseUiRoute` with `Wheelhouse`/`Idle` flags. State-changing API calls need the session token, a JSON content type and a same-origin `Origin`.
- Restrictions (cooldown, audit, wheel-only) apply to wheelhouse packages only. Self-updating pip/pip-audit in `Confirm-PythonAndTooling` is intended.

## Windows PowerShell 5.1 compatibility

The scripts target 5.1, so watch for these pitfalls:
- **Keep every source file ASCII.** 5.1 reads a BOM-less `.ps1` as ANSI.
- **`ConvertFrom-Json` in 5.1 emits a JSON array as a single object.** Flatten it with `foreach`, not `@()`.
- **Enable TLS 1.2 explicitly** via `[Net.ServicePointManager]` before any web request.
- **Avoid `@(...)` around a function that returns `Write-Output -NoEnumerate`**, because it double-wraps the array. Assign it to a `[string[]]` variable instead.
- **Use `$PSBoundParameters.ContainsKey()`, not `.Contains()`.**
- **PowerShell 7's `ConvertFrom-Json` turns ISO date strings into `[datetime]`**; 5.1 keeps text. Never `[string]`-cast a timestamp read from JSON (it becomes `10/31/2026 15:55:17`): use `ConvertTo-IsoTimestamp` (catalog records are normalized on read by `ConvertTo-CatalogCheck`) or `ConvertTo-UtcDateTime`.
- **A one-element array inside `$(if ...)` is unrolled to a scalar** and becomes a JSON string. Build lists with plain assignments before putting them in an object the UI serializes.
- **Don't wrap the `-NoEnumerate` readers in `@()` or pipe them straight into `ForEach-Object`** (`Read-WheelhouseManifest`, `Get-WheelhouseGroupFile`, `Get-UntrackedWheelFile`, `Test-ManifestIntegrity`, `Merge-WheelhouseManifest`) - assign them to a variable first. The newer `Read-WheelhouseDenylist` / `Read-QuarantineRecord` return plain arrays and are fine inside `@()`.

## Tests

All tests live in `Tests/WheelhouseManager.Tests.ps1`.
- Mock bodies execute in module scope, so they cannot see helper functions defined in the test. Tests pass data to and from mocks through `$global:Whm*` variables, which `AfterAll` cleans up.
- Don't use `Assert-MockCalled` (removed in Pester 6). Record calls in globals and assert on those instead.
- A global `python` stub is added when python isn't installed, because Pester can only mock commands that exist.
- UI job tests start real child PowerShell processes from throw-away scripts; API tests call `Invoke-WheelhouseUiApi` directly with a temp manager root (and mock `Start-WheelhouseUiJob`). Defender is faked through `Test-WheelhouseDefenderAvailable` / `Invoke-MpScan` / `Get-WheelhouseThreatDetection`.
- Intake/sync tests use `New-TestRelease` and the shared mock bodies (`$script:intakeAgeMock`, `$script:intakeDownloadMock`, `$script:intakeScanMock`); `Invoke-TestIntake` runs check + publish. Pass `-StagingRoot` and `-DenylistPath` inside the test folder. Journal tests write a journal by hand and run the repair.
