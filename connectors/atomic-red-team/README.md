# Atomic Red Team — BAS / AEV runner

`atomic-red-team` · **import** connector · category **Adversary Emulation** · ⚠️ **intrusive** (engagement scope enforced)

Runs [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) atomic tests on the (possibly **remote**) worker host and reports the per-test outcome back to XORCISM's emulation layer (`XTHREAT.EMULATIONRUN` / `EMULATIONRESULT`), which powers the **ATT&CK validation-coverage heatmap** (`/attack`). This is the **validate** stage of CTEM / **Adversarial Exposure Validation (AEV)** — safely run a known attack technique on an authorized host and see whether your controls *prevent* or *detect* it.

It wraps the canonical **`Invoke-AtomicTest`** executor (the standard `Invoke-AtomicRedTeam` PowerShell module defenders already use), so XORCISM ships **no novel offensive code**. Full ATT&CK coverage comes from importing the ART library into `ATOMICTEST` with `xorcism_python/importers/import_atomics.py` (`--download`, needs PyYAML).

> **Remote execution:** run `connectors/runner.py` in remote-worker mode on the target host (a Kali box, an agent VM, or the asset itself). The job queue, engagement scope and database stay centralized in XORCISM; the atomic executes on the remote worker.

## Safety — it does NOT execute by default, and live execution is ROE-gated

| `execute` | Behaviour |
|-----------|-----------|
| `false` (**default**) | **Plan / check only** — lists the atomics for the technique (`-ShowDetailsBrief`) and optionally checks prerequisites (`-CheckPrereqs`). **Nothing is run.** Outcome = `Planned`. |
| `true` | **Actually runs** the atomics (`Invoke-AtomicTest -Confirm:$false`), then optionally `-Cleanup`. |

**Authorization for live execution (`execute=true`):** you must supply a **`target`** host, and that host must be inside an **active engagement scope (ROE)**. This is enforced at three layers:

1. the connector refuses to execute with no `target`;
2. the API (`POST /api/connectors/run`, **admin only**) requires an active engagement and rejects a target that is not in its scope (audited as `connector_out_of_scope`);
3. the worker (`runner.py`) **re-validates** the target against the engagement scope and refuses out-of-scope (`PermissionError`).

So execution is *allowed* — but only against hosts you have explicitly authorized, and every run is audited. (Importing a saved result `file` is not execution and is exempt.)

## Parameters

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `technique` | string | — | ATT&CK technique, e.g. `T1059.001` |
| `target` | target | — | Host the atomic runs **on** (the worker's own host). **Required to execute** — must be in the engagement scope. Leave empty for plan/check. |
| `test_guids` | string | — | Optional comma-separated atomic GUIDs to limit to specific tests |
| `execute` | bool | `false` | `false` = plan/check; `true` = run (requires `target` in an active engagement) |
| `check_prereqs` | bool | `true` | In plan mode, also run `-CheckPrereqs` |
| `cleanup` | bool | `false` | After execution, run the atomic's `-Cleanup` |
| `file` | file | — | Offline: a saved atomic-result export to import instead of running |

## Modes

1. **Live** — `Invoke-AtomicTest` present + a `technique` → plan (default) or execute.
2. **Offline** — `file` = a saved result export (list or `{ results: [...] }`).
3. **Demo** — neither → a built-in 2-atomic simulated sample (Outcome `No result (simulated)`), so the import path + coverage heatmap are exercisable without running anything.

## How it works

`run.py` returns `{ "emulation_results": [ {technique, atomic_guid, name, executor, outcome, detail, host}, … ], host, scenario, executed }`. The runner routes `emulation_results` through `runner.import_emulation` → one `EMULATIONRUN` + one `EMULATIONRESULT` per atomic (resolving `ATOMICTEST` by GUID and `AttackTechniqueID` from `ATTACKTECHNIQUE`, the run's target asset from the host name, and a coverage **Score** = % executed). The connector performs **no database access** itself (worker-safe). Required permission: `connector:atomic-red-team`.
