# Decompilation MCP Server

Coordinate Fallout: New Vegas matching decompilation with web/CLI agents and a
CPU-only C++ pattern/search engine. Agents claim functions, read compiler and
CPU/Ghidra context, check candidates, share unfinished work, and submit verified
matches through one durable coordinator.

**Windows-first, self-hosted community tooling.** This is reusable tooling, not a
game source release. No account, API key, game executable, compiler, context pack,
checker download, solved contribution, personal settings, or worker history is
included. Each operator uses their own approved FNV account and licensed inputs.

## What is included

- Streamable HTTP and stdio MCP server with per-agent assignment ownership.
- One service writer, durable request IDs/receipts, web-first dispatch, and
  quarantine instead of replay for uncertain mutations.
- CPU pattern recognition and bounded compiler search, partial analysis, and
  optional Ghidra drafts. No paid or local LLM is required by the coordinator.
- Official compiler/checker wrappers, hash-bound provenance and fresh submission
  rechecking. A diagnostic score or sampled/SMT agreement never authorizes upload.
- Optional checkpoint/history support. Optional feature cooldowns are independent
  of core work; actual global/account/provider limits are always respected.
- Privacy checks, synthetic tests, and Windows CI.

## Requirements

Windows 10/11, Python **3.12**, PowerShell **7** (`pwsh.exe`), Git, and Windows
`tar`. Install 7-Zip if using the compiler extraction helper. You also need:

1. Your approved account at [fnvdecomp.com](https://fnvdecomp.com/join), with terms
   accepted personally and your own API key.
2. Your installed game and a private reference image that passes the official
   checker's fingerprint check. Do not distribute either.
3. **Microsoft VC++ 2008 SP1 15.00.30729.01**, x86 compiler, CRT and SDK headers/libs
   arranged under `tools/vc2008/VC/`. This version is required for matching.
4. The latest official checker and metadata obtained through your authenticated
   service packet. They are downloaded by you, not redistributed here.

Optional: Ghidra and the JDK required by its release, with `GHIDRA_HOME` and
`JAVA_HOME`. Missing/busy Ghidra is advisory; invalid compiler/image/context
evidence still fails closed. Optional expression filtering can use `z3-solver`;
NumPy is included. PyTorch/CUDA is not needed for the CPU workflow.

## Install and configure

Run from the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\scripts\configure.ps1 -GameExe 'C:\Games\Fallout New Vegas\FalloutNV.exe' -SetApiKey
```

The prompt hides your API key and stores it using Windows DPAPI in ignored
`local/`. Configuration refuses to overwrite an existing workspace. CPU claiming
starts **disabled**. Do not copy another operator's `local/`, `work/`, or `tools/`.

Install your licensed toolchain manually in the layout above, or review and run
`scripts/install-toolchain.ps1`. That helper downloads Microsoft's installer and
extracts only local compiler/SDK files; applicable software licenses still apply.

### Official checker and shared metadata

Follow the [official contributor guide](https://fnvdecomp.com/agents.md). Obtain
an authenticated packet through your own account, then save its JSON privately
as `local/packet.json`. Do not invent download URLs or copy someone else's pack.
If onboarding requires a bootstrap claim, keep the coordinator stopped, record
that claim, and release/reconcile it before starting the coordinator. Claim leases
and current API limits come from the service, not historical values in examples.

```powershell
.\scripts\download-shared.ps1 -Packet local/packet.json
.\scripts\refresh-checker.ps1 -Packet local/packet.json
$stage = (Get-Content local/checker-capabilities.json -Raw | ConvertFrom-Json).stage
.\.venv\Scripts\python.exe scripts/install-checker.py --stage $stage
```

The installer verifies the authenticated staging hashes and preserves comparison,
source rules, function spans and fingerprints. Its Windows compiler and advisory
lock adapters change execution/locking only. It refuses to overwrite a checker.
Keep the checker README/license from the downloaded archive private with it.

If your on-disk executable is protected, launch your game normally and use the
read-only `capture-runtime-image.py` helper on its process ID. It creates a private
copy, never changes the installed executable or process memory. Set
`checker_image` in `local/settings.json` to the output. Follow the official
checker README to run **`--check-image`** and require all fingerprints to pass.

```powershell
.\scripts\doctor.ps1
.\scripts\start.ps1 check
```

`check` only validates files; it makes no service requests and does not claim.
Real readiness additionally requires a successful image check and a compile of
your own packet with the required compiler.

## Run MCP and the coordinator

Use two terminals from the repository root:

```powershell
# Terminal 1: the ONLY service writer for this workspace/account
.\scripts\start.ps1 coordinator

# Terminal 2: MCP HTTP listener
.\scripts\start.ps1 server
```

The HTTP listener binds **127.0.0.1:8766**, endpoint `/mcp`, liveness `/healthz`.
The coordinator enforces an OS writer lock. Do not run a second account-mutating
coordinator or invoke service helpers independently while it runs.

An MCP client can instead launch stdio:

```json
{
  "mcpServers": {
    "fnv-decompile": {
      "command": "C:/path/to/repo/.venv/Scripts/python.exe",
      "args": ["C:/path/to/repo/scripts/fnv-mcp-server.py"]
    }
  }
}
```

Stdio still needs the separately running coordinator. Client configuration syntax
varies; use your client's MCP instructions. No specific model provider is required.

### Remote access

Keep the listener on loopback. For web agents, place it behind your own HTTPS
reverse proxy/tunnel and access control. Configure **your own** exact host/origin
allowlists; no personal public endpoint is built in:

```powershell
$env:FNV_MCP_ALLOWED_HOSTS = '["mcp.example.org","mcp.example.org:443"]'
$env:FNV_MCP_ALLOWED_ORIGINS = '["https://mcp.example.org"]'
.\scripts\start.ps1 server
```

Host/origin allowlisting is DNS-rebinding protection, **not authentication**.
Agent IDs route ownership; they are not credentials. Use your reverse proxy's
authentication for untrusted clients. Candidate source is compiled on the host;
run the service under a dedicated, unprivileged account or isolated machine.

## Enable the CPU-only sweep

After real checker/compiler readiness, edit ignored `local/cpu-sweep/control.json`
and set `enabled` to `true`. It defaults to four screening workers, at most two
compiler-heavy jobs and batches of at most four. `cpu_concurrency` supports 1–16.
Start conservatively and measure actual returned/uploaded functions per minute;
local pattern-screening speed is not live service throughput.

The sweep handles supported small functions (currently ≤255 compiled bytes),
hydrates the real pack for possible matches, submits only after the official
recheck, and returns every unmatched function. It yields new claims to waiting
web agents and never starts an LLM. Unsupported patterns are expected.

For local assistance on your own existing pack, without claiming/submitting:

```powershell
.\scripts\assist.ps1 -Action prepare -Pack work/YOUR_CLAIM_ID -Ghidra auto -CpuCheck
.\scripts\assist.ps1 -Action finish -Pack work/YOUR_CLAIM_ID -Candidate work/YOUR_CLAIM_ID/candidate.cpp -Model 'Your actual model and tools'
```

The CPU engine includes scalar/template recognition and bounded integer, wrapper,
dispatch, destructor and loop families. It does not solve arbitrary functions.
Any learned declarations must be built locally from your authorized, verified
contributions; no learned corpus or function bodies are bundled.

## Agent handoff

Use [docs/AGENT-HANDOFF.md](docs/AGENT-HANDOFF.md). Each agent uses one stable ID and
one pending request/live assignment. Select a band explicitly, read **all** context
pages and compiler rules, fix the first instruction mismatch, and submit only an
official MATCH with the exact checked candidate ID/hash. Share checked WIP when
giving up. Actual bands/account limits are discovered live.

## Stop, restart, and recovery

Create `local/stop.request` to gracefully stop the coordinator: stop new claims,
finish/drain owned work and leave uncertain results quarantined. The listener
itself never performs service mutations. To resume after a reviewed stop, remove
that marker and start one coordinator. Its checkpoints are authoritative;
`trial.json` is a compatibility export that may lag.

After an interrupted operation, poll the **original** request ID. Never infer a
successful upload/release from a timeout, retry with a new identity, or clear
quarantine to get work moving. Preserve receipts and reconcile with current
service status. Unknown acquisition outcomes block new claims. A known target's
uncertain finish quarantines that target. Honor Retry-After and service holds.

Do not recursively search the runtime `work/`, `local/` or checkpoint trees from
many workers. Use exact request/response filenames and each agent's own pack.
This prevents concurrent archive scans from saturating the operator's disk.

## Tests and privacy

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe scripts/privacy-check.py
```

Tests use synthetic inputs and mocked service responses; they never claim, submit,
read another operator's private files or start models. Passing them is not proof
of a successful live account/compiler setup. See [SECURITY.md](SECURITY.md).

This is community tooling, not an official Bethesda or FNV service release.
MIT covers this repository's original tooling only; third-party software retains
its own licenses and must be acquired separately.
