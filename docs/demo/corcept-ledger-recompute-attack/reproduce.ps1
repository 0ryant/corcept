#requires -Version 5
<#
  reproduce.ps1 — regenerate the corcept-ledger-recompute-attack evidence pack.

  Proves the HONEST CEILING of the keyless ledger hash chain and that Ed25519
  signing — not the keyless chain — is what makes the ledger tamper-EVIDENT
  against a SOURCE-READING adversary.

  Threat model: an adversary who can read this repo knows the hash domain prefix
  (`HASH_DOMAIN = "corcept:ledger:v1:"`, public in
  crates/corcept-ledger/src/canonical.rs). So they can rewrite a committed row
  AND recompute the WHOLE chain. The keyless `audit verify` then FALSE-PASSES;
  only `audit verify --signed` catches it (the attacker cannot forge a signature
  without the operator's private key).

  Everything under cells/ is produced by this script. No outputs are hand-edited.
  Nothing dangerous is executed — the ledger rows are synthetic decision records.

  Run from anywhere:  pwsh docs/demo/corcept-ledger-recompute-attack/reproduce.ps1
#>
$ErrorActionPreference = "Stop"
$P    = $PSScriptRoot
$Root = (Resolve-Path "$P\..\..\..").Path
$C    = Join-Path $Root "target\release\corcept.exe"
if (-not (Test-Path $C)) {
  $dbg = Join-Path $Root "target\debug\corcept.exe"
  if (Test-Path $dbg) { $C = $dbg }
  else { Write-Host "Building corcept..." -ForegroundColor Cyan; Push-Location $Root; cargo build -p corcept-cli --release; Pop-Location; $C = Join-Path $Root "target\release\corcept.exe" }
}

New-Item -ItemType Directory -Force -Path "$P\cells" | Out-Null
Get-ChildItem "$P\cells\*" -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse

# --- Build a SIGNED governed workspace. Key under the workspace's data home so
# this demo is fully self-contained and never touches the operator's real key. ---
$work = "$P\.work"
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Force -Path "$work\data" | Out-Null
$env:CORCEPT_DATA_HOME    = (Resolve-Path "$work\data").Path
$env:CORCEPT_TRUSTED_HISTORY = "1"   # sign every appended row + populate trust dir
$workJson = ((Resolve-Path $work).Path -replace '\\','/')

& $C init --path $work | Out-Null
& $C key generate | Out-Null

# Append three synthetic decision rows; row 2 is a DENIED dangerous command —
# the row an attacker would most want to rewrite after the fact.
function Append-Decision($json) {
  $payload = $json -replace '__WORKSPACE__', $workJson
  & $C hook pretool-guard --input $payload | Out-Null
}
# A genuine deny so the ledger has a meaningful "deny rm -rf /" row to attack.
$denyEvent = @"
{"session_id":"recompute-demo","transcript_path":"x","cwd":"__WORKSPACE__","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}
"@
$okEvent = @"
{"session_id":"recompute-demo","transcript_path":"x","cwd":"__WORKSPACE__","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"}}
"@
Append-Decision $okEvent
Append-Decision $denyEvent
Append-Decision $okEvent

$ledgerSrc = "$work\.corcept\ledger\events.jsonl"

# Sanity: the clean signed ledger must pass BOTH modes.
& $C audit --path $workJson verify          | Out-File "$P\cells\01-clean-keyless.json" -Encoding utf8
& $C audit --path $workJson verify --signed | Out-File "$P\cells\02-clean-signed.json"  -Encoding utf8

# --- The recompute attack: copy the ledger, flip row 2 deny->allow, and
# recompute the entire PUBLIC-prefix chain (signatures left stale). ---
$atk = "$P\cells\events-recomputed.jsonl"
Copy-Item $ledgerSrc $atk -Force
# Find the 1-based line of the deny row (robust to ordering).
$lines = Get-Content $atk
$denyLine = 0
for ($i = 0; $i -lt $lines.Count; $i++) {
  if ($lines[$i] -match '"decision":"deny"') { $denyLine = $i + 1; break }
}
if ($denyLine -eq 0) { throw "no deny row found in ledger to attack" }

Push-Location $Root
& cargo run -q -p corcept-ledger --example recompute_attack -- $atk $denyLine decision allow
Pop-Location

# Stage the recomputed ledger into a throwaway workspace and verify BOTH modes.
$victim = "$P\.victim"
if (Test-Path $victim) { Remove-Item -Recurse -Force $victim }
Copy-Item $work $victim -Recurse
Copy-Item $atk "$victim\.corcept\ledger\events.jsonl" -Force
$victimJson = ((Resolve-Path $victim).Path -replace '\\','/')

# (1) KEYLESS verify FALSE-PASSES the recompute attack (the honest ceiling).
& $C audit --path $victimJson verify          | Out-File "$P\cells\03-attacked-keyless-FALSE-PASS.json" -Encoding utf8
# (2) SIGNED verify CATCHES it and names the row (the load-bearing element).
$signedOut = & $C audit --path $victimJson verify --signed
$signedExit = $LASTEXITCODE
$signedOut | Out-File "$P\cells\04-attacked-signed-CATCHES.json" -Encoding utf8

# --- Assert the proof so a regression fails the repro, not just the unit test. ---
$keylessAttacked = Get-Content "$P\cells\03-attacked-keyless-FALSE-PASS.json" -Raw | ConvertFrom-Json
$signedAttacked  = Get-Content "$P\cells\04-attacked-signed-CATCHES.json"     -Raw | ConvertFrom-Json
if ($keylessAttacked.tamper_detected) {
  throw "REPRO FAIL: keyless verify was expected to FALSE-PASS the recompute attack but flagged tamper."
}
if (-not $signedAttacked.tamper_detected) {
  throw "REPRO FAIL: signed verify was expected to CATCH the recompute attack but passed."
}
if ($signedExit -eq 0) {
  throw "REPRO FAIL: signed verify must exit non-zero (fail-closed) on the attacked ledger."
}

# Human-readable proof note.
@"
Recompute-attack proof (signed vs unsigned)
===========================================

Threat model: a SOURCE-READING adversary. The hash domain prefix
HASH_DOMAIN = "corcept:ledger:v1:" is PUBLIC (crates/corcept-ledger/src/canonical.rs),
so the attacker can rewrite a row AND recompute the whole chain.

Attack: row $denyLine ("rm -rf /") flipped from deny -> allow, then the entire
prev_hash/hash chain recomputed over the public prefix (signatures left stale).

Result:
  - 03-attacked-keyless-FALSE-PASS.json : ``audit verify``          -> status=$($keylessAttacked.status) tamper_detected=$($keylessAttacked.tamper_detected)
    The keyless chain is a tamper-DETECTION checksum (catches accidental
    corruption + naive edits). It does NOT make the ledger tamper-EVIDENT
    against this adversary: it FALSE-PASSES.
  - 04-attacked-signed-CATCHES.json     : ``audit verify --signed`` -> status=$($signedAttacked.status) tamper_detected=$($signedAttacked.tamper_detected) tampered_lines=$($signedAttacked.tampered_lines -join ',') exit=$signedExit
    Signing IS the load-bearing element: the stale Ed25519 signature no longer
    matches the rewritten preimage and the attacker cannot forge one without the
    operator's private key. The exact altered row is named (BadSignature).

Enforcement (unchanged by this demo): sign at append with CORCEPT_SIGN_LEDGER=1
and gate at ``corcept doctor --strict`` (fail-closed, non-zero exit). The default
keyless mode is honestly labelled as detection, not evidence.

Honest ceiling: signing proves a row was produced by a holder of the operator
key; it does NOT prove the *content* of a decision was correct, nor protect a
key that itself leaks. Non-repudiation across machines is the tsign / cex-spine
path, deferred.
"@ | Out-File "$P\cells\PROOF.txt" -Encoding utf8

# Cleanup throwaway workspaces; keep cells/ as the evidence pack.
Remove-Item -Recurse -Force $work,$victim -ErrorAction SilentlyContinue
Remove-Item Env:CORCEPT_DATA_HOME,Env:CORCEPT_TRUSTED_HISTORY -ErrorAction SilentlyContinue
Write-Host "Done. Proof in cells/ (see cells/PROOF.txt)." -ForegroundColor Green
# The last external call (`audit verify --signed`) fail-closes with a non-zero
# exit BY DESIGN on the attacked ledger; that is the asserted proof, not a script
# error. All proof assertions above passed, so report success explicitly.
exit 0
