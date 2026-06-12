#requires -Version 5
<#
  reproduce.ps1 — regenerate the corcept-hook-governance evidence pack.

  Everything under decisions/ and ledger/ is produced by this script from the
  synthetic Claude Code hook events in events/. No outputs are hand-edited.
  All events are SYNTHETIC; nothing runs the dangerous commands — corcept
  evaluates them as PreToolUse payloads and never executes them.

  Requires the `corcept` binary (built below if absent).
  Run from anywhere:  pwsh docs/demo/corcept-hook-governance/reproduce.ps1
#>
$ErrorActionPreference = "Stop"
$P     = $PSScriptRoot
$Root  = (Resolve-Path "$P\..\..\..").Path
$C     = Join-Path $Root "target\release\corcept.exe"
if (-not (Test-Path $C)) {
  $dbg = Join-Path $Root "target\debug\corcept.exe"
  if (Test-Path $dbg) { $C = $dbg }
  else { Write-Host "Building corcept..." -ForegroundColor Cyan; Push-Location $Root; cargo build -p corcept-cli --release; Pop-Location; $C = Join-Path $Root "target\release\corcept.exe" }
}

# --- Design-system drift pin: the vendored _assets/site.css must match the
# algol.cc source exactly (same discipline as the engineering-doctrine primer pin).
# Pinned sha256 of algol.cc/css/site.css as vendored into _assets/site.css. ---
$PinnedCssSha = "2728b214e6e59e926dbaac02a3c7fb08f531c3099074d921d2b818bf4d887182"
$vendored = "$P\_assets\site.css"
if (-not (Test-Path $vendored)) { throw "Missing vendored design system: $vendored" }
$haveSha = (Get-FileHash $vendored -Algorithm SHA256).Hash.ToLower()
if ($haveSha -ne $PinnedCssSha) {
  throw "site.css drift: _assets/site.css sha256 $haveSha != pinned $PinnedCssSha (re-vendor from algol.cc/css/site.css and update the pin in reproduce.ps1 + index.html)."
}
$src = "$Root\..\algol.cc\css\site.css"
if (Test-Path $src) {
  $srcSha = (Get-FileHash $src -Algorithm SHA256).Hash.ToLower()
  if ($srcSha -ne $PinnedCssSha) {
    throw "site.css drift: algol.cc source sha256 $srcSha != pinned $PinnedCssSha (the live design system moved; re-vendor _assets/site.css and update the pin)."
  }
} else {
  Write-Host "Note: algol.cc source not found at $src; verified vendored copy against pinned sha only." -ForegroundColor Yellow
}
Write-Host "Design-system pin OK (site.css sha256 $PinnedCssSha)." -ForegroundColor Green

New-Item -ItemType Directory -Force -Path "$P\decisions","$P\ledger" | Out-Null
Get-ChildItem "$P\decisions\*","$P\ledger\*" -ErrorAction SilentlyContinue | Remove-Item -Force

# Fresh governed workspace (gitignored; holds the .corcept config + ledger).
$work = "$P\.work"
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Force -Path $work | Out-Null
& $C init --path $work | Out-Null
$workJson = ((Resolve-Path $work).Path -replace '\\','/')

# --- Scenario A: run every synthetic event through the PreToolUse guard. ---
Write-Host "Scenario A — governing hook events..." -ForegroundColor Cyan
$rows = @()
foreach ($ev in (Get-ChildItem "$P\events\*.json" | Sort-Object Name)) {
  $name    = $ev.BaseName
  $payload = (Get-Content $ev.FullName -Raw) -replace '__WORKSPACE__', $workJson
  $out     = & $C hook pretool-guard --input $payload
  $out | Out-File "$P\decisions\$name.decision.json" -Encoding utf8
  $d   = ($out | ConvertFrom-Json).hookSpecificOutput
  $evj = $payload | ConvertFrom-Json
  $cmd = if ($evj.tool_input.command) { $evj.tool_input.command } else { $evj.tool_input.file_path }
  $rows += [pscustomobject]@{ event=$name; tool=$evj.tool_name; input=$cmd; decision=$d.permissionDecision; reason=$d.permissionDecisionReason }
}

# A completed (allowed) call, audited into the ledger as a command_executed row.
$audit = (Get-Content "$P\events\ok-cargo-test.json" -Raw) -replace '__WORKSPACE__', $workJson
$audit = ($audit | ConvertFrom-Json); $audit.hook_event_name = "PostToolUse"
$audit | Add-Member -NotePropertyName tool_response -NotePropertyValue (@{exitCode=0}) -Force
& $C hook posttool-audit --input ($audit | ConvertTo-Json -Compress -Depth 6) | Out-Null

# Decision summary table.
$tbl = "# Hook governance decisions (Scenario A)`n`nProduced by ``corcept hook pretool-guard`` over [``events/``](../events). corcept evaluates each PreToolUse payload and never executes the command.`n`n| Event | Tool | Input | Decision | Reason |`n|---|---|---|:---:|---|`n"
foreach ($r in $rows) { $inp = $r.input -replace '\|','\|'; $rsn = $r.reason -replace '\|','\|'; $tbl += "| ``$($r.event)`` | $($r.tool) | ``$inp`` | **$($r.decision)** | $rsn |`n" }
$deny=($rows|?{$_.decision -eq 'deny'}).Count; $ask=($rows|?{$_.decision -eq 'ask'}).Count; $allow=($rows|?{$_.decision -eq 'allow'}).Count
$tbl += "`n**Totals:** $deny deny / $ask ask / $allow allow, across $($rows.Count) events.`n"
$tbl | Out-File "$P\decisions\summary.md" -Encoding utf8

# --- Scenario B: the tamper-evident ledger. ---
Write-Host "Scenario B — verifying + tampering the ledger..." -ForegroundColor Cyan
Copy-Item "$work\.corcept\ledger\events.jsonl" "$P\ledger\events.jsonl" -Force
& $C audit --path $workJson verify | Out-File "$P\ledger\verify-intact.json" -Encoding utf8

# Tamper a COPY: flip the rm -rf deny into an allow, then re-verify.
$tamper = "$P\.tamper"
if (Test-Path $tamper) { Remove-Item -Recurse -Force $tamper }
Copy-Item $work $tamper -Recurse
$lf = "$tamper\.corcept\ledger\events.jsonl"
(Get-Content $lf -Raw).
  Replace('"decision":"deny","decision_reason":"Blocked recursive force deletion of dangerous target `/`."',
          '"decision":"allow","decision_reason":"approved by attacker"') |
  Set-Content $lf -NoNewline
& $C audit --path (($tamper -replace '\\','/')) verify | Out-File "$P\ledger\verify-tampered.json" -Encoding utf8
@'
Tamper test: an attacker edits one committed ledger row in events.jsonl, flipping
the `rm -rf /` decision from "deny" to "allow" (reason "approved by attacker"),
without recomputing the SHA-256 hash chain.

`corcept audit verify` on the tampered ledger returns status=fail,
hash_chain_valid=false, and pinpoints the altered row (hash_mismatch). The
append-only chain makes silent rewriting of past decisions detectable.
See verify-tampered.json.
'@ | Out-File "$P\ledger\tamper.txt" -Encoding utf8

Remove-Item -Recurse -Force $work,$tamper -ErrorAction SilentlyContinue
Write-Host "Done. See decisions/ and ledger/." -ForegroundColor Green
