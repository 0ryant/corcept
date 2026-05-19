#!/usr/bin/env bash
# Supply-chain governance gate for CORCEPT (ST-029).
# Modes: strict (default) | advisory
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MODE="${1:-strict}"
REPORTS="${REPO_ROOT}/supply-chain-reports"
mkdir -p "$REPORTS"

info() { echo "supply-chain-gate: $*"; }
fail() {
  echo "supply-chain-gate FAIL: $*" >&2
  [[ "$MODE" == "advisory" ]] || exit 1
}

run_or_skip() {
  local name="$1"
  shift
  if "$@"; then
    info "$name OK"
  else
    fail "$name"
  fi
}

# ── Gitleaks ──
if command -v gitleaks >/dev/null 2>&1; then
  run_or_skip gitleaks gitleaks detect --source . --no-git -v \
    --report-path "$REPORTS/gitleaks.json" \
    --report-format json
else
  info "gitleaks not installed — skip (install in CI)"
fi

# ── Cargo audit ──
if command -v cargo >/dev/null 2>&1; then
  if cargo audit --version >/dev/null 2>&1; then
    run_or_skip cargo-audit cargo audit --json >"$REPORTS/cargo-audit.json"
  else
    info "installing cargo-audit"
    cargo install cargo-audit --locked 2>/dev/null || true
    if cargo audit --version >/dev/null 2>&1; then
      run_or_skip cargo-audit cargo audit --json >"$REPORTS/cargo-audit.json"
    else
      fail "cargo-audit unavailable"
    fi
  fi
fi

# ── Filesystem scan (trivy) ──
if command -v trivy >/dev/null 2>&1; then
  run_or_skip trivy-fs trivy fs --scanners vuln,secret,misconfig \
    --severity HIGH,CRITICAL \
    --format json \
    --output "$REPORTS/trivy-fs.json" \
    .
else
  info "trivy not installed — skip"
fi

# ── GitHub Actions lint ──
if command -v actionlint >/dev/null 2>&1; then
  run_or_skip actionlint actionlint -shellcheck= \
    .github/workflows/*.yml >"$REPORTS/actionlint.txt"
else
  info "actionlint not installed — skip"
fi

# ── Workflow static analysis (zizmor) ──
if command -v zizmor >/dev/null 2>&1; then
  run_or_skip zizmor zizmor --persona auditor .github/workflows \
    >"$REPORTS/zizmor.txt" 2>&1 || true
else
  info "zizmor not installed — skip"
fi

info "complete (mode=$MODE, reports=$REPORTS)"
