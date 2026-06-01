# gaps

Source: `<ecosystem-catalog>/manager-reports/2026-05-21-ecosystem-synthesis-next-level.md`

## Goal

Productise `corcept` as a hook-time governance surface with a callable MCP
interface and durable receipts.

## Remaining

- Stable hook-decision receipt shape.
- Example showing allow, deny, degraded, and audit-only hook outcomes.
- Catalog evidence for the canonical `corcept-mcp` surface.

## Steps

1. Emit one receipt format for hook decisions across all five hook types.
2. Add adversarial fixtures for prompt injection, unsafe path, unsafe network,
   missing approval, and missing doctrine source.
3. Add docs showing how a consumer verifies a hook decision receipt.
4. Add catalog evidence only after the MCP smoke and receipt fixtures pass.

## Acceptance evidence

- MCP server starts from the chosen local build or install path.
- At least one allow and one deny receipt are committed as fixtures.
- Adversarial hook corpus has deterministic expected outcomes.
- Docs show the lifecycle from hook event to receipt.

## Current lane note

- Source-local cleanup added a CI local-path guard and converted
  `corcept-mcp`'s `mcpact-*` dependencies from developer-absolute paths to
  sibling-relative, version-pinned path dependencies.
- `corcept-mcp` is now the canonical first-party MCP adapter; the legacy
  `corcept serve` surface remains only for the deprecation window.
- `scripts/smoke-canonical-mcp.ps1` builds the local CLI and generated adapter,
  starts the canonical MCP server, lists tools, and invokes `corcept_doctor`.
- The next product lane is receipt evidence and catalog proof, not deciding the
  canonical MCP surface.

## Stop conditions

- Do not expose mutation-capable tools before authority classes and approval
  gates are explicit.
- Do not call hook governance "enforced" where the surface is advisory only.
