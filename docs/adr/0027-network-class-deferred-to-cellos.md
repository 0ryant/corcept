---
title: ADR-0027 Network-class attacks deferred to cellos
status: accepted
date: 2026-05-20
seo:
  title: Network-tool classification belongs to cellos, not corcept
  description: Decision record deferring `nc / ncat / socat / wget --post-file / curl --data-binary @` classification from corcept's process membrane to cellos's network membrane.
  keywords: [Corcept, Cellos, network membrane, defense in depth, egress allowlist, adversarial classification]
tags: [adr, security, network, cellos, layering]
---

# ADR-0027: Network-class attacks deferred to cellos

## Context

The per-tool benchmark (a16733b550df3f42b, 2026-05-20) surfaces a network-tool
attack class containing `nc`, `ncat`, `socat`, `wget --post-file`, and `curl
--data-binary @` patterns. A natural reflex is to add a `detect_dangerous_network_tool`
classifier to `corcept-guards` next to the privilege-escalation and
environment-variable detectors.

The operator clarified during the Fix 3 pass that this is the wrong layer.

## Decision

Network-tool classification stays in **cellos** (the network membrane). It
does **not** ship in corcept (the process membrane).

The architectural rule is:

| Layer    | Membrane          | Authority unit             | Adversarial scope |
|----------|-------------------|----------------------------|-------------------|
| cellos   | network membrane  | egress / ingress per host  | Network class     |
| corcept  | process membrane  | pre-tool / pre-bash gate   | Process intent    |

`cellos` enforces an **empty-allowlist by default** on egress. That single
policy blocks ALL outbound network from the agent regardless of which
process initiated the egress — `nc`, `wget`, `curl`, Python's `socket` module,
a Rust crate's TLS dialer, the agent's own MCP transports, anything. The
allowlist is the load-bearing primitive; classification at the command surface
is at best defense-in-depth and at worst introduces an inconsistency where
the corcept-side classifier and the cellos-side allowlist disagree.

The corcept process membrane is therefore intentionally silent on the
network-tool attack class. The benchmark records these scenarios as "passes
through corcept; cellos enforces."

See `council-layers-4-10-decisions.md` §D3 (Authority) for the broader
layering rationale.

## Consequences

- Per-tool benchmark scenarios `si-001`, `si-005`, `si-010`, `si-015`
  (network-shaped shell-injection variants) and any future network-tool
  scenarios remain `allow` from corcept's perspective. They are not bugs in
  corcept — they are deliberate handoffs to the cellos layer.
- Corcept ships a code comment at the network-tool decision point pointing
  to this ADR so future readers do not "fix" the gap by adding a duplicate
  classifier.
- If the operator ever stages an integration without cellos in front of the
  agent (the unsupported topology), the operator MUST acknowledge that the
  network-class attacks pass with no enforcement. Corcept does not provide a
  fallback because doing so would invite the inconsistency this ADR is
  pinning down.
- The corcept v3 commercial-validity claim is conditioned on cellos being
  deployed alongside corcept. The benchmark numbers reported for corcept
  reflect process-membrane enforcement only; the network membrane is
  measured independently in the cellos benchmark.

## Status

Accepted by the operator on 2026-05-20 during the per-tool benchmark fix pass.
