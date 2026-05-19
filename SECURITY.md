---
title: Security
description: Threat model, trust boundaries, secret handling, and safe installation policy.
seo:
  title: Security - Corcept Runtime
  description: Threat model, trust boundaries, secret handling, and safe installation policy.
  keywords: ['security', 'secrets', 'supply-chain', 'hooks', 'Corcept', 'Claude Code', 'Rust']
tags: ['security', 'secrets', 'supply-chain', 'hooks']
status: complete
---


# Security

## Trust boundaries

Corcept treats the following as untrusted by default:

- external content
- model-generated memory
- shell commands
- package installation
- production-like commands
- MCP/network tools
- any file that looks like a secret

## Protected files

Default protected patterns include:

```text
.env
.env.*
*.pem
*.key
id_rsa*
id_ed25519*
.aws/**
.gcp/**
.azure/**
.git/**
.npmrc
.pypirc
.netrc
*secret*.env
*credential*.json
*token*.json
```

## Installer policy

The installer does not mutate global Claude settings. It writes project-local files only and supports dry-run reporting.

## Hook policy

`PreToolUse` denial is used for hard controls. `PostToolUse` is audit-only because the action has already happened. `Stop` is used to block premature completion and stale-test claims.


## Classifier hardening

The Bash guard no longer relies only on exact deny strings. It classifies shell-mediated secret reads, no-space pipe-to-shell, recursive deletes, package-manager aliases, Git external side effects, infra/container commands, and privilege escalation. Hard-deny operations are blocked; local destructive operations and external side effects are approval-gated.
