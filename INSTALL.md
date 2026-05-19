---
title: Installation
description: Install, dry-run, plugin, and local development instructions.
seo:
  title: Installation - Corcept Runtime
  description: Install, dry-run, plugin, and local development instructions.
  keywords: ['install', 'claude-code', 'plugin', 'cli', 'Corcept', 'Claude Code', 'Rust']
tags: ['install', 'claude-code', 'plugin', 'cli']
status: complete
---


# Installation

## Build from source

```bash
cargo build --workspace --all-targets
```

## Install the CLI locally

```bash
cargo install --path crates/corcept-cli
cargo install --path crates/create-corcept
```

## Initialize a repository

Always dry-run first:

```bash
create-corcept --path /path/to/repo --dry-run
create-corcept --path /path/to/repo
```

Equivalent CLI form:

```bash
corcept init --path /path/to/repo --dry-run
corcept init --path /path/to/repo
```

## Use the plugin in development

```bash
claude --plugin-dir ./plugins/corcept
```

## Package plugin zip

```bash
make plugin-zip
```

The plugin zip is intended for Claude Code local testing and controlled distribution. The full repository zip contains source, docs, tests, schemas, and plugin assets.
