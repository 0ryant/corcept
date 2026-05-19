---
title: Release
description: Release checklist, plugin zip packaging, checksums, and versioning.
seo:
  title: Release - Corcept Runtime
  description: Release checklist, plugin zip packaging, checksums, and versioning.
  keywords: ['release', 'packaging', 'checksums', 'Corcept', 'Claude Code', 'Rust']
tags: ['release', 'packaging', 'checksums']
status: complete
---


# Release

## Checklist

- [x] Root docs present.
- [x] ADRs present.
- [x] Completed subtask records present.
- [x] Rust workspace present.
- [x] Plugin assets present.
- [x] Hook wrappers present.
- [x] Schemas present.
- [x] Tests authored.
- [x] CI workflow present.

## Build release artifacts

```bash
cargo build --release --workspace
make plugin-zip
make scaffold-zip
shasum -a 256 dist/*.zip > dist/checksums.txt
```

## Versioning

Use semver. Breaking policy or schema changes require a minor or major bump depending on compatibility.
