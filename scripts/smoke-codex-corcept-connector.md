# Codex hotload runbook

Use this when you want Codex to talk to Corcept over MCP without making Corcept a default global connector.

## 1. Install or build Corcept

Use either:

```powershell
cargo install --path crates/corcept-cli
```

or a local build path such as:

```powershell
cargo build -p corcept-cli
```

## 2. Bind the server to one repo

Use the canonical entrypoint:

```powershell
corcept serve --path C:\path\to\repo
```

## 3. Add a local MCP connector in Codex

If your Codex build offers a local MCP or connector form, use this payload:

```json
{
  "command": "corcept",
  "args": ["serve", "--path", "C:\\path\\to\\repo"]
}
```

If you are using a local build instead of an installed binary, point `command` at the built executable path instead.

## 4. Hotload and verify

After enabling the connector:

1. Reconnect or hotload the MCP server in Codex.
2. Verify that `tools/list` shows only the bounded Corcept tools.
3. Run `doctor_report` first.
4. Optionally run `candidate_memory_list` or `cloudevents_preview`.

## 5. Boundary check

Expected in v1:

- read-mostly project inspection
- no shell bridge
- no hook execution
- no ledger mutation
- no memory promotion

If you see a broader surface than that, stop and review `docs/adr/0008-no-default-mcp.md`.
