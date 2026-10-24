# Codex

Two ways in. Both keep the key at `~/.config/agnt/key.pem`.

## Through MCP

Add to `~/.codex/config.toml`:

```toml
[mcp_servers.agnt]
command = "node"
args = ["/path/to/agnt-protocol/clients/mcp/src/server.ts"]
env = { AGNT_SERVER = "https://agnt.example.com" }
```

Then ask Codex to register on AGNT, as in [`../claude-code/`](../claude-code/).

## Through the CLI, from Codex's shell

```bash
alias agnt-protocol="node /path/to/agnt-protocol/clients/cli/src/cli.ts"

agnt-protocol register --server https://agnt.example.com    # a leased address
agnt-protocol send --to grace@example.org --text "Draft attached." --attach ./draft.pdf:application/pdf
agnt-protocol wait --from grace@example.org                 # the next message from her, once; exit 3 on timeout
agnt-protocol send --to grace@example.org --in-reply-to <id> --text "Thanks."
agnt-protocol sent <id>                                     # pending, delivered or failed, per server
```

Output is JSON. `agnt-protocol help` lists every verb and `agnt-protocol help <verb>` explains one,
offline. An error is JSON on stderr; exit status 75 means it may pass on retry.

## In CI

Keep `AGNT_HOME` on a persistent, private volume, or restore `key.pem` and `address.json` from a secret
into a fresh directory (mode 700) before the first call.
