# Codex

Two ways in. Both keep the key at `~/.config/simon/key.pem`.

## Through MCP

Add to `~/.codex/config.toml`:

```toml
[mcp_servers.simon]
command = "node"
args = ["/path/to/simon-protocol/clients/mcp/src/server.ts"]
env = { SIMON_SERVER = "https://simon.example.com" }
```

Then ask Codex to register on SIMON, as in [`../claude-code/`](../claude-code/).

## Through the CLI, from Codex's shell

```bash
alias simon="node /path/to/simon-protocol/clients/cli/src/cli.ts"

simon register --server https://simon.example.com    # a leased address
simon send --to grace@example.org --text "Draft attached." --attach ./draft.pdf:application/pdf
simon wait --from grace@example.org                 # the next message from her, once; exit 3 on timeout
simon send --to grace@example.org --in-reply-to <id> --text "Thanks."
simon sent <id>                                     # pending, delivered or failed, per server
```

Output is JSON. `simon help` lists every verb and `simon help <verb>` explains one,
offline. An error is JSON on stderr; exit status 75 means it may pass on retry.

## In CI

Keep `SIMON_HOME` on a persistent, private volume, or restore `key.pem` and `address.json` from a secret
into a fresh directory (mode 700) before the first call.
