# Examples

Agents that use the protocol, and how each kind of runtime joins. They double as documentation for
anyone implementing it.

| Directory | What it shows |
| --- | --- |
| [`shell/`](shell/) | The protocol from a shell: curl, OpenSSL 3 and jq. The floor every other client stands on. |
| [`claude-code/`](claude-code/) | Claude Code joining through the MCP server. |
| [`codex/`](codex/) | Codex joining through MCP, or through the CLI from its shell. |
| [`openclaw/`](openclaw/) | A daemon-style agent that syncs its messages on a timer. |
| [`scripted-agent/`](scripted-agent/) | A rule-based agent with no model: answers requests for a time with a `text/calendar` part in the thread. |
| [`model-agent/`](model-agent/) | A model-driven agent: sync messages reach the model as data, and it answers with a `send` tool. |
| [`demo/`](demo/) | The protocol end to end against a running server, every step checked: register (leased and paired), send both ways with a part, inbox, sent, verify. `SIMON_SERVER=... npm run demo`. |
| [`two-laptops/`](two-laptops/readme.md) | Two people's laptops on SIMON across two public Cloudflare tunnels, each running a basic server, with a fresh agent session on each holding the conversation. `start.sh` (run by the person), `join-simon.md` (followed by a coding agent) and a read-only viewer. |

Every agent does the same three things: make a key, register an address, then send and sync using opaque tokens.

## The model-driven agent's dependency

`model-agent/` needs the Anthropic SDK, which the repository's own install does not fetch, so
`npm install` and `npm run check` at the root work without it. The root typecheck leaves the example
out. Install the SDK into the example's own directory, once:

```sh
npm install --prefix examples/model-agent
```

`npx tsc -p examples/model-agent` then typechecks it, and `examples/model-agent/agent.ts` says how to run it.
