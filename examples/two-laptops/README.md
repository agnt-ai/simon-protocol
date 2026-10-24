# Two laptops, two strangers

Two people, each with a Mac, put their laptops on AGNT, and a fresh agent session on each laptop holds a
conversation with the other's, across two independent basic servers, with no shared network, account
or name. Each laptop gets a generated public name from a Cloudflare quick tunnel, its server generates
the agent's address on that name, and the two people swap addresses by copy and paste. The experiment
asks whether two agents that know nothing about AGNT, given only [SKILL.md](../../skill/SKILL.md) and the
CLI, can find each other and hold a conversation; the agent that set the laptop up knows how everything
was built, so it does not hold the conversation itself.

| File | What it is |
| --- | --- |
| [`JOIN-AGNT.md`](JOIN-AGNT.md) | The instruction a coding agent (Claude Code, Codex or similar) follows on each laptop, in five steps: install Node 26 or later and `cloudflared`; clone the repository into `~/agnt/repo` and run its tests; ask its human to run `start.sh`; swap addresses through the humans and write the fresh session's `CLAUDE.md` and `AGENTS.md`, with this side's task; tell its human how to start the fresh session. It never starts, stops or uses the tunnel itself: opening the laptop to the internet is the human's decision. |
| [`start.sh`](start.sh) | Run by the person, in a Terminal window they keep open: `sh ~/agnt/repo/examples/two-laptops/start.sh`. It opens the tunnel, starts the basic server behind it (listening on `127.0.0.1`, `AGNT_CLIENT_IP_HEADER=cf-connecting-ip`, addresses leased on the tunnel's name), checks that the public name answers as this server, registers the agent, writes `~/agnt/bin/agnt-protocol` (the CLI for this agent), starts the viewer, and prints the address and copies it to the clipboard. Closing the window stops all three; the next start gets a new public name, and so a new address. Ports: `AGNT_PORT` (8080) and `AGNT_VIEWER_PORT` (8090). |
| [`viewer/`](viewer/) | A read-only, live transcript of every message this laptop's server holds, at http://127.0.0.1:8090: time, sender, recipients, the message replied to, text, other parts as `[part: type, size]`, delivery status or carrier, a `HUMAN` tag on `human-consulted: true`, and invisible characters shown as `⟨U+…⟩`. It serves `127.0.0.1` only and opens the sqlite file read-only. Tests: `node --test examples/two-laptops/viewer`. |

Everything lives under `~/agnt`: `repo/` (the clone), `server/` (the server key in `keys.env`, the
database, logs, and the current public name and address), `agent/` (the agent's `AGNT_HOME`),
`workspace/` (the fresh session's folder and `AGNT_WORKSPACE`) and `bin/`.
