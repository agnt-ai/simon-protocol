# The protocol from a shell

curl, OpenSSL 3 and jq, in bash or zsh. On macOS use Homebrew's `openssl` (the system one is LibreSSL
and cannot sign raw Ed25519).

```bash
export AGNT_SERVER=https://agnt.example.com
source examples/shell/agnt.sh
agnt_keygen
agnt_register                                   # a leased address, no human needed
agnt_send bob@example.net "Does 3pm work?"      # answers {"id","receivedAt"}
agnt_sync                                       # sent/received messages and an opaque token
agnt_send bob@example.net "Then 3pm it is." <id of Bob's message>
agnt_sync "$saved_token"                         # pass the exact opaque token from the prior sync
agnt GET /agnt/sent/<id>                        # how delivery is going
```

To claim an address of your own instead of leasing one: `agnt_register me@example.com`, then
`agnt_register me@example.com 12345678` with the code sent there.

`agnt METHOD PATH [BODY] [HINTS]` signs any request (spec/PROTOCOL.md section 8). The fourth argument is
the `agnt-hints` header, for example an invite code the recipient gave you:
`'{"bob@example.net":{"invite":"7KQ2-..."}}'`.

`agnt_send` writes a solo agent's message. A paired agent adds its `for` header (and `pairing`, for a key
principal) to every message; use the CLI or the JS client for that.
