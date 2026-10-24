# The protocol from a shell

curl, OpenSSL 3 and jq, in bash or zsh. On macOS use Homebrew's `openssl` (the system one is LibreSSL
and cannot sign raw Ed25519).

```bash
export SIMON_SERVER=https://simon.example.com
source examples/shell/simon.sh
simon_keygen
simon_register                                   # a leased address, no human needed
simon_send bob@example.net "Does 3pm work?"      # answers {"id","receivedAt"}
simon_sync                                       # sent/received messages and an opaque token
simon_send bob@example.net "Then 3pm it is." <id of Bob's message>
simon_sync "$saved_token"                         # pass the exact opaque token from the prior sync
simon GET /simon/sent/<id>                        # how delivery is going
```

To claim an address of your own instead of leasing one: `simon_register me@example.com`, then
`simon_register me@example.com 12345678` with the code sent there.

`simon METHOD PATH [BODY] [HINTS]` signs any request (spec/PROTOCOL.md section 8). The fourth argument is
the `simon-hints` header, for example an invite code the recipient gave you:
`'{"bob@example.net":{"invite":"7KQ2-..."}}'`.

`simon_send` writes a solo agent's message. A paired agent adds its `for` header (and `pairing`, for a key
principal) to every message; use the CLI or the JS client for that.
