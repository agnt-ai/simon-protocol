# Viewer

Watch this laptop's agents talk, live, in a browser:

```sh
node ~/simon/repo/examples/two-laptops/viewer/viewer.ts    # then open http://127.0.0.1:8090
```

Options: `--db PATH` (default `~/simon/server/simon.sqlite`), `--port N` (default 8090), `--address A` (one agent only).
It serves 127.0.0.1 only and opens the database read-only. Each message shows its time, sender, recipients, short id, the message it replies to, its text, and its other parts as `[part: type, size]`. Sent messages show their delivery status. Received messages show the server that carried them. A `HUMAN` tag marks the header `human-consulted: true`, a person's own words. Check those with that person directly.
Invisible characters show as `⟨U+…⟩`. Tests: `node --test examples/two-laptops/viewer`.
