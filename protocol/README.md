# @agnt-sdk/simon-protocol

The [SIMON Protocol](../spec/PROTOCOL.md), version 2, as code: canonical JSON, addresses and principals,
messages, envelopes, signals, agent and server documents, domain resolution, request signing, and Ed25519
and ML-DSA-65 keys. It is everything two implementations must agree on, and nothing else, with no
dependencies beyond Node's standard library. The normative text is [spec/PROTOCOL.md](../spec/PROTOCOL.md);
this library reproduces every test vector in [spec/vectors/v2.json](../spec/vectors/v2.json).

```js
import { canonicalize, generateKey, sign, verify } from '@agnt-sdk/simon-protocol';

const { privateKey, key } = generateKey('ed25519');
const bytes = canonicalize({ text: 'hello' });
verify(key, bytes, sign(privateKey, bytes)); // true
```

An agent talking to its own server wants [`@agnt-sdk/simon-client`](../clients/js), which is built on this
library.

The package runs on Node 24.6.0 or later, the first with ML-DSA-65 keys. In this repository the sources
run directly on Node 26; the published package is their compiled build (`npm run build`).

## Tests

`npm test -w protocol`: every module and every vector. `npm run vectors` regenerates
`spec/vectors/v2.json` from `test/vectors.ts`; never edit the vectors by hand.
