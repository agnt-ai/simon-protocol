# Contributing

Thank you for helping. Contributions from people and from AI agents are welcome on the same terms.
Everything in this repository, code and documents alike, is licensed under the
[Apache License 2.0](LICENSE), and contributions are accepted under the same license. Participation
follows the [code of conduct](CODE_OF_CONDUCT.md); vulnerabilities go through [SECURITY.md](SECURITY.md),
not issues.

## The layout

| Directory | What | Runtime |
| --- | --- | --- |
| `spec/` | The protocol (`PROTOCOL.md`), the agent-to-server API (`CLIENT.md`), the registry and the test vectors | none |
| `protocol/` | The protocol as a library, and the vector generator | Node 26 |
| `conformance/` | The black-box conformance suite and its peer simulator | Node 26, `@agnt-sdk/simon-protocol` |
| `server/` | The basic server | Node 26, `@agnt-sdk/simon-protocol` |
| `app/` | The application template, on the basic server's extension API | Node 26, MongoDB |
| `clients/js`, `clients/cli`, `clients/mcp` | The JavaScript client, the CLI and the MCP server | Node 26 |
| `clients/python` | The Python client, a port kept beside the JavaScript one | Python 3.11 or later |
| `examples/` | Agents and per-runtime guides | Node 26 |
| `skill/` | What an agent reads to join | none |
| `docs/` | Decisions and architecture | none |

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) says what may import what; a test enforces it. TypeScript
runs directly on Node 26 (type stripping): there is no build step.

## Tests

Install once with `npm ci`. Then:

```sh
npm run check        # types, formatting, and every JavaScript suite below; CI runs exactly this
npm run format       # fix formatting
```

Every test passes; the counts below are those of release 0.2.0.

| Suite | Command | Tests | What it covers |
| --- | --- | --- | --- |
| Protocol | `npm test -w protocol` | 127 | Canonical JSON, keys, messages, envelopes, documents, resolution, requests; the vectors regenerated and compared with `spec/vectors/v1.json`; the import boundaries |
| Basic server | `npm test -w server` | 481 | The spec's rules as the server applies them, federation on a fake network, hardening, running behind a tunnel or a load balancer, the extension hooks, configuration, the store contract on sqlite |
| Conformance | `npm test -w conformance` | 11 | The whole suite against a toy server with planted faults, each caught by the check aimed at it; the simulator behind a tunnel; the README's check list |
| Application | `npm test -w app` | 100 | Every module, privacy and safety, federations of application and basic servers, the store contract on MongoDB, the conformance suite against the application. It needs no MongoDB of your own: `mongodb-memory-server` downloads one the first time |
| JavaScript client | `npm test -w clients/js` | 98 | The calls, verification and its trust record, labelled output, the workspace, `wait`, and the key file, against an in-process server |
| CLI | `npm test -w clients/cli` | 20 | The CLI as a process |
| MCP server | `npm test -w clients/mcp` | 13 | The MCP server as a process, over stdio |
| MongoDB store | `npm test -w store-mongo` | 107 | The Store contract and the store's own races, on an in-memory MongoDB |
| Specification | `npm run test:spec` | 6 | The published vectors validated against the JSON schemas in `spec/schemas` |
| Two-laptops viewer | `node --test examples/two-laptops/viewer` | 1 | The viewer against a database the basic server wrote. Not part of `npm run check` |
| Python client | `cd clients/python && python3 -I -m unittest` | 136 | Every vector, the units and the client. Run it twice: with the standard library only (one test skips), and with `cryptography` installed |

Checks against real processes:

```sh
node server/scripts/smoke.ts     # two basic servers on localhost, a message each way
scripts/dev.sh                   # a development server on :8787; then, in another shell, npm run demo
scripts/image-check.sh           # the server's Docker image, run as a deployment runs it
npm run build && scripts/test-built.sh packed   # the packed packages, on the Node that runs it
```

CI runs the last two on every push: the image check, and the packed packages on Node 24.6.0, where the
protocol's and the JavaScript client's suites, the vectors among them, run against the compiled files.

The conformance suite against the basic server, run as [conformance/README.md](conformance/README.md)
says with every optional check on, passes 210 of its 212 checks and skips `sent.expired`, which needs
the server's clock moved by days, and `deliver.no-lookup-before-signature`, which can see a lookup only
through a public tunnel. A run takes a few minutes.

## Running the conformance suite against a server

```sh
node conformance/src/cli.ts --server <origin> --format text
```

The server must resolve the suite's peer domain, `peer.test`, to `http://127.0.0.1:47100`, and have rate
limits loose enough for one run. [conformance/README.md](conformance/README.md) explains every option, and
[server/README.md](server/README.md) has the exact command for the basic server.

## Generated files

Commit these regenerated with the change that alters them; a test fails when one is stale.

| File | Regenerate with | After changing |
| --- | --- | --- |
| `spec/vectors/v1.json` | `npm run vectors` | the protocol library or the vector generator |
| `app/openapi.json` | `npm run openapi` | a route of the application |
| the check list in `conformance/README.md` | `npm run readme -w conformance` | a conformance check |

## Changing the protocol

A change to `spec/PROTOCOL.md`, `spec/CLIENT.md` or the shape of an endpoint starts as an issue, so the
rule is agreed before the code. Section 1 of the protocol changes only for an overwhelming reason. A change
that is agreed lands in the specification, the vectors, the library, the conformance suite and every
implementation here, together.

**Registry entries.** A convention (a header, a claim type, a hint, a document member) is added to
[spec/registry.md](spec/registry.md) as **proposed**. It becomes **registered** only once two independent
implementations use it; link both in the pull request that changes its status.

## Releasing

Six packages are published to npm, together and always at one version: `@agnt-sdk/simon-protocol`
(`protocol/`), `@agnt-sdk/simon-server` (`server/`, the `simon-server` binary), `@agnt-sdk/simon-store-mongo`
(`store-mongo/`), `@agnt-sdk/simon-client` (`clients/js`), `@agnt-sdk/simon-cli` (`clients/cli`, the
`simon` binary) and `@agnt-sdk/simon-mcp` (`clients/mcp`, the `simon-mcp` binary). What is published is the build
of `scripts/pack.ts`: compiled JavaScript with type declarations for Node 24.6.0 or later, never the
TypeScript sources, which is why `npm publish` refuses to run in a source directory. Every other workspace
is private.

1. **Bump the versions.** In one pull request, set `version` in the six `package.json` files to the new
   version, and the six packages' dependencies on each other to exactly that version. Run `npm install`
   to update `package-lock.json`, and add the release to [CHANGELOG.md](CHANGELOG.md).
2. **Tag the merged commit** `vX.Y.Z`, with the same version, and push the tag:
   `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. **The publish workflow** ([.github/workflows/publish.yml](.github/workflows/publish.yml)) runs the full
   check, confirms the tag matches every package's version (`scripts/release-version.ts`), packs the six
   with `node scripts/pack.ts --release`, runs `scripts/test-built.sh` on the packed files on Node 24, and
   publishes them in dependency order (protocol, server, the MongoDB store, client, then the CLI and the
   MCP server) with `--access public --provenance`.

A version on npm cannot be published again. If the workflow fails part way, fix the cause and release the
next patch version.

**Authentication: trusted publishing.** The workflow publishes by npm's trusted publishing (OIDC), with no
token, so npm shows each version as published by GitHub Actions from this repository, with provenance, and
never by a personal account. It needs npm 11.5.1 or later, which the workflow installs. Provenance also
needs the repository to be public. Setting it up:

1. **The first release** happens before the packages exist on npm, when no trusted publisher can be
   configured for them yet. For it, store a granular access token of a bot account (not a person's
   account), with publish rights on the `@agnt-sdk` scope, as the repository secret `NPM_TOKEN`. The
   workflow passes it to npm as `NODE_AUTH_TOKEN` when it is set, and uses no token when it is empty.
2. **Then configure a trusted publisher** on npmjs.com for each of the six packages (the package's
   settings, "Trusted Publisher"): GitHub Actions; organization `agnt-ai`; repository `simon-protocol`;
   workflow `publish.yml`; no environment (unless one is added to the workflow, in which case name it).
3. **Then delete the `NPM_TOKEN` secret,** and set each package's publishing access to "Require two-factor
   authentication and disallow tokens". From then on, only this workflow can publish.

## Sign-off (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org) instead of a
contributor license agreement. Each contributor signs off their own commits, certifying that they wrote
the change or otherwise have the right to submit it under the project's license:

```
Signed-off-by: Ada Lovelace <ada@example.com>
```

`git commit -s` adds the line from your Git configuration. Use your real name. A commit made by an agent
is signed off by the person responsible for it. Pull requests with commits that are not signed off cannot
be merged.

The name is covered separately: see [TRADEMARK.md](TRADEMARK.md).
