#!/usr/bin/env bash
# The four packed packages of a release (scripts/pack.ts --release), published to npm in dependency order,
# public and with provenance. Run by .github/workflows/publish.yml, which is where the OIDC identity that
# npm's trusted publishing and provenance need comes from. With NODE_AUTH_TOKEN set (the first release
# only), npm authenticates with that token instead; otherwise by trusted publishing, with no token at all.
#   scripts/publish.sh <directory of packed tarballs> <version>
set -euo pipefail
PACKED="${1:?usage: $0 <directory of packed tarballs> <version>}"
VERSION="${2:?usage: $0 <directory of packed tarballs> <version>}"
REGISTRY=https://registry.npmjs.org/

npm --version
if [ -n "${NODE_AUTH_TOKEN:-}" ]; then
  # Read from the environment when npm runs, so the token is never written out.
  npm config set --location=user '//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}'
fi
for name in simon-protocol simon-client simon-cli simon-mcp; do
  npm publish "$PACKED/agnt-sdk-$name-$VERSION.tgz" --registry "$REGISTRY" --access public --provenance
done
