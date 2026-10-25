# Two images from this repository. Node 26 runs the TypeScript sources directly (type stripping), so
# neither has a build step.
#
#   docker build -t simon-server .             the basic server (server/): the default, last stage
#   docker build -t simon-app --target app .   the application template (app/), for MongoDB
#
# Both are configured by environment variables (server/README.md, app/README.md) and listen on SIMON_PORT.

# The application template: the basic server plus its modules, with the npm packages app/ depends on.
FROM node:26-alpine AS app
WORKDIR /simon
# npm needs every workspace's package.json to read the lockfile; only app/'s dependencies are installed.
COPY package.json package-lock.json ./
COPY protocol/package.json protocol/
COPY conformance/package.json conformance/
COPY server/package.json server/
COPY store-mongo/package.json store-mongo/
COPY app/package.json app/
COPY clients/js/package.json clients/js/
COPY clients/cli/package.json clients/cli/
COPY clients/mcp/package.json clients/mcp/
COPY examples/package.json examples/
RUN npm ci --omit=dev --ignore-scripts --workspace app --include-workspace-root=false && npm cache clean --force
COPY protocol/src protocol/src
COPY server/src server/src
COPY store-mongo/src store-mongo/src
COPY clients/js/src clients/js/src
COPY app/src app/src
ENV NODE_ENV=production SIMON_PORT=8090
EXPOSE 8090
USER node
WORKDIR /simon/app
CMD ["node", "src/main.ts"]

# The basic server: Node's standard library and @agnt-sdk/simon-protocol, nothing from npm. Its sqlite file is
# in the /data volume.
FROM node:26-alpine AS server
WORKDIR /simon
COPY protocol/package.json protocol/
COPY protocol/src protocol/src
COPY server/package.json server/
COPY server/src server/src
# @agnt-sdk/simon-protocol resolves through a link, as npm's workspaces make one: Node strips types only from
# files outside node_modules, and the link's target is outside. npm itself is removed from the image.
RUN mkdir -p node_modules/@agnt-sdk /data \
  && ln -s ../../protocol node_modules/@agnt-sdk/simon-protocol \
  && chown node:node /data \
  && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
    /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg
ENV NODE_ENV=production SIMON_PORT=8080 SIMON_DB=/data/simon.sqlite
VOLUME /data
EXPOSE 8080
USER node
WORKDIR /simon/server
CMD ["node", "src/main.ts"]
