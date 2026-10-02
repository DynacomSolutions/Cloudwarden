# Dev container for `devdeploy` (docs/local-dev.md). It runs the Worker in the local workerd
# simulator with throwaway state; it is a development convenience, not the production deploy path.
FROM node:22-slim

# `openssl` is for the end-to-end suite; `ca-certificates` for npm downloads.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates openssl \
 && rm -rf /var/lib/apt/lists/* \
 && corepack enable

WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .

# Build the web client into the image with `--build-arg WEB_VAULT=true` (docs/web-client.md;
# needs network and about 10 GiB of memory at build time). A prebuilt `web-vault/` is copied as is.
ARG WEB_VAULT=false
RUN if [ "$WEB_VAULT" = "true" ]; then node scripts/build-web.mjs --no-scope; fi

ENV CI=true
EXPOSE 8080
CMD ["node", "scripts/dev-container.mjs"]
