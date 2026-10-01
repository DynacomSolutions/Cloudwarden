# Dev container for `devdeploy` (docs/local-dev.md). It runs the Worker in the local workerd
# simulator with throwaway state; it is a development convenience, not the production deploy path.
FROM node:22-slim

# `openssl` is for the end-to-end suite; `ca-certificates` for fetching the optional web vault.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates openssl \
 && rm -rf /var/lib/apt/lists/* \
 && corepack enable

WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .

# Bake in the official web vault with `--build-arg WEB_VAULT=true` (needs network at build time).
ARG WEB_VAULT=false
RUN if [ "$WEB_VAULT" = "true" ]; then pnpm web-vault:fetch; fi

ENV CI=true
EXPOSE 8080
CMD ["node", "scripts/dev-container.mjs"]
