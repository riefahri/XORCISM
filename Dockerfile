# syntax=docker/dockerfile:1
#
# XORCISM — application image (TypeScript/Express server + bundled client).
# Multi-stage build: compile the native better-sqlite3 module and produce the
# bundles in the builder, then ship only the runtime. SQLite databases live in a
# volume (/data) and are auto-created on first start.
#
# Scope: this image runs the Node WEB application only. The security connectors
# are Python and run via connectors/runner.py on a worker (local sidecar or a
# remote worker); their manifests are copied in so the Connectors catalog is
# listed in the UI even though this image does not execute them.

# ── Build stage ────────────────────────────────────────────────────────────────
FROM node:20-bookworm AS builder
# Build toolchain for the native better-sqlite3 module (node-gyp)
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app/xorcism_ts

# Dependencies first (Docker layer cache) — needs package.json + lockfile
COPY xorcism_ts/package.json xorcism_ts/package-lock.json ./
RUN npm ci

# Source + build (server: tsc → dist/server ; client: esbuild → dist/client/js)
COPY xorcism_ts/ ./
RUN npm run build

# Drop dev dependencies (keeps the compiled better-sqlite3 binary)
RUN npm prune --omit=dev

# ── Runtime stage ──────────────────────────────────────────────────────────────
# bookworm-slim matches the builder's Debian 12 glibc, so the native
# better-sqlite3 binary compiled above stays ABI-compatible.
FROM node:20-bookworm-slim AS runtime
LABEL org.opencontainers.image.title="XORCISM" \
      org.opencontainers.image.description="Open unified cybersecurity management platform — cyber exposure, threat & compliance." \
      org.opencontainers.image.url="https://xorcism.ai" \
      org.opencontainers.image.vendor="XORCISM"
ENV NODE_ENV=production \
    DB_DIR=/data \
    PORT=9292
WORKDIR /app/xorcism_ts

# Compiled artifacts + production deps + statics served directly
COPY --from=builder /app/xorcism_ts/node_modules ./node_modules
COPY --from=builder /app/xorcism_ts/dist ./dist
COPY --from=builder /app/xorcism_ts/package.json ./package.json
COPY xorcism_ts/client ./client
# DB schema SQL — resolved as ../../../databases from dist/server (=> /app/databases)
COPY databases /app/databases
# Connector manifests — resolved as ../../../../connectors from dist/server/routes
# (=> /app/connectors) so the Connectors catalog is listed in the UI.
COPY connectors /app/connectors

# SQLite databases volume (bind-mount your XORCISM_databases here to reuse them)
VOLUME /data
RUN mkdir -p /data && chown -R node:node /data /app
USER node

EXPOSE 9292
# Healthcheck: the login page answers (any non-5xx => healthy)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:'+(process.env.PORT||9292)+'/login',r=>process.exit(r.statusCode<500?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "dist/server/index.js"]
