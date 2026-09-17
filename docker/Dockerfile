# syntax=docker/dockerfile:1.7
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json nest-cli.json ./
COPY src ./src
# npm run build = nest build + tsc-alias. tsc-alias is REQUIRED: without it dist/ keeps the
# "@config"/"@core" path aliases and `node dist/main.js` dies with MODULE_NOT_FOUND at boot.
# Prune only afterwards - tsc-alias is a devDependency.
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
RUN addgroup -S app && adduser -S app -G app
COPY --from=build --chown=app:app /app/node_modules ./node_modules
COPY --from=build --chown=app:app /app/dist ./dist
COPY --chown=app:app public ./public
COPY --chown=app:app package.json ./
# Created (and owned) in the image so a named volume mounted at /app/.keys inherits this
# ownership instead of arriving root-owned and unwritable by USER app.
RUN mkdir -p /app/.keys && chown app:app /app/.keys
USER app
EXPOSE 3001
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD wget -qO- http://127.0.0.1:3001/health || exit 1
CMD ["node", "dist/main.js"]
