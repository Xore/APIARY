# apiary-dashboard-next — the TanStack Start SSR/BFF tier (#1608).
# Nitro's node-server output is self-contained (.output holds server +
# client assets + public/static, including the vendored theme.css copy).
FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32
WORKDIR /app
COPY --from=build /app/.output ./.output
COPY server ./server
ENV PORT=8080 NODE_ENV=production
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --retries=5 --start-period=20s \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/static/theme.css || exit 1
USER node
# #1616: cluster.mjs forks WEB_CONCURRENCY copies of index.mjs (default
# min(4, host cpus) — see the file for why) instead of running the one
# process index.mjs used to be invoked as directly.
CMD ["node", "server/cluster.mjs"]
