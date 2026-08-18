# apiary-dashboard-next — the TanStack Start SSR/BFF tier (#1608).
# Nitro's node-server output is self-contained (.output holds server +
# client assets + public/static, including the vendored theme.css copy).
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine
WORKDIR /app
COPY --from=build /app/.output ./.output
ENV PORT=8080 NODE_ENV=production
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --retries=5 --start-period=20s \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/static/theme.css || exit 1
USER node
CMD ["node", ".output/server/index.mjs"]
