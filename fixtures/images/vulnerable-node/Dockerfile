# Golden-path fixture image (docs/RESET-PLAN.md, Phase 3).
# node:18.12-alpine is an old base with known OS-package CVEs that a base-image
# bump fixes; lodash 4.17.20 is a known dependency CVE that a lockfile update fixes.
FROM node:18.12-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY server.js ./
USER node
CMD ["node", "server.js"]
