# --- Node.js Planner Server ---
FROM node:22-alpine
WORKDIR /app

# Install deps first for layer caching
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# npm is only needed at build time; the planner runs node directly.
# Strip npm/npx so the runtime image doesn't ship npm's bundled dependency tree
# (the source of the HIGH findings in the security scan).
RUN rm -rf /usr/local/lib/node_modules/npm && rm -f /usr/local/bin/npm /usr/local/bin/npx

# Copy source
COPY src/ ./src/

# Run the planner without root privileges.
RUN addgroup -S -g 10001 app && adduser -S -u 10001 -G app app && chown -R app:app /app
USER app

ENV NODE_ENV=production
ENV PLANNER_HOST=0.0.0.0
ENV PLANNER_PORT=3000

EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:${PLANNER_PORT}/health || exit 1

CMD ["node", "src/planner/server.mjs"]
