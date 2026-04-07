# --- Node.js Planner Server ---
FROM node:22-alpine
WORKDIR /app

# Install deps first for layer caching
COPY package.json package-lock.json* ./
RUN npm install

# Copy source
COPY src/ ./src/

ENV NODE_ENV=production
ENV PLANNER_HOST=0.0.0.0
ENV PLANNER_PORT=3000

EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:${PLANNER_PORT}/health || exit 1

CMD ["node", "src/planner/server.mjs"]
