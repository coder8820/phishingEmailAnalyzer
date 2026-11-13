# ============================================================
# Frontend Dockerfile — PhishGuard AI
# ============================================================
FROM node:20-alpine AS base
ENV NODE_ENV=production
WORKDIR /app

# ---- Dependencies ----
FROM base AS dependencies
COPY package.json package-lock.json* ./
RUN npm ci --only=production

# ---- Build ----
FROM base AS builder
COPY package.json package-lock.json* ./
RUN npm ci
COPY . .
RUN npm run build

# ---- Production runner ----
FROM base AS production
# Non-root user
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]

# ---- Development ----
FROM node:20-alpine AS development
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY . .
CMD ["npm", "run", "dev"]
