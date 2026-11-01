# ====================================================
# TrustVault - Production Multi-Stage Container Image
# ====================================================

FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Install npm dependencies
COPY package*.json ./
COPY prisma ./prisma/
RUN npm ci

# Copy source code and configurations
COPY tsconfig.json ./
COPY src ./src
COPY public ./public

# Generate Prisma Client & compile TypeScript
RUN npx prisma generate
RUN npm run build

# ====================================================
# Production Runner Stage
# ====================================================
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=4000
ENV STORAGE_DIR=/app/storage/blobs
ENV DATABASE_URL="file:/app/prisma/vault.db"

# Install production dependencies only
COPY package*.json ./
COPY prisma ./prisma/
RUN npm ci --omit=dev && npx prisma generate

# Copy built application & static assets from builder stage
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/public ./public
COPY scripts ./scripts

# Create storage & database directories with proper permissions
RUN mkdir -p /app/storage/blobs /app/prisma

EXPOSE 4000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:4000/api/health || exit 1

# Start server: Push schema, ensure benchmark personas, run production server
CMD ["sh", "-c", "npx prisma db push --skip-generate && node dist/index.js"]
