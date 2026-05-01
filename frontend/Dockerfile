FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ENV NEXT_PUBLIC_API_URL=http://localhost:8000
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public

# Drop privileges. node:20-alpine ships a non-root `node` user (uid 1000)
# specifically for this. Defense in depth — if the Next.js process is
# RCE'd (e.g. via the same kind of CVE we just patched in next 16.2.4),
# the attacker doesn't get root inside the container and can't write to
# system paths. chown is required because COPY --from sets root:root by
# default and the standalone build needs read access from `node`.
RUN chown -R node:node /app
USER node

EXPOSE 3000

# Liveness probe: the standalone server exposes /api/health at the root
# (Next.js doesn't auto-add /healthz, but our backend mirror /health is
# what the platform checks). For the *frontend* container, a simple HTTP
# GET / (the Next-rendered home page) is the cheapest signal.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --quiet --spider http://127.0.0.1:3000/ || exit 1

CMD ["node", "server.js"]
