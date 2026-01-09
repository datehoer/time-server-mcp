# syntax=docker/dockerfile:1

FROM node:22-alpine AS build
WORKDIR /app

RUN corepack enable

COPY package.json pnpm-lock.yaml tsconfig.json ./
COPY src ./src
COPY public ./public

RUN pnpm install --frozen-lockfile
RUN pnpm build
RUN pnpm prune --prod

FROM node:22-alpine AS runtime
WORKDIR /app

ENV NODE_ENV=production

COPY --from=build --chown=node:node /app/package.json ./package.json
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/public ./public

USER node

EXPOSE 3001
CMD ["node", "dist/main.js"]
