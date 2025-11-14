FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

#stage 2
FROM node:20-alpine AS runner
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY ./backend ./backend
RUN mkdir -p /var/data/uploads \
    && ln -s /var/data/uploads /app/uploads
EXPOSE 5000
CMD [ "node", "backend/server.js" ]