FROM oven/bun:1-alpine
WORKDIR /app
COPY simple-share-relay.mjs ./simple-share-relay.mjs
EXPOSE 3499
ENV HOST=0.0.0.0 PORT=3499
CMD ["bun", "simple-share-relay.mjs"]
