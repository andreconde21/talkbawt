FROM node:24-alpine

ENV NODE_ENV=production \
    PORT=3000 \
    DB_PATH=/data/talkbawt.db

WORKDIR /app
COPY package.json ./
COPY src ./src

# /data is created in the image and owned by the app user, so a fresh named
# volume inherits that ownership and the container never needs root.
RUN addgroup -S talkbawt && adduser -S talkbawt -G talkbawt \
 && mkdir -p /data && chown -R talkbawt:talkbawt /data /app
USER talkbawt

EXPOSE 3000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "src/server.mjs"]
