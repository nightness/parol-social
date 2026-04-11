# Stage 1: Build relay server binary
FROM rust:1.92-alpine AS builder
RUN apk add --no-cache musl-dev pkgconfig
WORKDIR /build
COPY . .
RUN cargo build --release -p parolnet-relay-server --features analytics

# Stage 2: Runtime with nginx + relay
FROM nginx:alpine

# Nginx config
COPY server/nginx.conf /etc/nginx/conf.d/default.conf

# Static files
COPY server/index.html /usr/share/nginx/html/index.html
COPY server/install.html /usr/share/nginx/html/install.html
COPY pwa/ /usr/share/nginx/html/pwa/

# Relay binary
COPY --from=builder /build/target/release/parolnet-relay /usr/local/bin/parolnet-relay

# Entrypoint script
COPY server/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80

CMD ["/entrypoint.sh"]
