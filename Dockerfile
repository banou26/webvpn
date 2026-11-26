FROM rust:1.96.0-slim-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN cargo build --release --locked -p webvpnd

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/webvpnd /usr/local/bin/webvpnd
EXPOSE 4433/udp 8443/tcp
CMD ["webvpnd"]
