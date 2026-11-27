# Multi-stage build for kymessages

# Pinned build toolchains; no generated WebAssembly is stored in the repository.
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS go-toolchain
FROM rust:1.99.0-alpine@sha256:0cce0a5e0e8ba67b455257a3a02a1d99005f382748789d6464460028810f1627 AS rust-toolchain

# Stage 1: Build React PWA Frontend
FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS frontend-builder
COPY --from=go-toolchain /usr/local/go /usr/local/go
COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo RUSTUP_HOME=/usr/local/rustup
ENV PATH="/usr/local/go/bin:/usr/local/cargo/bin:$PATH"
RUN apk add --no-cache bash build-base
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
WORKDIR /app/web
COPY web/crypto/rust-toolchain.toml ./crypto/
# wasm-bindgen-cli's locked buf_redux/multipart dependencies emit future-Rust warnings.
# These are build-tool dependencies only; product Rust passes clippy with -D warnings.
RUN cd crypto && cargo +1.99.0 install --locked wasm-bindgen-cli --version 0.2.130
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
COPY scripts/build-crypto.sh scripts/build-pqwasm.sh /app/scripts/
COPY internal/e2eeid /app/internal/e2eeid
RUN npm run build

# Stage 2: Build Go Standalone Binary
FROM go-toolchain AS backend-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
COPY --from=frontend-builder /app/web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o kymessages ./cmd/server

# Stage 3: Minimal Production Container
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=backend-builder /app/kymessages /app/kymessages
# /app/backups is the optional mount for sealed local capsules; KY_BACKUP_DIR is set by the
# operator (compose does), so an image run bare keeps no local copies.
# Never root: Compose runs it as the owner of ./data (KY_UID);
# a bare run uses 10001, which owns the image's own volumes.
RUN mkdir -p /app/data /app/backups && chown 10001:10001 /app/data /app/backups
USER 10001:10001

ENV KY_PORT=8080
ENV KY_HOST=0.0.0.0
ENV KY_DATA_DIR=/app/data

EXPOSE 8080
VOLUME ["/app/data", "/app/backups"]

ENTRYPOINT ["/app/kymessages"]
