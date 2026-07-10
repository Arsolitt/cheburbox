# syntax=docker/dockerfile:1

# Global build args — declared before any FROM so both stages can resolve them.
# Pin by digest for reproducible builds:
#   --build-arg GO_IMAGE=golang:1.26-bookworm@sha256:<digest>
#   --build-arg RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:<digest>
ARG GO_IMAGE=golang:1.26-bookworm
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

# Builder stage: compile a static pure-Go binary (CGO disabled, no libc dependency).
FROM ${GO_IMAGE} AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src

# Cache downloaded modules in a dedicated layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/cheburbox ./cmd/cheburbox/

# Runtime stage: distroless static image, non-root uid 65532, no shell.
FROM ${RUNTIME_IMAGE}

ARG VERSION=dev
ARG REVISION=
ARG CREATED=

LABEL org.opencontainers.image.title="cheburbox" \
      org.opencontainers.image.description="Declarative sing-box configuration generator and validator" \
      org.opencontainers.image.source="https://github.com/Arsolitt/cheburbox" \
      org.opencontainers.image.url="https://github.com/Arsolitt/cheburbox" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

COPY --from=builder /out/cheburbox /cheburbox

ENTRYPOINT ["/cheburbox"]
