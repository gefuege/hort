# Hort — CLI image. Mount /var/lib/hort/.hort for persistent vault state.
# Build: docker build -t ghcr.io/gefuege/hort:dev .
# Run: docker run --rm -it -v hort-state:/var/lib/hort/.hort ghcr.io/gefuege/hort:dev init

ARG GO_VERSION=1.26
ARG DEBIAN_VERSION=bookworm-20241016-slim

FROM golang:${GO_VERSION}-bookworm AS builder

# Let Go auto-download a newer toolchain if go.mod requires one.
ENV GOTOOLCHAIN=auto

WORKDIR /src

# Cache module downloads separately from source compilation.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=docker
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Static binary, stripped. Same flags GoReleaser uses for the CLI build.
ENV CGO_ENABLED=0
RUN go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
      -o /out/hort \
      ./cmd/hort

# ---------- Runtime ----------
FROM debian:${DEBIAN_VERSION} AS runtime

RUN apt-get update -y \
 && apt-get install -y --no-install-recommends ca-certificates \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --home-dir /var/lib/hort --shell /usr/sbin/nologin --uid 1000 hort \
 && mkdir -p /var/lib/hort/.hort \
 && chown -R hort:hort /var/lib/hort

COPY --from=builder /out/hort /usr/local/bin/hort

USER hort
ENV HOME=/var/lib/hort

VOLUME ["/var/lib/hort/.hort"]

ENTRYPOINT ["/usr/local/bin/hort"]
CMD ["--help"]
