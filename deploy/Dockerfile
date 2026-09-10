# Gripline gateway container (P0.54 deployable executable).
#
# Build:  docker build -t gripline -f deploy/Dockerfile .
# Run:    see deploy/config.example.json; mount the config and state dirs.
#
# Security posture: distroless-style final image (no shell, no package
# manager), non-root user, read-only root filesystem friendly. The state
# database and signer keyring MUST be on a persistent volume — the runtime
# refuses to boot without them (deployment.allow_ephemeral_state defaults to
# false).

FROM golang:1.25.13-alpine@sha256:1e0126852075c9c60731c8ba49088448b91f63e2aed97ca9d1a9791622a05946 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.buildCommit=${COMMIT} -X main.buildDate=${BUILD_DATE}" -o /out/gripline ./cmd/gripline
RUN mkdir -p /out/state

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="gripline" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"
COPY --from=build /out/gripline /usr/local/bin/gripline
COPY --from=build --chown=65532:65532 /out/state/ /var/lib/gripline/
USER 65532:65532

# Config (read-only mount) and durable state (volume). If request bodies may be
# chunked, mount the configured spool_dir as a bounded writable tmpfs, for
# example: --tmpfs /tmp/gripline-spool:rw,noexec,nosuid,size=64m.
#   docker run -v ./config.json:/etc/gripline/config.json:ro \
#              -v gripline-state:/var/lib/gripline \
#              -p 8443:8443 -p 127.0.0.1:9090:9090 gripline
VOLUME ["/var/lib/gripline"]
EXPOSE 8443 9090

ENTRYPOINT ["/usr/local/bin/gripline"]
CMD ["serve", "--config", "/etc/gripline/config.json"]
