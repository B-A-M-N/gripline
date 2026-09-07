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

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gripline ./cmd/gripline
RUN mkdir -p /out/state

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gripline /usr/local/bin/gripline
COPY --from=build --chown=65532:65532 /out/state/ /var/lib/gripline/
USER 65532:65532

# Config (read-only mount) and durable state (volume).
#   docker run -v ./config.json:/etc/gripline/config.json:ro \
#              -v gripline-state:/var/lib/gripline \
#              -p 8443:8443 -p 127.0.0.1:9090:9090 gripline
VOLUME ["/var/lib/gripline"]
EXPOSE 8443 9090

ENTRYPOINT ["/usr/local/bin/gripline"]
CMD ["-config", "/etc/gripline/config.json"]
