# Keep in step with the go line in go.mod (CI checks).
FROM golang:1.27.2-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/lanternfish-gate ./cmd/lanternfish-gate \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/lanternfish-gate /usr/local/bin/lanternfish-gate
COPY --from=build --chown=65532:65532 /out/data /data
ENV LANTERNFISH_DATA=/data/gate.json \
    LANTERNFISH_AUDIT_LOG=/data/audit.log \
    LANTERNFISH_LISTEN=:8443
VOLUME /data
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/lanternfish-gate"]
CMD ["serve"]
