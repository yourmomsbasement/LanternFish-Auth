# Keep in step with the go line in go.mod (CI checks). Images are pinned by
# digest: a tag can be moved to different contents, a digest can't. Update
# the digest with the tag.
FROM golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/lanternfish-gate ./cmd/lanternfish-gate \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/lanternfish-gate /usr/local/bin/lanternfish-gate
COPY --from=build --chown=65532:65532 /out/data /data
ENV LANTERNFISH_DATA=/data/gate.json \
    LANTERNFISH_AUDIT_LOG=/data/audit.log \
    LANTERNFISH_LISTEN=:8443
VOLUME /data
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/lanternfish-gate"]
CMD ["serve"]
