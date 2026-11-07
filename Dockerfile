FROM docker.io/library/golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/janus ./cmd/janus \
 && mkdir -p /out/data /out/secrets

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/janus /janus
# /data guarda o SQLite padrão e /secrets a chave mestra. São graváveis pelo
# usuário nonroot; com --user 99:100 (Unraid), monte volumes com esse dono.
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/secrets /secrets
ENV JANUS_MASTER_KEY_FILE=/secrets/master_key
VOLUME ["/data", "/secrets"]
EXPOSE 8080 8081 5514/udp 5514/tcp
ENTRYPOINT ["/janus"]
CMD ["serve"]
