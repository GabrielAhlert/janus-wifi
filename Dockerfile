FROM docker.io/library/golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/janus ./cmd/janus

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/janus /janus
EXPOSE 8080 8081 5514/udp 5514/tcp
ENTRYPOINT ["/janus"]
CMD ["serve"]
