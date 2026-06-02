FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
RUN go build -trimpath -ldflags="-s -w" -o /out/netventory ./cmd/server

FROM alpine:3.20
RUN addgroup -S netventory && adduser -S -G netventory netventory
USER netventory
WORKDIR /app
COPY --from=build /out/netventory /app/netventory
EXPOSE 8080
ENTRYPOINT ["/app/netventory"]

