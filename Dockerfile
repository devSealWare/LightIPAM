FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
RUN go build -trimpath -ldflags="-s -w" -o /out/light-ipam ./cmd/server

FROM alpine:3.20
RUN addgroup -S lightipam && adduser -S -G lightipam lightipam
USER lightipam
WORKDIR /app
COPY --from=build /out/light-ipam /app/light-ipam
EXPOSE 8080
ENTRYPOINT ["/app/light-ipam"]
