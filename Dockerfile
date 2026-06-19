FROM node:22-alpine AS assets
WORKDIR /src
COPY package.json package-lock.json* tailwind.config.js ./
COPY internal/ui ./internal/ui
RUN npm ci
RUN npm run build:css

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY go.sum* ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY --from=assets /src/internal/ui/static/app.css ./internal/ui/static/app.css
RUN go build -trimpath -ldflags="-s -w" -o /out/light-ipam ./cmd/server

FROM alpine:3.20
# postgresql-client provides pg_dump/pg_restore for the in-app backup feature.
# It is an ordinary TCP database client — the app keeps zero Linux capabilities.
RUN apk add --no-cache postgresql16-client
RUN addgroup -S lightipam && adduser -S -G lightipam lightipam
RUN mkdir -p /var/lib/lightipam/backups && chown -R lightipam:lightipam /var/lib/lightipam
USER lightipam
WORKDIR /app
COPY --from=build /out/light-ipam /app/light-ipam
EXPOSE 8080
ENTRYPOINT ["/app/light-ipam"]
