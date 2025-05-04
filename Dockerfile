FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o bin/auth ./cmd/auth

FROM alpine:3.21
RUN apk --no-cache add curl
WORKDIR /app
COPY --from=builder ./app/bin ./bin
COPY --from=builder ./app/config ./config

HEALTHCHECK --interval=30s --timeout=1m --start-period=30s --start-interval=10s --retries=2 CMD curl -f http://localhost:8081/api/v1/ping

ENTRYPOINT ["./bin/auth"]