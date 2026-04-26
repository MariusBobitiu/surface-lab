FROM golang:1.24-alpine AS builder
WORKDIR /src

COPY services/php-stack/go.mod services/php-stack/go.sum ./services/php-stack/
WORKDIR /src/services/php-stack
RUN go mod download

WORKDIR /src
COPY . .
WORKDIR /src/services/php-stack
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/php-stack .

FROM alpine:3.22 AS runner
RUN apk add --no-cache ca-certificates
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=builder /out/php-stack /usr/local/bin/php-stack
USER app
EXPOSE 50064
CMD ["php-stack"]
