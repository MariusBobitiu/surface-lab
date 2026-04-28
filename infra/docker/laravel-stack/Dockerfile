FROM golang:1.25-alpine AS builder
WORKDIR /src

COPY services/laravel-stack/go.mod services/laravel-stack/go.sum ./services/laravel-stack/
WORKDIR /src/services/laravel-stack
RUN go mod download

WORKDIR /src
COPY . .
WORKDIR /src/services/laravel-stack
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/laravel-stack .

FROM alpine:3.22 AS runner
RUN apk add --no-cache ca-certificates
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=builder /out/laravel-stack /usr/local/bin/laravel-stack
USER app
EXPOSE 50063
CMD ["laravel-stack"]
