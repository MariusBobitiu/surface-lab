FROM golang:1.25-alpine AS builder
WORKDIR /src

COPY services/wp-stack/go.mod services/wp-stack/go.sum ./services/wp-stack/
WORKDIR /src/services/wp-stack
RUN go mod download

WORKDIR /src
COPY . .
WORKDIR /src/services/wp-stack
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/wp-stack .

FROM alpine:3.22 AS runner
RUN apk add --no-cache ca-certificates
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=builder /out/wp-stack /usr/local/bin/wp-stack
USER app
EXPOSE 50062
CMD ["wp-stack"]
