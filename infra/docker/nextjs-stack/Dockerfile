FROM golang:1.25-alpine AS builder
WORKDIR /src

COPY services/nextjs-stack/go.mod services/nextjs-stack/go.sum ./services/nextjs-stack/
WORKDIR /src/services/nextjs-stack
RUN go mod download

WORKDIR /src
COPY . .
WORKDIR /src/services/nextjs-stack
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/nextjs-stack .

FROM alpine:3.22 AS runner
RUN apk add --no-cache ca-certificates
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=builder /out/nextjs-stack /usr/local/bin/nextjs-stack
USER app
EXPOSE 50061
CMD ["nextjs-stack"]
