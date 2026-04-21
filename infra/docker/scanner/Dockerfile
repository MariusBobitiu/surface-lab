FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/scanner .

FROM alpine:3.22 AS runner
RUN apk add --no-cache ca-certificates netcat-openbsd
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=builder /out/scanner /usr/local/bin/scanner
USER app
EXPOSE 50051
CMD ["scanner"]
