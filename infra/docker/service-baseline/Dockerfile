FROM golang:1.24-alpine AS builder
WORKDIR /src

COPY services/service-baseline/go.mod services/service-baseline/go.sum ./services/service-baseline/
WORKDIR /src/services/service-baseline
RUN go mod download

WORKDIR /src
COPY . .
WORKDIR /src/services/service-baseline
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/service-baseline .

FROM alpine:3.22 AS runner
RUN apk add --no-cache ca-certificates
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=builder /out/service-baseline /usr/local/bin/service-baseline
USER app
EXPOSE 50061
CMD ["service-baseline"]
