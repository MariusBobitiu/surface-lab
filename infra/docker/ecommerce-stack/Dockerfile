FROM golang:1.25-alpine AS builder
WORKDIR /src

COPY services/ecommerce-stack/go.mod services/ecommerce-stack/go.sum ./services/ecommerce-stack/
WORKDIR /src/services/ecommerce-stack
RUN go mod download

WORKDIR /src
COPY . .
WORKDIR /src/services/ecommerce-stack
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/ecommerce-stack .

FROM alpine:3.22 AS runner
RUN apk add --no-cache ca-certificates
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=builder /out/ecommerce-stack /usr/local/bin/ecommerce-stack
USER app
EXPOSE 50065
CMD ["ecommerce-stack"]
