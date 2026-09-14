FROM golang:1.27.1 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o fetch-k8s-cert .

FROM alpine:latest
RUN apk --no-cache add ca-certificates socat
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
COPY --from=builder /app/fetch-k8s-cert /usr/local/bin/fetch-k8s-cert
RUN chown appuser:appgroup /usr/local/bin/fetch-k8s-cert && chmod 755 /usr/local/bin/fetch-k8s-cert
WORKDIR /home/appuser
RUN chown -R appuser:appgroup /home/appuser
USER appuser
CMD ["fetch-k8s-cert"]
