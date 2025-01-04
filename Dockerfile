FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY . .
RUN go build -o slackattack

FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/slackattack .

ENTRYPOINT ["/app/slackattack"] 