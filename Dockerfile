FROM golang:1.16-alpine AS builder

COPY . /build

WORKDIR /build/auth-server

RUN  go build

FROM alpine:latest

COPY --from=builder /build/auth-server/auth-server /usr/bin/auth-server

RUN adduser -S auth

USER auth

CMD ["/usr/bin/auth-server"]