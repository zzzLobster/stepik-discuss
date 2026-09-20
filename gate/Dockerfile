FROM golang:1.27.1-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY gate ./gate
COPY .git ./.git
RUN CGO_ENABLED=0 go build -o /gate ./gate

FROM alpine:3.21
RUN apk add --no-cache ca-certificates wget && adduser -S -u 10001 gate && \
    mkdir /data && chown 10001:nogroup /data && chmod 700 /data
COPY --from=build /gate /gate
EXPOSE 8081
USER gate
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD wget -qO- http://127.0.0.1:8081/healthz | grep -q '"ok":true' || exit 1
ENTRYPOINT ["/gate"]
