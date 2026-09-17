FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY gate ./gate
RUN CGO_ENABLED=0 go build -o /gate ./gate

FROM alpine:3.21
RUN apk add --no-cache ca-certificates wget && adduser -S -u 10001 gate
COPY --from=build /gate /gate
EXPOSE 8081
USER gate
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD wget -qO- http://127.0.0.1:8081/healthz | grep -q '"ok":true' || exit 1
ENTRYPOINT ["/gate"]
