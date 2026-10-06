FROM golang:1.25.7-alpine AS build
RUN apk add --no-cache ca-certificates git
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download
COPY . ./

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_TIME=unknown
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV CGO_ENABLED=0
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags "-s -w -X github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/version.Version=${VERSION} -X github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/version.Commit=${COMMIT} -X github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/version.BuildTime=${BUILD_TIME}" \
    -o /out/server ./cmd/server \
 && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags "-s -w -X github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/version.Version=${VERSION} -X github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/version.Commit=${COMMIT} -X github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/version.BuildTime=${BUILD_TIME}" \
    -o /out/garmr ./cmd/garmr

FROM alpine:3.22
RUN apk add --no-cache ca-certificates wget \
    && addgroup -S -g 10001 mirrors-waf \
    && adduser -S -D -H -u 10001 -G mirrors-waf mirrors-waf \
    && mkdir -p /etc/mirrors-waf /var/lib/mirrors-waf \
    && chown -R 10001:10001 /etc/mirrors-waf /var/lib/mirrors-waf

COPY --from=build /out/server /usr/local/bin/server
COPY --from=build /out/garmr /usr/local/bin/garmr

WORKDIR /var/lib/mirrors-waf
USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O - http://127.0.0.1:8080/healthz >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/server"]
CMD ["--config", "/etc/mirrors-waf/config.yaml"]
