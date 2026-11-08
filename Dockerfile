FROM golang:1.27.3-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /cinderlock ./cmd/cinderlock

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build --chmod=0555 /cinderlock /usr/local/bin/cinderlock
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/usr/local/bin/cinderlock"]
