FROM golang:1.24-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -ldflags "-s -w" -o /usr/local/bin/crust .

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/crust /usr/local/bin/crust
ENV PATH="$PATH:/usr/local/bin"

EXPOSE 9090
ENTRYPOINT ["crust", "start", "--foreground", "--auto", "--listen-address", "0.0.0.0"]
