FROM golang:1.24-alpine

RUN apk add --no-cache bash curl && \
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/BakeLens/crust/main/install.sh)"

EXPOSE 9090
ENTRYPOINT ["/root/.local/bin/crust", "start", "--foreground", "--auto", "--listen-address", "0.0.0.0"]
