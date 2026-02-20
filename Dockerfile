FROM golang:1.24

RUN apt-get update && apt-get install -y --no-install-recommends bash curl git sqlite3 && \
    rm -rf /var/lib/apt/lists/* && \
    curl -fsSL https://raw.githubusercontent.com/BakeLens/crust/main/install.sh | bash -s -- --no-font

EXPOSE 9090
ENV PATH="$PATH:/root/.local/bin"
ENTRYPOINT ["/root/.local/bin/crust", "start", "--foreground", "--auto", "--listen-address", "0.0.0.0"]
