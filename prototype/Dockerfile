FROM rust:1.100-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libwebkit2gtk-4.1-dev libxdo-dev libssl-dev librsvg2-dev \
    libayatana-appindicator3-dev libgtk-3-dev openssh-server xvfb dbus-x11 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source/prototype
