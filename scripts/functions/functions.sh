#!/usr/bin/env bash

install_docker_desktop() {
    local user
    user=$(whoami)
    local FORCE_REINSTALL=0
    local ARCH
    ARCH=$( [[ "$(uname -m)" =~ aarch64|arm64 ]] && echo arm64 || echo amd64 )

    trap 'cleanup' EXIT TERM INT
    cleanup() { info "Cleaning up"; rm -f Docker.dmg 2>/dev/null || true && ok; }

    download_docker_desktop() {
        if [ -f Docker.dmg ] && [ "${FORCE_REINSTALL}" != 1 ]; then
            info "Docker.dmg already exists. Skipping download."
        else
            rm -f Docker.dmg
            info "Downloading Docker Desktop..."
            wget -q --show-progress "https://desktop.docker.com/mac/main/${ARCH}/Docker.dmg" -O Docker.dmg
        fi
    }

    install_docker_desktop_internal() {
        download_docker_desktop
        info "Installing Docker Desktop for user ${user}..."
        sudo hdiutil attach Docker.dmg >/dev/null 2>&1
        sudo /Volumes/Docker/Docker.app/Contents/MacOS/install --accept-license --user="${user}"
        sudo xattr -dr com.apple.quarantine /Applications/Docker.app >/dev/null 2>&1 || true
        sudo hdiutil detach /Volumes/Docker >/dev/null 2>&1
    }

    is_docker_running() {
        if docker info >/dev/null 2>&1; then
            info "Docker is running."
        else
            info "Docker is not running. Starting Docker Desktop..."
            open -a Docker
            sleep 20
        fi
    }
    if command -v docker >/dev/null 2>&1; then
        info "Docker Desktop or Docker cli already installed"
        ok
        return 0
    fi
    info "Starting Docker Desktop installation..."
    install_docker_desktop_internal
    is_docker_running
    info "Docker Desktop installation complete!"
}
