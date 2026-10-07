#!/usr/bin/env bash
# Shared Compose helpers for host-side maintenance scripts.
# shellcheck shell=bash

using_desktop_compose() {
    case "${NESSUS_COMPOSE_DESKTOP:-}" in
        1|true|yes) return 0 ;;
        0|false|no) return 1 ;;
    esac
    [ "$(docker info --format '{{.OperatingSystem}}' 2>/dev/null)" = "Docker Desktop" ]
}

compose() {
    if grep -qi microsoft /proc/version 2>/dev/null \
        && ! docker info >/dev/null 2>&1; then
        echo "[compose] Use Git Bash, not WSL bash: Docker Desktop is not available in this distro" >&2
        return 1
    fi
    local files=(-f docker-compose.yml)
    if using_desktop_compose; then
        files+=(-f docker-compose.desktop.yml)
    fi
    MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' docker compose "${files[@]}" "$@"
}

compose_bind() {
    local host="$1" dest="$2" mode="${3:-}"
    if command -v cygpath >/dev/null 2>&1; then
        host=$(cygpath -w "$host")
    fi
    if [ -n "$mode" ]; then
        printf '%s:%s:%s' "$host" "$dest" "$mode"
        return 0
    fi
    printf '%s:%s' "$host" "$dest"
}

compose_run() {
    compose run "$@"
}
