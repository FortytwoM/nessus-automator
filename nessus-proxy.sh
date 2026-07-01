# Sourced by docker-entrypoint.sh, patch.sh, update.sh.
# NESSUS_* vars are optional: unset = we do not set outbound proxy ourselves.
# Local Nessus (https://127.0.0.1:8834) must not use Docker/host HTTP(S)_PROXY.

nessus_export_proxy() {
    local hp="${NESSUS_HTTP_PROXY:-}"
    local hsp="${NESSUS_HTTPS_PROXY:-}"
    local ap="${NESSUS_ALL_PROXY:-}"

    if [ -n "${NESSUS_PROXY:-}" ]; then
        [ -z "$hp" ] && hp="$NESSUS_PROXY"
        [ -z "$hsp" ] && hsp="$NESSUS_PROXY"
    fi

    if [ -z "$hp" ] && [ -z "$hsp" ] && [ -z "$ap" ]; then
        if [ -n "${HTTP_PROXY:-}" ] || [ -n "${http_proxy:-}" ] ||
            [ -n "${HTTPS_PROXY:-}" ] || [ -n "${https_proxy:-}" ] ||
            [ -n "${ALL_PROXY:-}" ] || [ -n "${all_proxy:-}" ]; then
            local base="${NESSUS_NO_PROXY:-localhost,127.0.0.1,::1}"
            local extra="${no_proxy:-${NO_PROXY:-}}"
            if [ -n "$extra" ]; then
                export no_proxy="${base},${extra}" NO_PROXY="${base},${extra}"
            else
                export no_proxy="$base" NO_PROXY="$base"
            fi
        fi
        return 0
    fi

    [ -n "$hp" ] && export http_proxy="$hp" HTTP_PROXY="$hp"
    [ -n "$hsp" ] && export https_proxy="$hsp" HTTPS_PROXY="$hsp"
    [ -n "$ap" ] && export all_proxy="$ap" ALL_PROXY="$ap"

    local np="${NESSUS_NO_PROXY:-localhost,127.0.0.1,::1}"
    export no_proxy="$np" NO_PROXY="$np"
}
