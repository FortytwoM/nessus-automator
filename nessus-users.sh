# Nessus user management (single admin user).
# shellcheck shell=bash

nessus_user_exists() {
    local username="$1"
    local existing

    existing=$(sqlite3 /opt/nessus/var/nessus/global.db "SELECT username FROM Users;" 2>/dev/null) || true
    if echo "$existing" | grep -q "^${username}$"; then
        return 0
    fi

    if /opt/nessus/sbin/nessuscli lsuser 2>/dev/null | grep -q "^${username}$"; then
        return 0
    fi

    return 1
}

nessus_create_user() {
    local username="$1"
    local password="$2"
    local is_admin="${3:-n}"
    local log_fn="${4:-echo}"

    if nessus_user_exists "$username"; then
        $log_fn "User '$username' exists"
        return 0
    fi

    $log_fn "Creating user '$username'..."

    export EXPECT_USERNAME="$username"
    export EXPECT_PASSWORD="$password"
    export EXPECT_IS_ADMIN="$is_admin"

    local max_wait=300
    local waited=0
    local attempt=0
    while [ $waited -lt $max_wait ]; do
        attempt=$((attempt + 1))
        result=$(expect <<'EXPECT_SCRIPT' 2>&1
set timeout 60
log_user 0
spawn /opt/nessus/sbin/nessuscli adduser $env(EXPECT_USERNAME)

expect {
    "Login password:" {
        send "$env(EXPECT_PASSWORD)\r"
        exp_continue
    }
    "Login password (again):" {
        send "$env(EXPECT_PASSWORD)\r"
        exp_continue
    }
    "system administrator" {
        expect -re {\(y/n\).*:}
        if { $env(EXPECT_IS_ADMIN) eq "y" } {
            send "y\r"
        } else {
            send "n\r"
        }
        exp_continue
    }
    "Enter the rules for this user" {
        send "\r"
        exp_continue
    }
    "Is that ok?" {
        expect -re {\(y/n\).*:}
        send "y\r"
        exp_continue
    }
    "User added" {
        puts "OK"
        exit 0
    }
    "already exists" {
        puts "OK"
        exit 0
    }
    "global.db is not ready yet" {
        puts "RETRY"
        exit 2
    }
    "global.db is not ready" {
        puts "RETRY"
        exit 2
    }
    timeout {
        puts "TIMEOUT"
        exit 1
    }
    eof {
        puts "EOF"
        exit 1
    }
}
EXPECT_SCRIPT
)

        if echo "$result" | grep -q "OK"; then
            $log_fn "User '$username' created"
            unset EXPECT_PASSWORD
            return 0
        elif echo "$result" | grep -q "RETRY"; then
            local delay=5
            if [ $waited -ge 60 ]; then delay=10; fi
            waited=$((waited + delay))
            $log_fn "  DB not ready, waiting... (attempt $attempt, ${waited}/${max_wait}s)"
            sleep "$delay"
        else
            $log_fn "Error: Failed to create user '$username'"
            echo "$result" | tail -20 | while read -r line; do
                [ -n "$line" ] && $log_fn "  $line"
            done
            unset EXPECT_PASSWORD
            return 1
        fi
    done

    $log_fn "Error: DB was not ready after ${max_wait}s, could not create user '$username'"
    unset EXPECT_PASSWORD
    return 1
}

nessus_set_password() {
    local username="$1"
    local password="$2"
    local log_fn="${3:-echo}"
    local result

    result=$(printf '%s\n%s\n' "$password" "$password" \
        | /opt/nessus/sbin/nessuscli chpasswd "$username" 2>&1) || true

    if echo "$result" | grep -qi "Password changed"; then
        $log_fn "Password updated for '$username'"
        return 0
    fi

    if echo "$result" | grep -qi "Cannot use the same password"; then
        $log_fn "Password already matches .env (${username})"
        return 0
    fi

    $log_fn "Error: Failed to update password for '$username'"
    echo "$result" | tail -8 | while read -r line; do
        [ -n "$line" ] && $log_fn "  $line"
    done
    return 1
}

nessus_verify_api_login() {
    local user="$1"
    local pass="$2"
    local response token payload

    if command -v jq >/dev/null 2>&1; then
        payload=$(jq -n --arg username "$user" --arg password "$pass" \
            '{username: $username, password: $password}') || return 1
    else
        payload="{\"username\":\"${user}\",\"password\":\"${pass}\"}"
    fi

    response=$(curl -s -k --connect-timeout 5 --max-time 15 \
        -X POST "https://localhost:8834/session" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null) || return 1

    if command -v jq >/dev/null 2>&1; then
        token=$(echo "$response" | jq -r '.token // empty' 2>/dev/null)
    else
        token=$(echo "$response" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
    fi

    [ -n "$token" ] && [ "$token" != "null" ]
}

nessus_verify_api_login_retry() {
    local user="$1"
    local pass="$2"
    local attempts="${3:-6}"
    local delay="${4:-5}"
    local n=0

    while [ $n -lt "$attempts" ]; do
        if nessus_verify_api_login "$user" "$pass"; then
            return 0
        fi
        n=$((n + 1))
        [ "$n" -lt "$attempts" ] && sleep "$delay"
    done
    return 1
}

ensure_admin_user() {
    local log_fn="${1:-echo}"
    local user="${NESSUS_USERNAME:-admin}"
    local pass="${NESSUS_PASSWORD:-admin}"

    if ! nessus_user_exists "$user"; then
        if ! nessus_create_user "$user" "$pass" "y" "$log_fn"; then
            $log_fn "Warning: Could not create admin user"
            return 1
        fi
    elif ! nessus_verify_api_login_retry "$user" "$pass" 6 5; then
        $log_fn "Admin password differs from .env, syncing..."
        if ! nessus_set_password "$user" "$pass" "$log_fn"; then
            $log_fn "Warning: Could not sync admin password from .env"
            return 1
        fi
        if ! nessus_verify_api_login_retry "$user" "$pass" 6 5; then
            $log_fn "Warning: Admin password still does not match .env after sync"
            return 1
        fi
    else
        $log_fn "Admin credentials OK (${user})"
    fi

    export NESSUS_API_USERNAME="$user"
    export NESSUS_API_PASSWORD="$pass"
    return 0
}

ensure_api_credentials() {
    ensure_admin_user "$@"
}
