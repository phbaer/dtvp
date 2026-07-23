#!/bin/sh
set -eu

interval_seconds=${DTVP_BACKUP_INTERVAL_SECONDS:-86400}
initial_delay_seconds=${DTVP_BACKUP_INITIAL_DELAY_SECONDS:-300}
retry_seconds=${DTVP_BACKUP_RETRY_SECONDS:-3600}
status_path=${DTVP_BACKUP_STATUS_PATH:-data/backup_status.json}
backup_command=${DTVP_BACKUP_COMMAND:-/usr/local/bin/dtvp-backup}
scheduler_once=${DTVP_BACKUP_SCHEDULER_ONCE:-false}

validate_integer() {
    variable_name=$1
    value=$2
    minimum=$3
    case "$value" in
        ''|*[!0-9]*)
            echo "$variable_name must be an integer." >&2
            exit 2
            ;;
    esac
    if [ "$value" -lt "$minimum" ]; then
        echo "$variable_name must be at least $minimum." >&2
        exit 2
    fi
}

validate_integer DTVP_BACKUP_INTERVAL_SECONDS "$interval_seconds" 300
validate_integer DTVP_BACKUP_INITIAL_DELAY_SECONDS "$initial_delay_seconds" 0
validate_integer DTVP_BACKUP_RETRY_SECONDS "$retry_seconds" 60

if [ ! -x "$backup_command" ]; then
    echo "Backup command is not executable: $backup_command" >&2
    exit 2
fi

case "$status_path" in
    /*) ;;
    *) status_path="/app/$status_path" ;;
esac

child_pid=""
stop_requested=false
forward_signal() {
    stop_requested=true
    if [ -n "$child_pid" ]; then
        kill -TERM "$child_pid" >/dev/null 2>&1 || true
    fi
}
trap forward_signal HUP INT TERM

run_child() {
    "$@" &
    child_pid=$!
    child_status=0
    wait "$child_pid" || child_status=$?
    child_pid=""
    if [ "$stop_requested" = true ]; then
        exit 143
    fi
    return "$child_status"
}

sleep_for() {
    duration=$1
    if [ "$duration" -gt 0 ]; then
        run_child sleep "$duration"
    fi
}

if [ "$scheduler_once" = true ]; then
    sleep_for "$initial_delay_seconds"
    run_child "$backup_command"
    exit $?
fi

echo "DTVP backup scheduler started with interval ${interval_seconds}s."
sleep_for "$initial_delay_seconds"

while :; do
    now=$(date +%s)
    if [ -f "$status_path" ]; then
        marker_time=$(stat -c %Y "$status_path" 2>/dev/null || echo 0)
        if [ "$marker_time" -le "$((now + 300))" ]; then
            age_seconds=$((now - marker_time))
            if [ "$age_seconds" -lt "$interval_seconds" ]; then
                sleep_for "$((interval_seconds - age_seconds))"
                continue
            fi
        fi
    fi

    if run_child "$backup_command"; then
        sleep_for "$interval_seconds"
    else
        status=$?
        echo "DTVP backup failed with status $status; retrying in ${retry_seconds}s." >&2
        sleep_for "$retry_seconds"
    fi
done
