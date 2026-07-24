#!/bin/sh
set -eu

umask 077

backup_root=${DTVP_BACKUP_ROOT:-/backup}
state_root=${DTVP_BACKUP_STATE_ROOT:-/state}
dtvp_data_root=${DTVP_BACKUP_DTVP_DATA_ROOT:-/app/data}
status_path=${DTVP_BACKUP_STATUS_PATH:-data/backup_status.json}
lock_dir=${DTVP_BACKUP_LOCK_DIR:-/tmp/dtvp-compose-backup.lock}

require_absolute_directory() {
    variable_name=$1
    directory=$2
    case "$directory" in
        /*) ;;
        *)
            echo "$variable_name must be an absolute path." >&2
            exit 2
            ;;
    esac
    if [ ! -d "$directory" ]; then
        echo "$variable_name does not exist: $directory" >&2
        exit 2
    fi
}

require_absolute_directory DTVP_BACKUP_ROOT "$backup_root"
require_absolute_directory DTVP_BACKUP_STATE_ROOT "$state_root"
require_absolute_directory DTVP_BACKUP_DTVP_DATA_ROOT "$dtvp_data_root"

backup_root=$(CDPATH= cd -- "$backup_root" && pwd -P)
state_root=$(CDPATH= cd -- "$state_root" && pwd -P)
dtvp_data_root=$(CDPATH= cd -- "$dtvp_data_root" && pwd -P)

case "$backup_root/" in
    "$state_root/"*)
        echo "Backup root must not be inside the mounted state root." >&2
        exit 2
        ;;
esac

for state_directory in dtvp; do
    if [ ! -d "$state_root/$state_directory" ]; then
        echo "Required state directory is unavailable: $state_root/$state_directory" >&2
        exit 1
    fi
done

case "$status_path" in
    /*) ;;
    *) status_path="/app/$status_path" ;;
esac
status_directory=$(dirname -- "$status_path")
mkdir -p "$status_directory"
status_directory=$(CDPATH= cd -- "$status_directory" && pwd -P)
status_path="$status_directory/$(basename -- "$status_path")"
case "$status_path" in
    "$dtvp_data_root"/*) ;;
    *)
        echo "DTVP_BACKUP_STATUS_PATH must resolve inside $dtvp_data_root." >&2
        exit 2
        ;;
esac

if ! mkdir "$lock_dir" 2>/dev/null; then
    echo "Another DTVP Compose backup is already running." >&2
    exit 75
fi

paused_containers=""
cleanup() {
    for container_id in $paused_containers; do
        docker unpause "$container_id" >/dev/null 2>&1 || true
    done
    rmdir "$lock_dir" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

if [ ! -S /var/run/docker.sock ]; then
    echo "The Docker Engine socket is unavailable." >&2
    exit 1
fi

project_name=$(docker inspect \
    --format '{{ index .Config.Labels "com.docker.compose.project" }}' \
    "${HOSTNAME:?HOSTNAME is required}")
if [ -z "$project_name" ] || [ "$project_name" = "<no value>" ]; then
    echo "Unable to resolve the scheduler's Compose project." >&2
    exit 1
fi

for service in dtvp; do
    container_ids=$(docker ps \
        --filter "label=com.docker.compose.project=$project_name" \
        --filter "label=com.docker.compose.service=$service" \
        --format '{{.ID}}')
    for container_id in $container_ids; do
        if [ "$(docker inspect --format '{{.State.Paused}}' "$container_id")" = "false" ]; then
            docker pause "$container_id" >/dev/null
            paused_containers="$container_id $paused_containers"
        fi
    done
done

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
snapshot_dir="$backup_root/dtvp-state-$timestamp"
if [ -e "$snapshot_dir" ]; then
    echo "Backup destination already exists: $snapshot_dir" >&2
    exit 1
fi
mkdir -m 0700 "$snapshot_dir"

tar -czf "$snapshot_dir/persistent-files.tar.gz" \
    -C "$state_root" dtvp

gzip -t "$snapshot_dir/persistent-files.tar.gz"

(
    cd "$snapshot_dir"
    sha256sum persistent-files.tar.gz > SHA256SUMS
)

completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
status_tmp="${status_path}.tmp.$$"
if printf '{"schema":"dtvp.backup-status/v1","completed_at":"%s"}\n' \
    "$completed_at" > "$status_tmp" && chmod 0600 "$status_tmp"; then
    mv "$status_tmp" "$status_path"
else
    rm -f "$status_tmp"
    echo "Backup succeeded but the DTVP backup-status marker was not updated." >&2
    exit 1
fi

cleanup
paused_containers=""
trap - EXIT HUP INT TERM

echo "Verified backup created at $snapshot_dir"
echo "Replicate it to encrypted off-host storage and test restoration regularly."
