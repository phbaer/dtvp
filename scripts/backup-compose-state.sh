#!/bin/sh
set -eu

umask 077

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 /absolute/path/to/backup-root" >&2
    exit 2
fi

case "$1" in
    /*) backup_root=$1 ;;
    *)
        echo "Backup root must be an absolute path." >&2
        exit 2
        ;;
esac

repository_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_dir"
mkdir -p "$backup_root"
backup_root=$(CDPATH= cd -- "$backup_root" && pwd -P)
data_root=$(CDPATH= cd -- "$repository_dir/data" && pwd -P)
case "$backup_root/" in
    "$data_root/"*)
        echo "Backup root must not be inside the DTVP data directory." >&2
        exit 2
        ;;
esac
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
snapshot_dir="$backup_root/dtvp-state-$timestamp"

if [ -e "$snapshot_dir" ]; then
    echo "Backup destination already exists: $snapshot_dir" >&2
    exit 1
fi
mkdir -m 0700 "$snapshot_dir"

running_services=$(docker compose ps --status running --services)

paused_services=""
resume_writers() {
    for service in $paused_services; do
        docker compose unpause "$service" >/dev/null 2>&1 || true
    done
}
trap resume_writers EXIT HUP INT TERM

for service in dtvp; do
    if printf '%s\n' "$running_services" | grep -Fx "$service" >/dev/null; then
        docker compose pause "$service" >/dev/null
        paused_services="$service $paused_services"
    fi
done

DTVP_BACKUP_PATH="$snapshot_dir" \
    docker compose --profile maintenance run --rm --no-deps dtvp-state-backup

gzip -t "$snapshot_dir/persistent-files.tar.gz"

(
    cd "$snapshot_dir"
    sha256sum persistent-files.tar.gz > SHA256SUMS
)

completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
status_path=${DTVP_BACKUP_STATUS_PATH:-data/backup_status.json}
status_tmp="${status_path}.tmp"
mkdir -p "$(dirname -- "$status_path")"
if printf '{"schema":"dtvp.backup-status/v1","completed_at":"%s"}\n' \
    "$completed_at" > "$status_tmp" && chmod 0600 "$status_tmp"; then
    mv "$status_tmp" "$status_path"
else
    rm -f "$status_tmp"
    echo "Warning: backup succeeded but the DTVP backup-status marker was not updated." >&2
fi

resume_writers
paused_services=""
trap - EXIT HUP INT TERM

echo "Verified backup created at $snapshot_dir"
echo "Store it encrypted and test restoration into an isolated environment."
