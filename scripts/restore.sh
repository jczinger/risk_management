#!/usr/bin/env bash
#
# VMS restore — the other half of scripts/backup.sh.
#
# This is destructive: it drops and recreates the database. It asks for confirmation, and
# refuses to run without PLATFORM_MASTER_KEY present, because a restore without the key
# produces a system whose records cannot be read — which looks like a successful restore
# until someone opens a volunteer's file.
#
# Usage:
#   scripts/restore.sh 20260724T193000Z
#   VMS_BACKUP_DIR=/mnt/x scripts/restore.sh 20260724T193000Z
#   VMS_RESTORE_YES=1 scripts/restore.sh <stamp>     # skip the prompt (for drills)

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

BACKUP_DIR="${VMS_BACKUP_DIR:-$PROJECT_DIR/backups}"
COMPOSE="${VMS_COMPOSE:-docker compose}"
STAMP="${1:-}"

log()  { printf '[restore %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
fail() { printf '[restore] ERROR: %s\n' "$*" >&2; exit 1; }

trap 'fail "failed on line $LINENO"' ERR

if [[ -z "$STAMP" ]]; then
    echo "Usage: scripts/restore.sh <timestamp>"
    echo
    echo "Available backups in $BACKUP_DIR:"
    ls -1 "$BACKUP_DIR" 2>/dev/null || echo "  (none)"
    exit 1
fi

source_dir="$BACKUP_DIR/$STAMP"
[[ -d "$source_dir" ]] || fail "no backup at $source_dir"
[[ -f "$source_dir/database.dump" ]] || fail "no database.dump in $source_dir"
[[ -f .env ]] || fail "no .env in $PROJECT_DIR"

# --- The key check, before anything destructive ------------------------------
master_key="$(grep -E '^PLATFORM_MASTER_KEY=' .env | tail -1 | cut -d= -f2- || true)"
[[ -n "$master_key" ]] || fail \
    "PLATFORM_MASTER_KEY is not set in .env. Restoring without it would give you a
  system full of unreadable records. Retrieve it from Keeper Security first."

db_name="$(grep -E '^POSTGRES_DB=' .env | tail -1 | cut -d= -f2- || true)"
db_user="$(grep -E '^POSTGRES_USER=' .env | tail -1 | cut -d= -f2- || true)"
db_name="${db_name:-vms}"
db_user="${db_user:-vms}"

# --- Verify the archive before trusting it ----------------------------------
if [[ -f "$source_dir/SHA256SUMS" ]]; then
    log "verifying checksums"
    ( cd "$source_dir" && sha256sum --check --quiet SHA256SUMS ) \
        || fail "checksum mismatch — this archive is damaged."
    log "checksums OK"
else
    log "WARNING: no SHA256SUMS in this backup; skipping verification"
fi

echo
cat "$source_dir/MANIFEST.txt" 2>/dev/null || true
echo
echo "This will DROP and recreate the database '$db_name' on $(hostname)."
echo "Everything currently in it will be replaced by the backup above."
echo

if [[ "${VMS_RESTORE_YES:-}" != "1" ]]; then
    read -r -p "Type the database name to confirm: " confirm
    [[ "$confirm" == "$db_name" ]] || fail "not confirmed; nothing was changed."
fi

# --- Stop the app, leaving the database up -----------------------------------
log "stopping web, worker and beat"
$COMPOSE stop web worker beat >/dev/null 2>&1 || true

# --- Database ----------------------------------------------------------------
log "recreating the database"
$COMPOSE exec -T db psql --username "$db_user" --dbname postgres \
    --command "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$db_name' AND pid <> pg_backend_pid();" \
    >/dev/null
$COMPOSE exec -T db psql --username "$db_user" --dbname postgres \
    --command "DROP DATABASE IF EXISTS \"$db_name\";" >/dev/null
$COMPOSE exec -T db psql --username "$db_user" --dbname postgres \
    --command "CREATE DATABASE \"$db_name\" OWNER \"$db_user\";" >/dev/null

log "restoring the dump (this may take a while)"
$COMPOSE exec -T db pg_restore \
    --username "$db_user" \
    --dbname "$db_name" \
    --no-owner \
    --no-privileges \
    --exit-on-error \
    < "$source_dir/database.dump"

# --- Media ------------------------------------------------------------------
if [[ -f "$source_dir/media.tar.gz" ]] && [[ -s "$source_dir/media.tar.gz" ]]; then
    log "restoring the media volume"
    $COMPOSE run --rm --no-deps --entrypoint sh -T web \
        -c 'cd /app/media && tar xzf -' < "$source_dir/media.tar.gz"
else
    log "no media archive to restore"
fi

# --- Bring it back up and confirm the keys line up --------------------------
log "applying any newer migrations"
$COMPOSE run --rm --no-deps -T web python manage.py deploy_migrate

log "starting the application"
$COMPOSE up -d web worker beat >/dev/null

log "verifying that each church's key still unwraps"
$COMPOSE run --rm --no-deps -T web python manage.py verify_keys

log "restore complete"
echo
echo "Check now, before trusting it: sign in to one church and open a volunteer's record."
echo "If the personal details are readable, the master key matches and the restore is good."
