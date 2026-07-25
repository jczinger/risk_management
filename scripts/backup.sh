#!/usr/bin/env bash
#
# VMS backup — Postgres dump plus the media volume.
#
# What this captures:
#   * A custom-format pg_dump of the whole database: the public registry and every church's
#     schema. Sensitive columns are ciphertext inside it, which is the point.
#   * A tar of the media volume: the encrypted document files.
#   * A manifest recording what was taken, and each church's key fingerprint.
#
# What this does NOT capture, deliberately:
#   * PLATFORM_MASTER_KEY. Storing the key beside the data it protects would undo the
#     encryption. Back it up separately, in Keeper Security. Restoring this archive onto a
#     host without that key yields a working system full of unreadable records.
#
# Usage:
#   scripts/backup.sh                 # write to ./backups
#   VMS_BACKUP_DIR=/mnt/x scripts/backup.sh
#   VMS_KEEP_DAYS=30 scripts/backup.sh
#
# Restore:  scripts/restore.sh <timestamp>

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

BACKUP_DIR="${VMS_BACKUP_DIR:-$PROJECT_DIR/backups}"
KEEP_DAYS="${VMS_KEEP_DAYS:-14}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
COMPOSE="${VMS_COMPOSE:-docker compose}"

log()  { printf '[backup %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
fail() { printf '[backup] ERROR: %s\n' "$*" >&2; exit 1; }

trap 'fail "failed on line $LINENO"' ERR

[[ -f .env ]] || fail "no .env in $PROJECT_DIR — run this from the deployment directory."

# Read DB settings from .env without importing the whole file into the shell.
db_name="$(grep -E '^POSTGRES_DB=' .env | tail -1 | cut -d= -f2- || true)"
db_user="$(grep -E '^POSTGRES_USER=' .env | tail -1 | cut -d= -f2- || true)"
db_name="${db_name:-vms}"
db_user="${db_user:-vms}"

mkdir -p "$BACKUP_DIR"
target="$BACKUP_DIR/$STAMP"
mkdir -p "$target"

log "backing up to $target"

# --- 1. Database ------------------------------------------------------------
#
# Custom format (-Fc): compressed, and restorable selectively with pg_restore.
log "dumping database '$db_name'"
$COMPOSE exec -T db pg_dump \
    --username "$db_user" \
    --dbname "$db_name" \
    --format=custom \
    --compress=6 \
    --no-owner \
    --no-privileges \
    > "$target/database.dump"

dump_size="$(stat -c %s "$target/database.dump")"
[[ "$dump_size" -gt 1024 ]] || fail "the dump is only ${dump_size} bytes — treating as failed."
log "database dump: $(numfmt --to=iec "$dump_size" 2>/dev/null || echo "${dump_size}B")"

# --- 2. Media volume (encrypted documents) ---------------------------------
log "archiving the media volume"
$COMPOSE run --rm --no-deps --entrypoint sh -T web \
    -c 'cd /app/media && tar czf - . 2>/dev/null || true' \
    > "$target/media.tar.gz"

media_size="$(stat -c %s "$target/media.tar.gz")"
log "media archive: $(numfmt --to=iec "$media_size" 2>/dev/null || echo "${media_size}B")"

# --- 3. Manifest ------------------------------------------------------------
#
# Key fingerprints, not keys. Lets a restore be checked against the escrow entries without
# putting any key material in the archive.
log "writing the manifest"
{
    echo "VMS backup manifest"
    echo "==================="
    echo "taken_at_utc:   $STAMP"
    echo "host:           $(hostname)"
    echo "database:       $db_name"
    echo "database_bytes: $dump_size"
    echo "media_bytes:    $media_size"
    echo
    echo "churches (schema | name | key fingerprint | documents mode):"
    $COMPOSE exec -T db psql --username "$db_user" --dbname "$db_name" \
        --tuples-only --no-align --field-separator=' | ' \
        --command "SELECT schema_name, name, dek_fingerprint, document_mode FROM public.tenants_tenant ORDER BY schema_name;" \
        2>/dev/null || echo "  (could not read the registry)"
    echo
    echo "IMPORTANT"
    echo "---------"
    echo "PLATFORM_MASTER_KEY is deliberately NOT in this archive. Without it, every"
    echo "encrypted field in this dump is unrecoverable. Confirm it is in Keeper Security"
    echo "before relying on this backup."
} > "$target/MANIFEST.txt"

# --- 4. Checksums -----------------------------------------------------------
( cd "$target" && sha256sum database.dump media.tar.gz > SHA256SUMS )
log "checksums written"

# --- 5. Prune ---------------------------------------------------------------
if [[ "$KEEP_DAYS" -gt 0 ]]; then
    log "pruning backups older than $KEEP_DAYS days"
    find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -mtime "+$KEEP_DAYS" \
        -exec rm -rf {} + 2>/dev/null || true
fi

log "done: $target"
echo
cat "$target/MANIFEST.txt"
