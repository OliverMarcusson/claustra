#!/usr/bin/env bash
set -euo pipefail
umask 077

backup_dir=${CLAUSTRA_BACKUP_DIR:?CLAUSTRA_BACKUP_DIR is required}
database_url=${CLAUSTRA_BACKUP_DATABASE_URL:?CLAUSTRA_BACKUP_DATABASE_URL is required}
age_recipient=${CLAUSTRA_BACKUP_AGE_RECIPIENT:?CLAUSTRA_BACKUP_AGE_RECIPIENT is required}
signing_key=${CLAUSTRA_SIGNING_KEY_FILE:?CLAUSTRA_SIGNING_KEY_FILE is required}

case "$backup_dir" in ""|/|.|..) echo "refusing unsafe backup directory" >&2; exit 64;; esac
mkdir -p -- "$backup_dir"
work_dir=$(mktemp -d)
partial="$backup_dir/.claustra-backup-$$.part"
cleanup(){ rm -rf -- "$work_dir"; rm -f -- "$partial"; }
trap cleanup EXIT

pg_dump --dbname="$database_url" --format=custom --file="$work_dir/postgres.dump"
install -m 0600 -- "$signing_key" "$work_dir/signing-key.pem"

if [[ -n ${CLAUSTRA_PREVIOUS_SIGNING_KEY_FILES:-} ]]; then
  mkdir "$work_dir/previous-signing-keys"
  IFS=',' read -ra previous_keys <<< "$CLAUSTRA_PREVIOUS_SIGNING_KEY_FILES"
  for key in "${previous_keys[@]}"; do
    key=${key//[[:space:]]/}
    [[ -n "$key" ]] && install -m 0600 -- "$key" "$work_dir/previous-signing-keys/$(basename "$key")"
  done
fi

if [[ -n ${CLAUSTRA_CONFIG_FILE:-} && -r $CLAUSTRA_CONFIG_FILE ]]; then
  install -m 0600 -- "$CLAUSTRA_CONFIG_FILE" "$work_dir/claustra.env"
fi

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
tar -C "$work_dir" -cf - . | age --recipient "$age_recipient" --output "$partial"
mv -- "$partial" "$backup_dir/claustra-$timestamp.tar.age"

mapfile -t backups < <(find "$backup_dir" -maxdepth 1 -type f -name 'claustra-*.tar.age' -printf '%T@ %p\n' | sort -rn | cut -d' ' -f2-)
for ((i=7; i<${#backups[@]}; i++)); do rm -f -- "${backups[$i]}"; done
