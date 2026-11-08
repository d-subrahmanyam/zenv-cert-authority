#!/usr/bin/env bash
# Generates random secrets for the compose stacks into deploy/docker/secrets/ (gitignored).
# Existing files are kept, so re-running is safe; delete a file to rotate it (and recreate
# the volumes, since the CA keys and database roles were created with the old values).
set -euo pipefail
dir="$(cd "$(dirname "$0")" && pwd)/secrets"
mkdir -p "$dir"
chmod 700 "$dir"   # host-side protection; the files themselves must be readable in-container
for name in root_passphrase intermediate_passphrase db_superuser_password db_owner_password db_app_password; do
    f="$dir/$name"
    if [[ -s "$f" ]]; then
        echo "keep    $f"
    else
        # 32 random bytes, base64url without padding: 43 chars, no shell/URL-special chars.
        head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' > "$f"
        echo "created $f"
    fi
    # Read by non-root container users (zenv-ca: 65532, postgres: 999).
    chmod 644 "$f"
done
