#!/bin/bash
# setup.sh -- creates the necessary users for the server isolation

set -e  # exit if any command fails

USERS=("vault_logger" "vault_admin" "vault_resources")

for user in "${USERS[@]}"; do
    if id "$user" &>/dev/null; then
        echo "User $user already exists."
    else
        echo "Creating user $user..."
        sudo useradd -r -s /usr/sbin/nologin "$user"
    fi
done

echo "All users have been created (or already existed)."
