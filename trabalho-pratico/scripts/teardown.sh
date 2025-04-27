#!/bin/bash
# teardown.sh -- remove users and optionally project files

set -e  # exit on error

USERS=("vault_logger" "vault_admin" "vault_resources")

echo "Removing users..."

for user in "${USERS[@]}"; do
    if id "$user" &>/dev/null; then
        echo "  Removing $user..."
        sudo userdel -r "$user" || echo "  [Warning] Could not completely remove $user."
    else
        echo "  User $user does not exist. Skipping."
    fi
done

echo "Users removed."

# Ask if you also want to clean files belonging to the users
read -p "Do you also want to clean files from db/ and storage/? (y/n): " choice

if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    echo "Cleaning files..."
    sudo rm -rf db/*.json storage/*
    echo "Files cleaned."
else
    echo "Keeping files."
fi

echo "Teardown complete."
