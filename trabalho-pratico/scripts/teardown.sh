#!/bin/bash
# teardown.sh -- remove the vault_server user and optionally project files

set -e  # exit on error

USER="vault_server"

echo "Removing user..."

if id "$USER" &>/dev/null; then
    echo "  Removing $USER..."
    sudo userdel -r "$USER" || echo "  [Warning] Could not completely remove $USER."
else
    echo "  User $USER does not exist. Skipping."
fi

echo "User removal complete."

# Ask if you also want to clean files belonging to the user
read -p "Do you also want to clean files from db/ and storage/? (y/n): " choice

if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    echo "Cleaning files..."
    sudo rm -rf db/*.json storage/*
    echo "Files cleaned."
else
    echo "Keeping files."
fi

echo "Teardown complete."
