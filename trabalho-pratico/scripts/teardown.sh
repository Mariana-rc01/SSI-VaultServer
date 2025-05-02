#!/bin/bash
# teardown.sh -- remove the vault_server user and optionally project files

set -e  # exit on error

USER="vault_server"

echo "Starting teardown..."

# Get the user with UID 1000
PRIMARY_USER=$(getent passwd 1000 | cut -d: -f1)

# Remove user if exists
if id "$USER" &>/dev/null; then
    echo "  Removing user $USER..."

    # Try removing user from group of UID 1000 user
    if [ -n "$PRIMARY_USER" ]; then
        echo "  Removing $USER from group $PRIMARY_USER..."
        sudo gpasswd -d "$USER" "$PRIMARY_USER" || echo "  [Warning] Could not remove from group."
    fi

    sudo userdel -r "$USER" || echo "  [Warning] Could not completely remove $USER (maybe already removed or home in use)."
else
    echo "  User $USER does not exist. Skipping."
fi

echo "User removal complete."

# Ask if you also want to clean files belonging to the user
read -p "Do you also want to clean files from db/, storage/, and __pycache__? (y/n): " choice

if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    echo "Cleaning files..."

    # Remove JSONs and storage files
    sudo rm -f db/*.json
    sudo rm -rf storage/*

    # Remove __pycache__ folders and .pyc files (optional cleanup)
    find . -type d -name "__pycache__" -exec rm -rf {} +
    find . -type f -name "*.pyc" -exec rm -f {} +

    echo "Files cleaned."
else
    echo "Keeping files."
fi

echo "Teardown complete."
