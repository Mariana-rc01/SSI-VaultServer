#!/bin/bash
# setup.sh -- creates a single user called vault_server with a provided password

set -e  # exit if any command fails

# Check if a password was provided
if [ -z "$1" ]; then
    echo "Usage: $0 <password>"
    exit 1
fi

PASSWORD="$1"
USER="vault_server"

# Check if the user already exists
if id "$USER" &>/dev/null; then
    echo "User $USER already exists."
else
    echo "Creating user $USER..."
    sudo useradd -m -s /bin/bash "$USER"
    echo "$USER:$PASSWORD" | sudo chpasswd
    echo "User $USER has been created with the specified password."
fi

# Show uid and gid of the user
USER_ID=$(id -u "$USER")
GROUP_ID=$(id -g "$USER")
echo "User ID: $USER_ID"
echo "Group ID: $GROUP_ID"
echo "User setup complete."
