#!/bin/bash
# setup.sh -- creates a user called vault_server with a provided password,
# adds them to the primary group of the user with UID 1000,
# and installs cryptography as that user.

set -e  # exit if any command fails

# Check if a password was provided
if [ -z "$1" ]; then
    echo "Usage: $0 <password>"
    exit 1
fi

PASSWORD="$1"
USER="vault_server"

# Find the username with UID 1000
PRIMARY_USER=$(getent passwd 1000 | cut -d: -f1)
if [ -z "$PRIMARY_USER" ]; then
    echo "No user with UID 1000 found."
    exit 1
fi

echo "Primary user with UID 1000: $PRIMARY_USER"

# Check if the user already exists
if id "$USER" &>/dev/null; then
    echo "User $USER already exists."
else
    echo "Creating user $USER..."
    sudo useradd -m -s /bin/bash "$USER"
    echo "$USER:$PASSWORD" | sudo chpasswd
    echo "User $USER has been created with the specified password."
fi

# Add vault_server to the group of the UID 1000 user
sudo usermod -aG "$PRIMARY_USER" "$USER"
echo "User $USER added to group $PRIMARY_USER."

# Run pip install as vault_server using a subshell
echo "Installing cryptography as $USER..."
sudo -u "$USER" -H bash -c 'pip3 install --user --upgrade cryptography'

# Optional: confirm install location
sudo -u "$USER" -H bash -c 'python3 -m pip show cryptography'

echo "Setup complete."
