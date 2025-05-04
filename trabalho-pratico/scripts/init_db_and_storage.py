import os
import pwd

VAULT_USER = 'vault_server'

def init_db_and_storage():
    """
    Creates JSON files and the storage folder (if they do not already exist), with:
      - Ownership assigned to the vault_server user
      - Files: mode 600 (or 644 if necessary)
      - .py files in 'server/': mode 755 (executable)
      - Folders: mode 700
    """
    try:
        pw = pwd.getpwnam(VAULT_USER)
    except KeyError:
        raise RuntimeError(f"System user '{VAULT_USER}' does not exist")

    uid, gid = pw.pw_uid, pw.pw_gid

    files = [
        'db/logs.json',
        'db/notifications.json',
        'db/users.json',
        'db/files.json',
        'db/groups.json'
    ]
    folders = [
        'storage',
        'server'
    ]

    # Ensure the 'db' folder exists
    os.makedirs('db', exist_ok=True)

    # Create files and apply permissions
    for path in files:
        if not os.path.exists(path):
            open(path, 'w').close()
        os.chown(path, uid, gid)
        os.chmod(path, 0o600)

    # Create folders and apply permissions recursively
    for folder in folders:
        os.makedirs(folder, exist_ok=True)
        for root, dirs, files in os.walk(folder):
            for d in dirs:
                full_path = os.path.join(root, d)
                os.chown(full_path, uid, gid)
                os.chmod(full_path, 0o700)
            for f in files:
                full_path = os.path.join(root, f)
                os.chown(full_path, uid, gid)

                if folder == 'server' and f.endswith('.py'):
                    os.chmod(full_path, 0o755)  # Executable
                elif folder == 'storage':
                    os.chmod(full_path, 0o600)  # Internal files
                else:
                    os.chmod(full_path, 0o644)  # Readable code

        os.chown(folder, uid, gid)
        os.chmod(folder, 0o700)

if __name__ == "__main__":
    init_db_and_storage()
