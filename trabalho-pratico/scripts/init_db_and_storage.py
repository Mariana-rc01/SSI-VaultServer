import os
import pwd

VAULT_USER = 'vault_server'

def init_db_and_storage():
    """
    Creates the JSON files and the storage folder (if they do not exist) and applies:
      - All resources are owned by vault_server
      - Files get mode 600
      - Folders (e.g., storage) get mode 700
    """
    try:
        pw = pwd.getpwnam(VAULT_USER)
    except KeyError:
        raise RuntimeError(f"OS user {VAULT_USER!r} does not exist")

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

    # Ensure db directory exists
    os.makedirs('db', exist_ok=True)

    # Create and set permissions for files
    for path in files:
        if not os.path.exists(path):
            open(path, 'w').close()
        os.chown(path, uid, gid)
        os.chmod(path, 0o600)

    # Create and set permissions for storage folder (recursively)
    for folder in folders:
        os.makedirs(folder, exist_ok=True)
        for root, dirs, files in os.walk(folder):
            for name in dirs + files:
                full_path = os.path.join(root, name)
                os.chown(full_path, uid, gid)
                os.chmod(full_path, 0o700)
        os.chown(folder, uid, gid)
        os.chmod(folder, 0o700)

if __name__ == "__main__":
    init_db_and_storage()
