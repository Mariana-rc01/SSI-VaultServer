import os
import pwd

USER_MAP = {
    'logger':       'vault_logger',
    'admin':        'vault_admin',
    'resources':    'vault_resources',
}

def init_db_and_storage():
    """
    Creates the JSON files and the storage folder (if they do not exist) and applies:
      - logger  → db/logs.json, db/notifications.json  (owner=vault_logger, mode=600)
      - admin   → db/users.json, db/files.json, db/groups.json (owner=vault_admin, mode=600)
      - resources → storage/ and recursively (owner=vault_resources, mode=700)
    """
    # Define what belongs to each type
    TASKS = {
        'logger': {
            'paths': ['db/logs.json', 'db/notifications.json'],
            'mode': 0o600
        },
        'admin': {
            'paths': ['db/users.json', 'db/files.json', 'db/groups.json'],
            'mode': 0o600
        },
        'resources': {
            'paths': ['storage'],
            'mode': 0o700,
            'recursive': True
        }
    }

    for utype, info in TASKS.items():
        username = USER_MAP[utype]
        try:
            pw = pwd.getpwnam(username)
        except KeyError:
            raise RuntimeError(f"OS user {username!r} does not exist")
        uid, gid = pw.pw_uid, pw.pw_gid

        for path in info['paths']:
            # If it does not exist, create (file or folder)
            if not os.path.exists(path):
                if info.get('recursive'):
                    os.makedirs(path, exist_ok=True)
                else:
                    open(path, 'w').close()

            # Change owner and permissions
            os.chown(path, uid, gid)
            os.chmod(path, info['mode'])

            # If recursive (storage), iterate through all
            if info.get('recursive') and os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for name in dirs + files:
                        full = os.path.join(root, name)
                        os.chown(full, uid, gid)
                        os.chmod(full, info['mode'])

if __name__ == "__main__":
    init_db_and_storage()
