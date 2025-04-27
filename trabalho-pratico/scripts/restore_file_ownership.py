import os

ORIGINAL_UID = 1000
ORIGINAL_GID = 1000

def restore_file_ownership():
    """
    Restores the ownership of all files in db/ and storage/ to the original user who started the server.
    """
    paths_to_restore = [
        'db/logs.json',
        'db/notifications.json',
        'db/users.json',
        'db/files.json',
        'db/groups.json',
        'storage',
    ]

    for path in paths_to_restore:
        if not os.path.exists(path):
            continue

        if os.path.isdir(path):
            # If it's a directory, restore ownership for all files inside
            for root, dirs, files in os.walk(path):
                for name in dirs + files:
                    full_path = os.path.join(root, name)
                    os.chown(full_path, ORIGINAL_UID, ORIGINAL_GID)
            os.chown(path, ORIGINAL_UID, ORIGINAL_GID)
        else:
            # If it's a file
            os.chown(path, ORIGINAL_UID, ORIGINAL_GID)

if __name__ == "__main__":
    restore_file_ownership()
