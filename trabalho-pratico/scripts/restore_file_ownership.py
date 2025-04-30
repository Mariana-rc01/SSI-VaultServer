import os

ORIGINAL_UID = 1000
ORIGINAL_GID = 1000

def restore_file_ownership():
    """
    Restaura a propriedade de todos os ficheiros em db/ e storage/
    para o utilizador original com UID e GID definidos.
    """
    paths_to_restore = [
        'db/logs.json',
        'db/notifications.json',
        'db/users.json',
        'db/files.json',
        'db/groups.json',
        'storage',
        'server'
    ]

    for path in paths_to_restore:
        if not os.path.exists(path):
            continue

        if os.path.isdir(path):
            # Restaura propriedade para o diretório e todo o conteúdo
            for root, dirs, files in os.walk(path):
                for name in dirs + files:
                    full_path = os.path.join(root, name)
                    os.chown(full_path, ORIGINAL_UID, ORIGINAL_GID)
            os.chown(path, ORIGINAL_UID, ORIGINAL_GID)
        else:
            # Restaura propriedade do ficheiro
            os.chown(path, ORIGINAL_UID, ORIGINAL_GID)

if __name__ == "__main__":
    restore_file_ownership()
