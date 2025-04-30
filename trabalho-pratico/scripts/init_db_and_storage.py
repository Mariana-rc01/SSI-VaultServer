import os
import pwd

VAULT_USER = 'vault_server'

def init_db_and_storage():
    """
    Cria os ficheiros JSON e a pasta storage (se ainda não existirem), com:
      - Propriedade atribuída ao utilizador vault_server
      - Ficheiros: modo 600 (ou 644 se necessário)
      - Ficheiros .py em 'server/': modo 755 (executável)
      - Pastas: modo 700
    """
    try:
        pw = pwd.getpwnam(VAULT_USER)
    except KeyError:
        raise RuntimeError(f"Utilizador do sistema '{VAULT_USER}' não existe")

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

    # Garantir que a pasta db existe
    os.makedirs('db', exist_ok=True)

    # Criar ficheiros e aplicar permissões
    for path in files:
        if not os.path.exists(path):
            open(path, 'w').close()
        os.chown(path, uid, gid)
        os.chmod(path, 0o600)

    # Criar pastas e aplicar permissões recursivamente
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
                    os.chmod(full_path, 0o755)  # Executável
                elif folder == 'storage':
                    os.chmod(full_path, 0o600)  # Ficheiros internos
                else:
                    os.chmod(full_path, 0o644)  # Código de leitura

        os.chown(folder, uid, gid)
        os.chmod(folder, 0o700)

if __name__ == "__main__":
    init_db_and_storage()
