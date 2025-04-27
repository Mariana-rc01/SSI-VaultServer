import os
import pwd
import sys

USER_MAP = {
    'logger':       'vault_logger',
    'admin':        'vault_admin',
    'resources':    'vault_resources',
}

def switch_to(user_type: str):
    """
    Changes the process's euid to the user associated with user_type.
    user_type must be one of the keys in USER_MAP: 'logger', 'admin', or 'resources'.
    """
    username = USER_MAP.get(user_type)
    if not username:
        raise ValueError(f"Invalid user_type: {user_type!r}")
    try:
        uid = pwd.getpwnam(username).pw_uid
    except KeyError:
        raise RuntimeError(f"OS user {username!r} does not exist")
    os.seteuid(uid)

def check_capabilities():
    """
    Checks if the current process can perform seteuid (i.e., has cap_setuid or is root).
    If not, displays a friendly error message and exits.
    """
    if os.geteuid() == 0:
        # If already root, it's ok
        return

    try:
        # Check if we have the cap_setuid capability
        with open(f"/proc/{os.getpid()}/status", "r") as f:
            content = f.read()
        # Look for the CapEff line (effective capabilities) and check if the setuid bit is active
        for line in content.splitlines():
            if line.startswith("CapEff:"):
                capeff = int(line.split()[1], 16)  # hexadecimal to integer
                # Bit 7 is CAP_SETUID (position 7 = 1 << 7 = 128)
                if not (capeff & (1 << 7)):
                    raise PermissionError
                return
        # If we don't find the CapEff line, assume we don't have the capability
        raise PermissionError
    except Exception:
        print("\n[ERROR] This process does not have sufficient permissions to switch users (seteuid).\n")
        print("Quick solution:")
        print("  sudo setcap cap_setuid+ep $(which python3)")
        print("\nThen run the server normally: python3 -m server.server\n")
        sys.exit(1)
