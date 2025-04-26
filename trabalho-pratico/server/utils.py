import random, base64, os, json
from utils.utils import *
from utils.data_structures import *
from server.utils_db import *
from server.notifications import add_notification

from typing import List, Dict, Optional, Any
from datetime import datetime

def negotiate_cipher(client_version: str, client_ciphers: list[str]) -> tuple[str, bool]:
    """Selects a common cipher between the client and the server and indicates if ECDH is used."""

    server_supported = [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256"
    ]

    common_ciphers = [c for c in client_ciphers if c in server_supported]

    if not common_ciphers:
        raise ValueError("No common ciphers available")

    selected_cipher = random.choice(common_ciphers)
    use_ecdh = client_version == "TLSv1.2"

    return selected_cipher, use_ecdh

def log_request(user_id: str, type: str, args: List[Any], status: str, error: str = "") -> None:
    """Logs the request made by the user."""
    logs: List[Dict[str, Any]] = []
    if os.path.exists(LOGS_JSON):
        with open(LOGS_JSON, "r") as f:
            logs = json.load(f)

    log_id = f"r{len(logs)+1}"
    logs.append({
        "id": log_id,
        "userid": user_id,
        "type": type,
        "args": args,
        "timestamp": datetime.now().isoformat() + "Z",
        "status": status,
        "error": error
    })

    with open(LOGS_JSON, "w") as f:
        json.dump(logs, f, indent=2)

def get_file_by_id(file_id: str) -> Optional[Dict[str, Any]]:
    """Gets the file by its ID."""
    files = load_files()
    for f in files:
        if f["id"] == file_id:
            return f
    return None

def get_user_key(file_info: Dict[str, Any], user_id: str) -> Optional[str]:
    """Gets the encryption key for a user or group member with read permission."""
    users = file_info.get("permissions", {}).get("users", [])
    for user in users:
        if user.get("userid") == f"Owner: {user_id}" and "read" in user.get("permissions", []):
            return user.get("key")
        elif user.get("userid") == user_id and "read" in user.get("permissions", []):
            return user.get("key")

    user_groups = get_user_groups(user_id)
    for group_permission in file_info.get("permissions", {}).get("groups", []):
        group_id = group_permission["groupid"]
        if group_id in user_groups and "read" in group_permission.get("permissions", []):
            for key_entry in group_permission.get("keys", []):
                if key_entry.get("userid") == user_id or key_entry.get("userid") == f"Owner: {user_id}":
                    return key_entry.get("key")

    return None

def add_request(filename: str, filedata: bytes, owner_id: str, owner_public_key: Any) -> str:
    """Adds a file request."""
    file_id = get_next_file_id()
    file_path = os.path.join(STORAGE_DIR, file_id)

    with open(file_path, "wb") as f:
        f.write(filedata)

    permissions = {
        "users": [
            {
                "userid": f"Owner: {owner_id}",
                "key": owner_public_key,
                "permissions": ["read", "write"]
            }
        ]
    }

    files = load_files()

    files.append({
        "id": file_id,
        "name": filename,
        "size": len(filedata),
        "owner": owner_id,
        "permissions": permissions,
        "created_at": datetime.now().isoformat() + "Z",
        "location": file_path,
    })

    save_files(files)

    log_request(owner_id, "add", [file_id], "success")

    return file_id

def add_user(client_subject: str, public_key: Any) -> Optional[str]:
    """Adds a user to the database."""
    users: List[Dict[str, Any]] = []
    if os.path.exists(USERS_JSON):
        with open(USERS_JSON, "r") as f:
            try:
                users = json.load(f)
            except json.JSONDecodeError as e:
                users = []

    user_id = f"u{len(users)+1}"
    for user in users:
        if user["username"] == client_subject:
            return user["id"]

    try:
        users.append({
            "id": user_id,
            "username": client_subject,
            "public_key": base64.b64encode(serialize_public_key_rsa(public_key)).decode(),
            "groups": []
        })
    except Exception as e:
        return None

    try:
        with open(USERS_JSON, "w") as f:
            json.dump(users, f, indent=2)
    except Exception as e:
        return None
    return user_id

def get_files_for_listing(list_type: str, target_id: str) -> dict:
    """Gets the files for listing."""
    all_files = load_files()
    user_groups = get_user_groups(target_id)

    result = {
        "personal": [],
        "shared": [],
        "group": [],
    }

    for file in all_files:
        if file["owner"] == target_id:
            if list_type == "group":
                user_permissions = next(
                    (permission["permissions"] for permission in file.get("permissions", {}).get("groups", [])
                    if permission["groupid"] == f"Owner: {target_id}"), []
                )
            else:
                user_permissions = next(
                    (permission["permissions"] for permission in file.get("permissions", {}).get("users", [])
                    if permission["userid"] == f"Owner: {target_id}"), []
                )
            result["personal"].append({
                "id": file["id"],
                "name": file["name"],
                "owner": file["owner"],
                "permissions": user_permissions,
            })

        for permission in file.get("permissions", {}).get("users", []):
            if permission["userid"] == target_id:
                result["shared"].append({
                    "id": file["id"],
                    "name": file["name"],
                    "shared_by": file["owner"],
                    "permissions": permission.get("permissions", []),
                })
                break

        if list_type == "group":
            for group_permission in file.get("permissions", {}).get("groups", []):
                group_id = group_permission["groupid"]
                if group_id == target_id and group_permission["permissions"] != []:
                    result["shared"].append({
                        "id": file["id"],
                        "name": file["name"],
                        "group": group_id,
                        "permissions": group_permission["permissions"],
                    })
        else:
            for group_permission in file.get("permissions", {}).get("groups", []):
                group_id = group_permission["groupid"]
                if group_id in user_groups and group_permission["permissions"] != []:
                    result["group"].append({
                        "id": file["id"],
                        "name": file["name"],
                        "group": group_id,
                        "permissions": group_permission["permissions"],
                    })

    return result

def get_user_groups(user_id: str) -> list:
    """Gets the groups of a user from the users database."""
    users = load_users()
    user = next((u for u in users if u["id"] == user_id), None)
    if not user:
        return []
    return user.get("groups", [])

def get_user_permissions_by_group(user_id: str) -> list:
    """Gets the permissions of a user in all groups."""
    groups = load_groups()
    user_groups = []

    for group in groups:
        member = next((m for m in group.get("members", []) if m["userid"] == user_id), None)

        if member:
            user_groups.append({
                "id": group["id"],
                "permissions": member.get("permissions", [])
            })

    return user_groups

def get_public_key(user_id: str) -> Optional[str]:
    """Gets the public key of a user."""
    users = load_users()
    for user in users:
        if user["id"] == user_id:
            return user["public_key"]
    return None

def get_group_members(group_id: str) -> list:
    """Gets the members of a group."""
    groups = load_groups()
    return next(
        (g["members"] for g in groups if g["id"] == group_id),
        []
    )

def group_delete(group_id: str, user_id: str) -> Optional[str]:
    """Deletes a group."""
    groups = load_groups()
    group = next((g for g in groups if g["id"] == group_id), None)

    if not group:
        return "Group not found"

    if group["owner"] != user_id:
        return "Only group owner can delete the group"

    groups.remove(group)
    save_groups(groups)

    users = load_users()
    for user in users:
        if group_id in user.get("groups", []):
            user["groups"].remove(group_id)

    save_users(users)

    files = load_files()
    for file in files:
        for group_perm in file.get("permissions", {}).get("groups", []):
            if group_perm["groupid"] == group_id:
                file["permissions"]["groups"].remove(group_perm)
                # Check if the file has no groups and no users, if not, it was from the group and can be deleted
                if not file["permissions"]["groups"] and not file["permissions"].get("users", []):
                    try:
                        os.remove(file["location"])
                    except Exception as e:
                        return f"Error deleting file: {str(e)}"
                    files.remove(file)
                break
    save_files(files)

    log_request(user_id, "group delete", [group_id], "success")

    return None

def add_group_request(group_name: str, user_id: str) -> str:
    """Adds a group request."""
    group_id = get_next_group_id()

    groups = load_groups()
    users = load_users()

    groups.append({
        "id": group_id,
        "name": group_name,
        "owner": user_id,
        "members": [
            {
                "userid": user_id,
                "permissions": ["read", "write"]
            }
        ]
    })

    save_groups(groups)

    for user in users:
        if user['id'] == user_id:
            if 'groups' not in user:
                user['groups'] = []
            user['groups'].append(group_id)
            break

    save_users(users)

    log_request(user_id, "group create", [group_id, group_name], "success")

    return group_id

def add_user_to_group(user_id: str, group_id: str, add_user_id: str, permission: str, encrypted_keys: dict) -> Optional[str]:
    """Adds a user to a group with specified permissions."""
    groups = load_groups()
    users = load_users()
    files = load_files()

    group = next((g for g in groups if g["id"] == group_id), None)

    if not group:
        return "Group not found"

    if group["owner"] != user_id:
        return "Only group owner can add users"

    if permission == "R":
        new_perms = ["read"]
    elif permission == "W":
        new_perms = ["read", "write"]
    else:
        return "Invalid permission"

    member_exists = False
    for member in group["members"]:
        if member["userid"] == add_user_id:
            member_exists = True
            for perm in new_perms:
                if perm not in member["permissions"]:
                    member["permissions"].append(perm)
            break

    if not member_exists:
        group["members"].append({
            "userid": add_user_id,
            "permissions": new_perms
        })

    user_found = False
    for user in users:
        if user["id"] == add_user_id:
            user_found = True
            user.setdefault("groups", [])
            if group_id not in user["groups"]:
                user["groups"].append(group_id)
            break

    if not user_found:
        return "User to add not found in system"

    for file in files:
        for group_perm in file["permissions"].get("groups", []):
            if group_perm["groupid"] == group_id:
                group_perm.setdefault("keys", [])

                key_entry = next(
                    (k for k in group_perm["keys"] if k["userid"] == add_user_id),
                    None
                )

                file_key = encrypted_keys.get(file["id"])

                if file_key:
                    if key_entry:
                        key_entry["key"] = file_key
                    else:
                        group_perm["keys"].append({
                            "userid": add_user_id,
                            "key": file_key
                        })

    save_groups(groups)
    save_users(users)
    save_files(files)

    return None

def share_file(file_info: dict, client_request: ShareRequest, user_id: str) -> Optional[str]:
    """Shares a file with a user or group."""
    if file_info["owner"] != user_id and file_info["permissions"].get("users", []):
        return "You are not the owner of this file or the file belongs to a group."

    if client_request.is_group:
        if "groups" not in file_info["permissions"]:
            file_info["permissions"]["groups"] = []

        group_permission = next(
            (g for g in file_info["permissions"]["groups"] if g["groupid"] == client_request.target_id),
            None
        )

        if not group_permission:
            group_permission = {
                "groupid": client_request.target_id,
                "keys": [],
                "permissions": ["read"] if client_request.permissions == "R" else ["read", "write"]
            }
            file_info["permissions"]["groups"].append(group_permission)

        for user_id, encrypted_key in client_request.encrypted_keys.items():
            key_entry = next(
                (k for k in group_permission["keys"] if k["userid"] == user_id),
                None
            )
            if key_entry:
                key_entry["key"] = encrypted_key
            else:
                group_permission["keys"].append({
                    "userid": user_id,
                    "key": encrypted_key
                })
    else:
        if "users" not in file_info["permissions"]:
            file_info["permissions"]["users"] = []

        user_entry = next(
            (u for u in file_info["permissions"]["users"] if u["userid"] == client_request.target_id),
            None
        )

        if user_entry:
            user_entry["key"] = client_request.encrypted_keys[client_request.target_id]
            new_perms = user_entry["permissions"]
            if client_request.permissions == "R":
                if "read" not in new_perms:
                    new_perms.append("read")
            elif client_request.permissions == "W":
                if "write" not in new_perms:
                    new_perms.append("write")
                if "read" not in new_perms:
                    new_perms.append("read")
            user_entry["permissions"] = new_perms
        else:
            new_perms = ["read"] if client_request.permissions == "R" else ["read", "write"]
            encrypted_key = client_request.encrypted_keys[client_request.target_id]
            file_info["permissions"]["users"].append({
                "userid": client_request.target_id,
                "key": encrypted_key,
                "permissions": new_perms
            })

    files = load_files()
    for f in files:
        if f["id"] == file_info["id"]:
            f.update(file_info)
            break
    save_files(files)

    return None

def group_add_request(client_request: GroupAddRequest, user_id: str) -> Optional[str]:
    """Handles group add request."""
    group_id = client_request.group_id
    group = next((g for g in load_groups() if g["id"] == group_id), None)
    if not group:
        return None

    # Check if the user is a member of the group with write permission
    user_groups = get_user_groups(user_id)
    if group_id not in user_groups:
        return None
    group_permissions = next(
        (g for g in group.get("members", []) if g["userid"] == user_id),
        None
    )
    if not group_permissions or "write" not in group_permissions.get("permissions", []):
        return None

    # Create the file
    file_id = get_next_file_id()
    file_path = os.path.join(STORAGE_DIR, file_id)
    with open(file_path, "wb") as f:
        f.write(base64.b64decode(client_request.encrypted_file))
    file_size = os.path.getsize(file_path)
    file_info = {
        "id": file_id,
        "name": client_request.filename,
        "size": file_size,
        "owner": user_id,
        "permissions": {
            "users": [],
            "groups": [
                {
                    "groupid": group_id,
                    "keys": [],
                    "permissions": ["read", "write"]
                }
            ]
        },
        "created_at": datetime.now().isoformat() + "Z",
        "location": file_path
    }

    for user_id_key, encrypted_key in client_request.encrypted_aes_key.items():
        key_entry = {
            "userid": f"Owner: {user_id_key}" if user_id_key == user_id else user_id_key,
            "key": encrypted_key
        }
        file_info["permissions"]["groups"][0]["keys"].append(key_entry)

    # Add the file to the database
    files = load_files()
    files.append(file_info)
    save_files(files)
    log_request(user_id, "group add", [file_id, client_request.filename], "success")
    members = get_group_members(group_id)
    for member in members:
        if member["userid"] != user_id and member["userid"] != group["owner"]:
            add_notification(member["userid"], f"File {file_id} added to your group {group_id}.")
    return file_id

def get_user_write_key(file_info: Dict[str, Any], user_id: str) -> Optional[str]:
    """Gets the encryption key for a user or group member with write permission."""
    # Check if the user is the owner
    if file_info["owner"] == user_id:
        owner_entry = next(
            (u for u in file_info["permissions"]["users"]
             if u["userid"] == f"Owner: {user_id}"),
            None
        )
        if owner_entry:
            return owner_entry["key"]

    # Check if the user has write permission
    for user_perm in file_info.get("permissions", {}).get("users", []):
        if user_perm["userid"] == user_id and "write" in user_perm.get("permissions", []):
            return user_perm["key"]

    # Check if the user is a member of a group with write permission
    user_groups = get_user_groups(user_id)
    for group_perm in file_info.get("permissions", {}).get("groups", []):
        if (group_perm["groupid"] in user_groups and
            "write" in group_perm.get("permissions", [])):
            for key_entry in group_perm.get("keys", []):
                if key_entry["userid"] == user_id or key_entry["userid"] == f"Owner: {user_id}":
                    return key_entry["key"]

    return None

def has_write_permission_in_group(user_id: str, group_id: str) -> bool:
    """Checks if a user has write permission in a specific group."""
    groups = load_groups()
    group = next((g for g in groups if g["id"] == group_id), None)
    if not group:
        return False

    member = next((m for m in group.get("members", []) if m["userid"] == user_id or m["userid"] == f"Owner: {user_id}"), None)
    if member and "write" in member.get("permissions", []):
        return True

    return False

def check_write_permission(file_info: Dict[str, Any], user_id: str) -> bool:
    """Checks if a user has write permission for a file."""
    if not file_info["permissions"].get("users", []):
        for group_perm in file_info.get("permissions", {}).get("groups", []):
            group_id = group_perm["groupid"]
            if has_write_permission_in_group(user_id, group_id):
                return True
            else:
                return False

    return get_user_write_key(file_info, user_id) is not None

def replace_file_requirements(client_request: ReplaceRequest, user_id: str) -> Optional[bytes]:
    """Get the keys to replace a file"""
    file_info = get_file_by_id(client_request.file_id)
    if not file_info:
        log_request(user_id, "replace", [client_request.file_id], "failed", "File not found")
        return None

    if not check_write_permission(file_info, user_id):
        log_request(user_id, "replace", [client_request.file_id], "failed", "No write permission")
        return None

    encrypted_key = get_user_write_key(file_info, user_id)
    if not encrypted_key:
        log_request(user_id, "replace", [client_request.file_id], "failed", "No encryption key found")
        return None

    return encrypted_key

def replace_file(client_request: ReplaceRequest, user_id: str) -> Optional[bytes]:
    """Replaces a file with new content."""
    file_info = get_file_by_id(client_request.file_id)
    if not file_info:
        log_request(user_id, "replace", [client_request.file_id], "failed", "File not found")

    if not check_write_permission(file_info, user_id):
        log_request(user_id, "replace", [client_request.file_id], "failed", "No write permission")
        return None

    try:
        new_content = base64.b64decode(client_request.encrypted_file)
        with open(file_info["location"], "wb") as f:
            f.write(new_content)

        files = load_files()
        for f in files:
            if f["id"] == client_request.file_id:
                f["size"] = len(new_content)
        save_files(files)

        log_request(user_id, "replace", [client_request.file_id], "success")

        if file_info["owner"] != user_id:
            add_notification(file_info["owner"], f"User {user_id} replaced the content of the file {client_request.file_id}.")
        return "File replaced successfully"
    except Exception as e:
        log_request(user_id, "replace", [client_request.file_id], "failed", str(e))
        return None

def revoke_file_access(client_request: RevokeRequest, client_id: str) -> Optional[str]:
    """Revokes access to a file for a user or group."""

    if client_request.target_id == client_id:
        return

    file_info = get_file_by_id(client_request.file_id)
    if not file_info:
        return

    if file_info["owner"] != client_id:
        return

    permissions = file_info.get("permissions", {})
    if "g" in client_request.target_id:
        group_permissions = permissions.get("groups", [])
        for group_perm in group_permissions:
            if group_perm["groupid"] == client_request.target_id:
                group_permissions.remove(group_perm)
                break
    else:
        user_permissions = permissions.get("users", [])
        for user_perm in user_permissions:
            if user_perm["userid"] == client_request.target_id:
                user_permissions.remove(user_perm)
                break
    file_info["permissions"] = permissions
    files = load_files()
    for f in files:
        if f["id"] == file_info["id"]:
            f.update(file_info)
            break
    save_files(files)
    log_request(client_request.target_id, "revoke", [client_request.file_id], "success")

    return "Access revoked successfully"

def delete_file(file_id: str, user_id: str) -> Optional[str]:
    """Handles file deletion and access revocation following the new rules"""
    files = load_files()
    file_info = next((f for f in files if f["id"] == file_id), None)

    if not file_info:
        return "File not found"

    file_owner = file_info["owner"]
    file_permissions = file_info.get("permissions", {})
    groups = load_groups()

    # 1st check if the user is the owner of the file
    if file_owner == user_id:
        try:
            os.remove(file_info["location"])
        except Exception as e:
            return f"Error deleting file: {str(e)}"

        new_files = [f for f in files if f["id"] != file_id]
        save_files(new_files)
        log_request(user_id, "delete", [file_id], "success", "")
        return "User has no access to this file"

    # 2nd Group owner with owner as "Owner: user_id" in the group
    for group_perm in file_permissions.get("groups", []):
        group = next((g for g in groups if g["id"] == group_perm["groupid"]), None)

        if group and group["owner"] == user_id:
            member_ids_in_file = [k["userid"] for k in group_perm.get("keys", [])]

            # Search for "Owner: <file_owner>" explicitly
            if f"Owner: {file_owner}" in member_ids_in_file:
                try:
                    os.remove(file_info["location"])
                    files = [f for f in files if f["id"] != file_id]
                    save_files(files)
                    log_request(user_id, "delete", [file_id], "success", "")
                    return "User has no access to this file"
                except Exception as e:
                    return f"Error deleting file: {str(e)}"

    # 3rd Group owner with owner not in the group
    modified = False
    new_groups = []

    for group_perm in file_permissions.get("groups", []):
        group = next((g for g in groups if g["id"] == group_perm["groupid"]), None)

        if group and group["owner"] == user_id:
            members = [m["userid"] for m in group.get("members", [])]
            if file_owner not in members:
                modified = True
            else:
                new_groups.append(group_perm)
        else:
            new_groups.append(group_perm)

    if modified:
        file_info["permissions"]["groups"] = new_groups
        files = [f if f["id"] != file_id else file_info for f in files]
        save_files(files)
        log_request(user_id, "delete", [file_id], "success", "")

    # 4th Remove all references to the user
    had_access = False

    # Remove the user from the users permissions
    original_users = file_permissions.get("users", [])
    new_users = [u for u in original_users if u["userid"] != user_id]
    if len(new_users) < len(original_users):
        had_access = True
    file_permissions["users"] = new_users

    # Remove the user from the group permissions
    for group_perm in file_permissions.get("groups", []):
        original_keys = group_perm.get("keys", [])
        new_keys = [k for k in original_keys if k["userid"] != user_id]
        if len(new_keys) < len(original_keys):
            had_access = True
            group_perm["keys"] = new_keys

    if had_access:
        files = [f if f["id"] != file_id else file_info for f in files]
        save_files(files)
        log_request(user_id, "delete", [file_id], "success", "User access revoked")
        return "User has no access to this file"

    return "User has no access to this file"

def add_user_to_group_requirements(requester_id: str, group_id: str) -> dict:
    """Get the keys to add a user to a group"""
    groups = load_groups()
    group = next((g for g in groups if g["id"] == group_id), None)
    if not group:
        return {"error": "Group not found"}

    if group["owner"] != requester_id:
        return {"error": "Only group owner can add users"}

    files = load_files()
    encrypted_keys = {}

    for file in files:
        for group_perm in file.get("permissions", {}).get("groups", []):
            if group_perm["groupid"] == group_id:
                for key_entry in group_perm.get("keys", []):
                    if key_entry["userid"] == requester_id:
                        encrypted_keys[file["id"]] = key_entry["key"]
                        break

    return encrypted_keys