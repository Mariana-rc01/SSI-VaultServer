import base64
import os
import json
from datetime import datetime
from typing import List, Dict, Optional, Any

from utils.utils import ReplaceRequest, ShareRequest, serialize_public_key_rsa
from server.utils_db import load_users, save_users, load_groups, save_groups, load_files, save_files, get_next_file_id, get_next_group_id

FILES_JSON = "./db/files.json"
LOGS_JSON = "./db/logs.json"
USERS_JSON = "./db/users.json"
GROUPS_JSON = "./db/groups.json"
STORAGE_DIR = "./storage"

def log_request(user_id: str, type: str, args: List[Any], status: str, error: str = "") -> None:
    """ Logs the request made by the user. """
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
    """ Gets the file by its ID. """
    files = load_files()
    for f in files:
        if f["id"] == file_id:
            return f
    return None

def get_user_key(file_info: Dict[str, Any], user_id: str) -> Optional[str]:
    """ Gets the encryption key for a user or group member with read permission. """
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
                if key_entry.get("userid") == user_id:
                    return key_entry.get("key")

    return None

def add_request(filename: str, filedata: bytes, owner_id: str, owner_public_key: Any) -> str:
    """ Adds a file request. """
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
    """ Adds a user to the database. """
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
    """ Gets the files for listing. """
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
    """ Gets the groups of a user from the users database. """
    users = load_users()
    user = next((u for u in users if u["id"] == user_id), None)
    if not user:
        return []
    return user.get("groups", [])

def get_user_permissions_by_group(user_id: str) -> list:
    """ Gets the permissions of a user in all groups. """
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
    """ Gets the public key of a user. """
    users = load_users()
    for user in users:
        if user["id"] == user_id:
            return user["public_key"]
    return None

def get_group_members(group_id: str) -> list:
    """ Gets the members of a group. """
    groups = load_groups()
    return next(
        (g["members"] for g in groups if g["id"] == group_id),
        []
    )

def add_group_request(group_name: str, user_id: str) -> str:
    """ Adds a group request. """
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
    """ Shares a file with a user or group. """
    if file_info["owner"] != user_id:
        return "You are not the owner of this file."

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
                if key_entry["userid"] == user_id:
                    return key_entry["key"]

    return None

def check_write_permission(file_info: Dict[str, Any], user_id: str) -> bool:
    """ Checks if a user has write permission for a file. """
    return get_user_write_key(file_info, user_id) is not None

def replace_file_requirements(client_request: ReplaceRequest, user_id: str) -> Optional[bytes]:
    """ Get the keys to replace a file """
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
    """ Replaces a file with new content. """
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
        return "File replaced successfully"
    except Exception as e:
        log_request(user_id, "replace", [client_request.file_id], "failed", str(e))
        return None

def add_user_to_group_requirements(requester_id: str, group_id: str) -> dict:
    """ Get the keys to add a user to a group """
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