import base64
import os
import json
from datetime import datetime
from typing import List, Dict, Optional, Any

from utils.utils import ShareRequest, serialize_public_key_rsa
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
        if user.get("username") == f"Owner: {user_id}" and "read" in user.get("permissions", []):
            return user.get("key")
        elif user.get("username") == user_id and "read" in user.get("permissions", []):
            return user.get("key")

    user_groups = get_user_groups(user_id)
    for group_permission in file_info.get("permissions", {}).get("groups", []):
        group_id = group_permission["groupname"]
        if group_id in user_groups and "read" in group_permission.get("permissions", []):
            for key_entry in group_permission.get("keys", []):
                if key_entry.get("username") == user_id:
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
                "username": f"Owner: {owner_id}",
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
                    if permission["groupname"] == f"Owner: {target_id}"), []
                )
            else:
                user_permissions = next(
                    (permission["permissions"] for permission in file.get("permissions", {}).get("users", [])
                    if permission["username"] == f"Owner: {target_id}"), []
                )
            result["personal"].append({
                "id": file["id"],
                "name": file["name"],
                "owner": file["owner"],
                "permissions": user_permissions,
            })

        for permission in file.get("permissions", {}).get("users", []):
            if permission["username"] == target_id:
                result["shared"].append({
                    "id": file["id"],
                    "name": file["name"],
                    "shared_by": file["owner"],
                    "permissions": permission.get("permissions", []),
                })
                break

        if list_type == "group":
            for group_permission in file.get("permissions", {}).get("groups", []):
                group_id = group_permission["groupname"]
                if group_id == target_id and group_permission["permissions"] != []:
                    result["shared"].append({
                        "id": file["id"],
                        "name": file["name"],
                        "group": group_id,
                        "permissions": group_permission["permissions"],
                    })
        else:
            for group_permission in file.get("permissions", {}).get("groups", []):
                group_id = group_permission["groupname"]
                if group_id in user_groups and group_permission["permissions"] != []:
                    result["group"].append({
                        "id": file["id"],
                        "name": file["name"],
                        "group": group_id,
                        "permissions": group_permission["permissions"],
                    })

    return result

def get_user_groups(user_id: str) -> list:
    """ Gets the groups of a user. """
    groups = load_groups()
    return [g["id"] for g in groups if user_id in g.get("members", [])]

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
                "username": user_id,
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

def share_file(file_info: dict, client_request: ShareRequest, user_id: str) -> Optional[str]:
    """ Shares a file with a user or group. """
    if file_info["owner"] != user_id:
        return "You are not the owner of this file."

    if client_request.is_group:
        if "groups" not in file_info["permissions"]:
            file_info["permissions"]["groups"] = []

        group_permission = next(
            (g for g in file_info["permissions"]["groups"] if g["groupname"] == client_request.target_id),
            None
        )

        if not group_permission:
            group_permission = {
                "groupname": client_request.target_id,
                "keys": [],
                "permissions": ["read"] if client_request.permissions == "R" else ["read", "write"]
            }
            file_info["permissions"]["groups"].append(group_permission)

        for user_id, encrypted_key in client_request.encrypted_keys.items():
            key_entry = next(
                (k for k in group_permission["keys"] if k["username"] == user_id),
                None
            )
            if key_entry:
                key_entry["key"] = encrypted_key
            else:
                group_permission["keys"].append({
                    "username": user_id,
                    "key": encrypted_key
                })
    else:
        if "users" not in file_info["permissions"]:
            file_info["permissions"]["users"] = []

        user_entry = next(
            (u for u in file_info["permissions"]["users"] if u["username"] == client_request.target_id),
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
                "username": client_request.target_id,
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
