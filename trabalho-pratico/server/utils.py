import base64
import os
import json
from datetime import datetime
from typing import List, Dict, Optional, Any

from utils.utils import serialize_public_key_rsa

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

def load_files() -> List[Dict[str, Any]]:
    """ Loads the files from the JSON file. """
    if os.path.exists(FILES_JSON):
        with open(FILES_JSON, "r") as f:
            return json.load(f)
    return []

def save_files(files: List[Dict[str, Any]]) -> None:
    """ Saves the files to the JSON file. """
    with open(FILES_JSON, "w") as f:
        json.dump(files, f, indent=2)

def get_file_by_id(file_id: str) -> Optional[Dict[str, Any]]:
    """ Gets the file by its ID. """
    files = load_files()
    for f in files:
        if f["id"] == file_id:
            return f
    return None

def get_user_key(file_info: Dict[str, Any], user_id: str) -> Optional[str]:
    """ Gets the file by its ID. """
    users = file_info.get("permissions", {}).get("users", [])
    for user in users:
        if user.get("username") == f"Owner: {user_id}":
            return user.get("key")
    return None

def get_next_file_id() -> str:
    """ Gets the next file ID. """
    files = load_files()
    return f"f{len(files)+1}"

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

def get_next_group_id() -> str:
    """ Gets the next group ID. """
    groups = load_groups()
    return f"f{len(groups)+1}"

def load_groups() -> List[Dict[str, Any]]:
    """ Loads the groups from the JSON file. """
    if os.path.exists(GROUPS_JSON):
        with open(GROUPS_JSON, "r") as f:
            return json.load(f)
    return []

def save_groups(groups: List[Dict[str, Any]]) -> None:
    """ Saves the groups to the JSON file. """
    with open(GROUPS_JSON, "w") as f:
        json.dump(groups, f, indent=2)

def add_group_request(group_name: str) -> str:
    """ Adds a group request. """
    group_id = get_next_group_id()

    groups = load_groups()

    groups.append({
        "id": group_id,
        "name": group_name,
        "members": [],
    })

    save_groups(groups)

    log_request(group_id, "group_create", [group_name], "success")

    return group_id
