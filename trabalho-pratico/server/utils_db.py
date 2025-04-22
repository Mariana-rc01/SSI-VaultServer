import json
import os
from typing import Any, Dict, List


FILES_JSON = "./db/files.json"
LOGS_JSON = "./db/logs.json"
USERS_JSON = "./db/users.json"
GROUPS_JSON = "./db/groups.json"
STORAGE_DIR = "./storage"

def load_users() -> List[Dict[str, Any]]:
    """ Loads the users from the JSON file. """
    if os.path.exists(USERS_JSON):
        with open(USERS_JSON, "r") as f:
            return json.load(f)
    return []

def save_users(users: list) -> None:
    """Saves the users to the JSON file."""
    with open(USERS_JSON, 'w') as f:
        json.dump(users, f, indent=2)

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

def get_next_id(existing_items: list, prefix: str) -> str:
    """ Gets the next ID to avoid duplicates after deletions. """
    if not existing_items:
        return f"{prefix}1"

    # Extracts all numbers from existing IDs
    ids = [int(item['id'][1:]) for item in existing_items if item['id'].startswith(prefix)]

    if not ids:
        return f"{prefix}1"

    return f"{prefix}{max(ids) + 1}"

def get_next_file_id() -> str:
    """ Gets the next file ID. """
    files = load_files()
    return get_next_id(files, "f")

def get_next_group_id() -> str:
    """ Gets the next group ID. """
    groups = load_groups()
    return get_next_id(groups, "g")