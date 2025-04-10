import os, json
from datetime import datetime

FILES_JSON = "files.json"
LOGS_JSON = "logs.json"
STORAGE_DIR = "./storage"

def log_request(user_id, type, args, status, error=""):
    """ Logs the request made by the user. """
    logs = []
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

def load_files():
    """ Loads the files from the JSON file. """
    if os.path.exists(FILES_JSON):
        with open(FILES_JSON, "r") as f:
            return json.load(f)
    return []

def save_files(files):
    """ Saves the files to the JSON file. """
    with open(FILES_JSON, "w") as f:
        json.dump(files, f, indent=2)

def get_file_by_id(file_id):
    """ Gets the file by its ID. """
    files = load_files()
    for f in files:
        if f["id"] == file_id:
            return f
    return None

def get_next_file_id():
    """ Gets the next file ID. """
    files = load_files()
    return f"f{len(files)+1}"

def add_request(filename, filedata, id):
    file_id = get_next_file_id()
    file_path = os.path.join(STORAGE_DIR, file_id)

    with open(file_path, "wb") as f:
        f.write(filedata)

    # TODO - Permissions
    files = load_files()
    files.append({
        "id": file_id,
        "name": filename,
        "size": len(filedata),
        "owner": f"{id}",
        "created_at": datetime.now().isoformat() + "Z",
        "location": file_path,
    })

    save_files(files)
    log_request(f"{id}", "add", [file_id], "success")
    return file_id
