import os, base64, random, ssl
from utils.utils import *
from utils.data_structures import *
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from datetime import datetime

def prepare_tls_client_context(tls_option: str) -> tuple[str, list[str], ssl.SSLContext, bool, bytes, bytes, object]:
    """Prepares parameters for the client's TLS handshake"""
    client_random = os.urandom(32)

    # TLS 1.3
    dh_ciphers = ["TLS_AES_256_GCM_SHA384",
                  "TLS_AES_128_GCM_SHA256",
                  "TLS_CHACHA20_POLY1305_SHA256"]

    # TLS 1.2
    ecdh_ciphers = ["ECDHE-RSA-AES256-GCM-SHA384",
                    "ECDHE-RSA-AES128-GCM-SHA256",
                    "ECDHE-RSA-CHACHA20-POLY1305"]

    if tls_option == "TLSv1.3":
        selected_group = dh_ciphers
        use_ecdh = False
        client_version = "TLSv1.3"
    else:
        selected_group = ecdh_ciphers
        use_ecdh = True
        client_version = "TLSv1.2"

    random.shuffle(selected_group)
    context = ssl.create_default_context()
    if client_version == "TLSv1.2":
        context.set_ciphers(':'.join(selected_group))

    available_ciphers = context.get_ciphers()
    cipher_suites = [cipher["name"] for cipher in available_ciphers]

    return client_version, cipher_suites, use_ecdh, client_random

def menu() -> None:
    print("\nPlease choose a command:")
    print("- add <file-path>")
    print("- read <file-id>")
    print("- list [-u <user-id> | -g <group-id>]")
    print("- share <file-id> <target-id> --permission=[r|w]")
    print("- delete <file-id>")
    print("- replace <file-id> <file-path>")
    print("- details <file-id>")
    print("- revoke <file-id> <target-id>")
    print("- group create <group-name>")
    print("- group delete <group-id>")
    print("- group add-user <group-id> <user-id> --permission=[r|w]")
    print("- group list")
    print("- group add <group-id> <file-path>")
    print("- exit")

def addRequest(file_path: str, client_public_key) -> bytes:
    """Add a file request."""
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        return b""

    aes_key = os.urandom(32)

    aesgcm_file = build_aesgcm(aes_key)
    file_data: bytes = open(file_path, "rb").read()
    encrypted_file: bytes = encrypt(file_data, aesgcm_file)

    encrypted_aes_key = client_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    encrypted_file_b64: str = base64.b64encode(encrypted_file).decode()
    encrypted_aes_key_b64: str = base64.b64encode(encrypted_aes_key).decode()
    filename: str = os.path.basename(file_path)

    add_request = AddRequest(
        filename=filename,
        encrypted_file=encrypted_file_b64,
        encrypted_aes_key=encrypted_aes_key_b64,
    )

    return serialize_response(add_request)

def groupAddRequest(file_path: str, list_of_members_public_keys: list) -> bytes:
    """Add a file to a group request."""
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        return b""

    aes_key = os.urandom(32)

    aesgcm_file = build_aesgcm(aes_key)
    file_data: bytes = open(file_path, "rb").read()
    encrypted_file: bytes = encrypt(file_data, aesgcm_file)

    encrypted_file_b64: str = base64.b64encode(encrypted_file).decode()
    filename: str = os.path.basename(file_path)

    encrypted_keys = {}
    for public_key in list_of_members_public_keys:
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        encrypted_keys[public_key] = base64.b64encode(encrypted_aes_key).decode()

    add_request = AddRequest(
        filename=filename,
        encrypted_file=encrypted_file_b64,
        encrypted_aes_key=encrypted_keys,
    )

    return serialize_response(add_request)

def readRequest(file_id: str) -> bytes:
    """Read a file request."""
    read_request = ReadRequest(
        fileid=file_id,
    )
    return serialize_response(read_request)

def readResponse(decrypted_msg: bytes, client_private_key) -> None:
    """ Decrypts the file and prints its content. """
    if not decrypted_msg:
        print("Error: Decrypted message is empty.")
        return

    try:
        encrypted_aes_key_b64 = decrypted_msg.encrypted_key
        encrypted_file_b64 = decrypted_msg.filedata

        if not encrypted_aes_key_b64 or not encrypted_file_b64:
            print("Error: Missing encrypted AES key or file data.")
            return

        encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
        encrypted_file = base64.b64decode(encrypted_file_b64)

        aes_key = client_private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        aesgcm_file = build_aesgcm(aes_key)
        file_data: bytes = decrypt(encrypted_file, aesgcm_file)

        print("\nFile content:")
        print(file_data.decode("utf-8"))

    except Exception as e:
        print("\nError decrypting:", e)

def listRequest(list_type: str, target_id: str) -> bytes:
    """List files, shared files, or group files request."""
    list_request = ListRequest(
        list_type = list_type if list_type else None,
        target_id = target_id if target_id else "",
    )
    return serialize_response(list_request)

def listResponse(server_response: bytes) -> None:
    """Displays the list of files, shared files, and group files."""
    print("\n=== Files ===")
    for file in server_response.files:
        print(f"ID: {file['id']}, Name: {file['name']}, Owner: {file['owner']}, Permissions: {file['permissions']}")

    print("\n=== Shared Files ===")
    for file in server_response.shared:
        print(f"ID: {file['id']}, Name: {file['name']}, From: {file['shared_by']}, Permissions: {file['permissions']}")

    print("\n=== Groups Files ===")
    for file in server_response.group_files:
        print(f"ID: {file['id']}, Name: {file['name']}, Group: {file['group']}, Permissions: {file['permissions']}")


def groupCreateRequest(group_name: str) -> bytes:
    """Create a group request."""
    group_create_request = GroupCreateRequest(
        group_name=group_name,
    )
    return serialize_response(group_create_request)

async def groupAddUserRequest(group_id: str, user_id: str, permission: str, rsa_private_key, cipher, writer, reader) -> bytes:
    """Add a user to a group request."""
    try:
        # 1º Requirements: encrypted_keys for each file shared with the group or owner, owner's public_key
        requirements = GroupAddUserRequirementsRequest(
            group_id = group_id,
            user_id = user_id,
        )
        writer.write(encrypt(serialize_response(requirements), cipher))
        await writer.drain()

        response = await reader.read(max_msg_size)
        decrypted_msg: bytes = decrypt(response, cipher)
        requirements_response = deserialize_request(decrypted_msg)

        if isinstance(requirements_response, VaultError):
            raise ValueError(f"Erro do servidor: {requirements_response.error}")

        if not isinstance(requirements_response, GroupAddUserRequirementsResponse):
            raise ValueError("Invalid response type for GroupAddUserRequirementsRequest.")

        # 2º Encrypted keys for the user to add
        encrypted_keys = {}
        target_public_key = deserialize_public_key(base64.b64decode(requirements_response.public_key))
        for file_id, encrypted_key in requirements_response.encrypted_keys.items():
            aes_key = rsa_private_key.decrypt(
                base64.b64decode(encrypted_key),
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            encrypted_for_target = target_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            encrypted_keys[file_id] = base64.b64encode(encrypted_for_target).decode()

        # 3º GroupAddUserRequest
        group_add_user_request = GroupAddUserRequest(
            group_id = group_id,
            user_id = user_id,
            permission = permission,
            encrypted_keys = encrypted_keys
        )
        return serialize_response(group_add_user_request)
    except Exception as e:
        print("\nError in groupAddUserRequest:", e)
        return b""

async def shareRequest(file_id: str, target_id: str, permission: str, rsa_private_key, cipher, writer, reader) -> bytes:
    """Share a file with a user or group."""
    if permission not in ["R", "W"]:
        raise ValueError("Invalid permission")

    # 1º AES key for the file
    get_key_request = ReadRequest(file_id)
    writer.write(encrypt(serialize_response(get_key_request), cipher))
    await writer.drain()
    response = await reader.read(max_msg_size)

    decrypted_msg: bytes = decrypt(response, cipher)
    read_response: ReadResponse = deserialize_request(decrypted_msg)

    if not isinstance(read_response, ReadResponse):
        raise ValueError("Invalid response type for ReadRequest.")

    encrypted_aes_key = base64.b64decode(read_response.encrypted_key)
    aes_key = rsa_private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 2º Encrypted keys for the target
    encrypted_keys = {}
    is_group = target_id.startswith("g")

    if is_group:
        # Request group members
        group_members_request = GroupMembersRequest(target_id)
        writer.write(encrypt(serialize_response(group_members_request), cipher))
        await writer.drain()
        response = await reader.read(max_msg_size)
        decrypted_response: bytes = decrypt(response, cipher)
        group_members_response = deserialize_request(decrypted_response)

        if isinstance(group_members_response, GroupMembersResponse):
            for member in group_members_response.members:
                publicKey_request = PublicKeyRequest(member["userid"])
                writer.write(encrypt(serialize_response(publicKey_request), cipher))
                await writer.drain()
                response = await reader.read(max_msg_size)
                decrypted_response: bytes = decrypt(response, cipher)
                publicKey_response = deserialize_request(decrypted_response)
                if isinstance(publicKey_response, PublicKeyResponse):
                    target_public_key = deserialize_public_key(
                        base64.b64decode(publicKey_response.public_key)
                    )

                    encrypted_for_target = target_public_key.encrypt(
                        aes_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )

                    encrypted_keys[member["userid"]] = base64.b64encode(encrypted_for_target).decode()
    else:
        # Request public key for the target user
        publicKey_request = PublicKeyRequest(target_id)
        writer.write(encrypt(serialize_response(publicKey_request), cipher))
        await writer.drain()
        response = await reader.read(max_msg_size)
        decrypted_response: bytes = decrypt(response, cipher)
        publicKey_response: PublicKeyResponse = deserialize_request(decrypted_response)

        if isinstance(publicKey_response, PublicKeyResponse):
            target_public_key = deserialize_public_key(
                base64.b64decode(publicKey_response.public_key)
            )

            encrypted_for_target = target_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            encrypted_keys[target_id] = base64.b64encode(encrypted_for_target).decode()

    # 3º ShareRequest
    share_request = ShareRequest(
        fileid=file_id,
        target_id=target_id,
        permissions=permission,
        encrypted_keys=encrypted_keys,
        is_group=is_group,
    )

    return serialize_response(share_request)

async def groupAddRequest(file_path: str, group_id: str, cipher, writer, reader) -> bytes:
    """Add a file to a group request."""

    # 1º Get public keys for the group
    group_public_keys_request = GroupPublicKeysRequest(
        group_id = group_id
    )

    writer.write(encrypt(serialize_response(group_public_keys_request), cipher))
    await writer.drain()

    response = await reader.read(max_msg_size)
    decrypted_msg: bytes = decrypt(response, cipher)
    group_public_keys_response = deserialize_request(decrypted_msg)

    if not isinstance(group_public_keys_response, GroupPublicKeysResponse):
        raise ValueError("Invalid response type for GroupPublicKeysRequest.")

    if not group_public_keys_response.public_keys:
        raise ValueError("No public keys found for the group.")

    group_public_keys = {}
    for member in group_public_keys_response.public_keys:
        group_public_keys[member["userid"]] = deserialize_public_key(
            base64.b64decode(member["public_key"])
        )

    aes_key = os.urandom(32)

    # 2º Encrypted keys for the group
    encrypted_keys = {}
    for user_id, public_key in group_public_keys.items():
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        encrypted_keys[user_id] = base64.b64encode(encrypted_aes_key).decode()

    # 3º Encrypt the file with the AES key and get the filename
    aesgcm_file = build_aesgcm(aes_key)
    file_data: bytes = open(file_path, "rb").read()
    encrypted_file: bytes = encrypt(file_data, aesgcm_file)
    encrypted_file_b64: str = base64.b64encode(encrypted_file).decode()
    filename: str = os.path.basename(file_path)

    # 4º GroupAddRequest
    group_add_request = GroupAddRequest(
        group_id = group_id,
        filename = filename,
        encrypted_file = encrypted_file_b64,
        encrypted_aes_key = encrypted_keys
    )

    return serialize_response(group_add_request)

async def replaceRequest(file_id: str, file_path: str, rsa_private_key, cipher, writer, reader) -> bytes:
    """Replace a file request."""
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        return b""

    try:
        # 1º AES key for the file
        requeriments_request = ReplaceRequirementsRequest(file_id)
        writer.write(encrypt(serialize_response(requeriments_request), cipher))
        await writer.drain()

        response = await reader.read(max_msg_size)
        decrypted_msg: bytes = decrypt(response, cipher)
        requirements_response = deserialize_request(decrypted_msg)

        if not isinstance(requirements_response, ReplaceRequirementsResponse):
            return print("Invalid operation.")

        # 2º Decrypt AES key with RSA private key
        encrypted_aes_key = base64.b64decode(requirements_response.encrypted_key)
        aes_key = rsa_private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # 3º Encrypt the new file with the AES key
        aesgcm_file = build_aesgcm(aes_key)
        with open(file_path, "rb") as file:
            file_data: bytes = file.read()
        encrypted_file: bytes = encrypt(file_data, aesgcm_file)

        # 4º Send ReplaceRequest
        replace_request = ReplaceRequest(
            file_id = file_id,
            encrypted_file = base64.b64encode(encrypted_file).decode(),
        )
        return serialize_response(replace_request)
    except Exception as e:
        print(f"Replace error: {e}")
        return b""

def detailsResponse(file_details: DetailsResponse) -> None:
    """Displays the details of a file."""
    if not file_details:
        print("No details found")
        return

    print("\n=== File Details ===")
    print(f"File ID: {file_details.file_id}")
    print(f"File Name: {file_details.file_name}")
    print(f"File Size: {file_details.file_size} bytes")
    print(f"Owner: {file_details.owner}")
    if file_details.permissions and 'users' in file_details.permissions:
        print("Permissions:")
        for user in file_details.permissions['users']:
            user_id = user.get('userid', 'Unknown User')
            user_permissions = ', '.join(user.get('permissions', [])) or 'None'
            print(f"  - {user_id}: {user_permissions}")
    else:
        print("Permissions: None")
    created_at = datetime.strptime(file_details.created_at, "%Y-%m-%dT%H:%M:%S.%fZ")
    readable_date = created_at.strftime("%d-%m-%Y %H:%M:%S")
    print(f"Created At: {readable_date}\n")

def groupList(server_response: GroupListResponse) -> None:
    """Displays the list of groups."""
    if not server_response.groups:
        print("No groups found")
        return

    print("\n=== Groups ===")
    for group in server_response.groups:
        print(f"Group ID: {group['id']}")
        print(f"Permissions: {', '.join(group['permissions'] or 'None')}\n")
