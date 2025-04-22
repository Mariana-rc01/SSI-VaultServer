import os, base64, json
from utils.utils import(
    GroupAddUserRequest,
    GroupAddUserRequirementsRequest,
    GroupAddUserRequirementsResponse,
    GroupCreateRequest,
    GroupMembersResponse,
    ListRequest,
    PublicKeyResponse,
    ReadResponse,
    VaultError,
    encrypt,
    decrypt,
    build_aesgcm,
    serialize_response,
    AddRequest,
    ReadRequest,
    GroupMembersRequest,
    PublicKeyRequest,
    ShareRequest,
    deserialize_request,
    deserialize_public_key,
    max_msg_size
)
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def addRequest(file_path: str, client_public_key) -> bytes:
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

def readRequest(file_id: str) -> bytes:
    read_request = ReadRequest(
        fileid=file_id,
    )
    return serialize_response(read_request)

def readResponse(decrypted_msg: bytes, client_private_key) -> None:
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
    list_request = ListRequest(
        list_type = list_type if list_type else None,
        target_id = target_id if target_id else "",
    )
    return serialize_response(list_request)

def listResponse(server_response: bytes) -> None:
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
    group_create_request = GroupCreateRequest(
        group_name=group_name,
    )
    return serialize_response(group_create_request)

async def groupAddUserRequest(group_id: str, user_id: str, permission: str, rsa_private_key, aesgcm, writer, reader) -> bytes:
    try:
        # 1º Requirements: encrypted_keys for each file shared with the group or owner, owner's public_key
        requirements = GroupAddUserRequirementsRequest(
            group_id = group_id,
            user_id = user_id,
        )
        writer.write(encrypt(serialize_response(requirements), aesgcm))
        await writer.drain()

        response = await reader.read(max_msg_size)
        decrypted_msg: bytes = decrypt(response, aesgcm)
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

async def shareRequest(file_id: str, target_id: str, permission: str, rsa_private_key, aesgcm, writer, reader) -> bytes:
    # 1º AES key for the file
    get_key_request = ReadRequest(file_id)
    writer.write(encrypt(serialize_response(get_key_request), aesgcm))
    await writer.drain()
    response = await reader.read(max_msg_size)

    decrypted_msg: bytes = decrypt(response, aesgcm)
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
        writer.write(encrypt(serialize_response(group_members_request), aesgcm))
        await writer.drain()
        response = await reader.read(max_msg_size)
        decrypted_response: bytes = decrypt(response, aesgcm)
        group_members_response = deserialize_request(decrypted_response)

        if isinstance(group_members_response, GroupMembersResponse):
            for member in group_members_response.members:
                publicKey_request = PublicKeyRequest(member["userid"])
                writer.write(encrypt(serialize_response(publicKey_request), aesgcm))
                await writer.drain()
                response = await reader.read(max_msg_size)
                decrypted_response: bytes = decrypt(response, aesgcm)
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
        writer.write(encrypt(serialize_response(publicKey_request), aesgcm))
        await writer.drain()
        response = await reader.read(max_msg_size)
        decrypted_response: bytes = decrypt(response, aesgcm)
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
