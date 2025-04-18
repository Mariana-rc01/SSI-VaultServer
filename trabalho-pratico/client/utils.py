import os, base64, json
from utils.utils import(
    GroupCreateRequest,
    ListRequest,
    encrypt,
    decrypt,
    build_aesgcm,
    serialize_response,
    AddRequest,
    ReadRequest,
)
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12


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

def groupCreateRequest(group_name: str) -> bytes:
    group_create_request = GroupCreateRequest(
        group_name=group_name,
    )
    return serialize_response(group_create_request)
