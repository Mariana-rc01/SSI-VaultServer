import os, base64, json

from utils.utils import HARDCODED_AES_KEY, encrypt, decrypt, build_aesgcm, request

def add(file_path):
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        return b""

    file_data = open(file_path, "rb").read()

    # TODO - Change the hardcoded key
    aesgcm_file = build_aesgcm(HARDCODED_AES_KEY)
    encrypted_file = encrypt(file_data, aesgcm_file)
    encrypted_file_b64 = base64.b64encode(encrypted_file).decode()
    filename = os.path.basename(file_path)

    add_request = request("add", [filename, encrypted_file_b64])
    json_bytes = json.dumps(add_request).encode('utf-8')
    return json_bytes

def read(decrypted_msg):
    try:
        # TODO - Change the hardcoded key
        aesgcm_file = build_aesgcm(HARDCODED_AES_KEY)
        file_data = decrypt(decrypted_msg, aesgcm_file)
        print("\nFile content:")
        print(file_data.decode('utf-8'))
    except Exception as e:
        print("\nError decrypting:", e)
