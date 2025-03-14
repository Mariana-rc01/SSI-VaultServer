import sys
import os
import secrets

def setup(num_bytes, filename):
    key = secrets.token_bytes(num_bytes)
    with open(filename, 'wb') as f:
        f.write(key)

def xor_bytes(data, key):
    return bytes(a ^ b for a, b in zip(data, key))

def enc(message_file, key_file):
    with open(message_file, 'rb') as mf, open(key_file, 'rb') as kf:
        message = mf.read()
        key = kf.read()
        if len(key) < len(message):
            raise ValueError("Key must be at least as long as the message")
        ciphertext = xor_bytes(message, key)
        with open(message_file + '.enc', 'wb') as cf:
            cf.write(ciphertext)

def dec(ciphertext_file, key_file):
    with open(ciphertext_file, 'rb') as cf, open(key_file, 'rb') as kf:
        ciphertext = cf.read()
        key = kf.read()
        if len(key) < len(ciphertext):
            raise ValueError("Key must be at least as long as the ciphertext")
        plaintext = xor_bytes(ciphertext, key)
        with open(ciphertext_file + '.dec', 'wb') as pf:
            pf.write(plaintext)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python otp.py <setup|enc|dec> <args>")
        sys.exit(1)

    command = sys.argv[1]
    if command == 'setup':
        num_bytes = int(sys.argv[2])
        filename = sys.argv[3]
        setup(num_bytes, filename)
    elif command == 'enc':
        message_file = sys.argv[2]
        key_file = sys.argv[3]
        enc(message_file, key_file)
    elif command == 'dec':
        ciphertext_file = sys.argv[2]
        key_file = sys.argv[3]
        dec(ciphertext_file, key_file)
    else:
        print("Unknown command")
        sys.exit(1)
