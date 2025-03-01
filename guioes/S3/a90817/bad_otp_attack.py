import sys
from bad_otp import *

def generateBytesB1(nBytes, filenameBytes):
    bytes = bad_prng(nBytes)
    with open(filenameBytes, 'wb') as f:
        f.write(bytes)

def try_all_seeds(ciphertext, words):
    for seed in range(1, 65536): # 2^16
        for seed1 in range(1, 65536):
            random.seed(seed)
            generateBytesB1(seed1, 'otp1.key')
            decrypt(ciphertext, 'otp1.key')
            
            with open(ciphertext + '.dec', 'r') as f:
                decrypted_text = f.read()

            for word in words:
                if word.lower() in decrypted_text.lower():
                    print(f"Seed for random.seed: {seed}")
                    print(f"Seed for generateBytes: {seed1}")
                    return decrypted_text

    return "Not found."

def main(args):
    if len(args) < 3:
        print("Error.")
        return

    ciphertext_file = args[1]
    words = args[2:]

    resultado = try_all_seeds(ciphertext_file, words)
    print("Found message:", resultado)

if __name__ == "__main__":
    main(sys.argv)
