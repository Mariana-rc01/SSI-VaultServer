import sys

def manipulate_ciphertext(file_path, pos, known_ptxt, new_ptxt):
    with open(file_path, 'rb') as f:
        ciphertext = f.read()
    
    known_ptxt_bytes = known_ptxt.encode()
    new_ptxt_bytes = new_ptxt.encode()
    
    keystream = bytes([ciphertext[pos + i] ^ known_ptxt_bytes[i] for i in range(len(known_ptxt_bytes))])
    
    new_ciphertext = bytearray(ciphertext)
    for i in range(len(new_ptxt_bytes)):
        new_ciphertext[pos + i] = keystream[i] ^ new_ptxt_bytes[i]
    
    with open(file_path + '.attck', 'wb') as f:
        f.write(new_ciphertext)

def main():
    if len(sys.argv) != 5:
        print("Usage: chacha20_int_attck.py <fctxt> <pos> <ptxtAtPos> <newPtxtAtPos>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    pos = int(sys.argv[2])
    known_ptxt = sys.argv[3]
    new_ptxt = sys.argv[4]
    
    manipulate_ciphertext(file_path, pos, known_ptxt, new_ptxt)

if __name__ == "__main__":
    main()
