#!/usr/bin/env python3
 
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA1
from Crypto.Util.Padding import pad, unpad

master_key = get_random_bytes(32)
IV = get_random_bytes(16)
hmac_len = 64


def print_blocks(array: bytes):

    in_blocks = [array[i:i+AES.block_size]
                 for i in range(0, len(array), AES.block_size)]

    print("print_blocks"+"#"*32)
    for block in in_blocks:
        print(block)


def encrypt(plaintext: bytes) -> bytes:
    cipher = AES.new(master_key, AES.MODE_CBC, iv=IV)
    h = HMAC.new(master_key, digestmod=SHA1)

    h.update(plaintext)
    hmac = h.hexdigest().encode()
    padded = pad(plaintext + hmac, AES.block_size)

    return cipher.encrypt(padded)


def decrypt(ciphertext: bytes) -> bytes:
    decipher = AES.new(master_key, AES.MODE_CBC, iv=IV)

    return decipher.decrypt(ciphertext)


# Padding is valid -> True
def oracle(ciphertext: bytes) -> bool:
    decrypted = decrypt(ciphertext)

    try:
        unpadded = unpad(decrypted, AES.block_size)
    except:
        return False
    return True


# HMACs match -> True
def valid_frame(ciphertext: bytes) -> bool:
    h = HMAC.new(master_key, digestmod=SHA1)

    decrypted = decrypt(ciphertext)

    try:
        unpadded = unpad(decrypted, AES.block_size)
    except:
        return False

    plaintext = unpadded[:-hmac_len]
    hmac = unpadded[-hmac_len:]

    h.update(plaintext)
    generated_hmac = h.hexdigest().encode()

    if generated_hmac == hmac:
        return True
    return False


def random_cipher():
    global IV
    IV = get_random_bytes(16)
    global master_key
    master_key = get_random_bytes(32)


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def server(path: str):
    request = "GET /{} HTTP/1.1\r\nCookie={}\r\n\r\n"
    secret = "s3cret-auth-c00kie"

    return encrypt(request.format(path, secret).encode())


def attack():

    print("#"*17+" Attack started "+"#"*17)

    # all the requests are meant to be issued by the client through an evil js (xss for instance)

    original_encryption_len = len(server(''))
    blocks_num = original_encryption_len//AES.block_size

    for i in range(AES.block_size*2):
        forged_length = len(server('a'*i))

        if (forged_length > original_encryption_len):
            break

    # initial padding to add to have last block filled with padding
    at_least = i

    recovered_bytes = []

    for chosen in range(1, blocks_num):
        partial_recovered = []
        for char in range(AES.block_size):

            # on average, block_size * num_blocks * 256 attempt are needed for POODLE attack to retrieve all the needed bytes
            for i in range(256*AES.block_size):
                random_cipher()

                forged_request = server('a'*(at_least+char))

                forged_blocks = [forged_request[i:i+AES.block_size]
                                 for i in range(0, len(forged_request), AES.block_size)]

                # encrypted_blocks[chosen] is the chosen block to decrypt
                forged_blocks[-1] = forged_blocks[chosen]

                if oracle(b''.join(forged_blocks)):

                    c_prev = forged_blocks[chosen-1][-1:]
                    c_minus_one = forged_blocks[-2][-1:]

                    # plaintext last byte = c_n_-1 xor c_prev_to_chosen xor '0x01'
                    deciphered = byte_xor(
                        c_prev,  byte_xor(b'\x01', c_minus_one))

                    partial_recovered.append(deciphered.decode())

                    break

        partial_recovered.reverse()
        recovered_bytes.append(''.join(partial_recovered))

    recovered_secret = ''.join(recovered_bytes).split('\r\n')[1]

    print("#"*16+" Attack completed "+"#"*16)
    print("Recovered Secret is: ")
    print(recovered_secret)
    print("#"*50)


print('''
           ____  ____  ____  ____  __    ______
          / __ \/ __ \/ __ \/ __ \/ /   / ____/
         / /_/ / / / / / / / / / / /   / __/   
        / ____/ /_/ / /_/ / /_/ / /___/ /___   
       /_/    \____/\____/_____/_____/_____/   
          ''')

attack()
