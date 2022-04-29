import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA3_256
from Crypto.Util.Padding import pad, unpad
import binascii

master_key = get_random_bytes(16)
IV = get_random_bytes(16)
hmac_len = 64
block_size = AES.block_size


def print_blocks(array: bytes):
    in_blocks = [array[i:i+block_size] for i in range(0, len(array), 16)]

    print("#"*128)
    for block in in_blocks:
        print(block.hex())


def encrypt(plaintext: bytes) -> bytes:
    cipher = AES.new(master_key, AES.MODE_CBC, iv=IV)
    h = HMAC.new(master_key, digestmod=SHA3_256)

    h.update(plaintext)
    hmac = h.hexdigest().encode()
    padded = pad(plaintext + hmac, cipher.block_size)

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
    h = HMAC.new(master_key, digestmod=SHA3_256)

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


secret = "this is a secret"


def attack(secret: bytes) -> str:
    request = "GET /{} HTTP/1.1\r\nCookie: {}\r\n\r\n"

    original_encryption_len = len(encrypt(request.format('', secret).encode()))
    blocks_num = original_encryption_len//block_size
    decrypted_secret = []

    for i in range(block_size*2):
        forged_request = request.format('a'*i, secret).encode()
        forged_length = len(encrypt(forged_request))

        if (forged_length > original_encryption_len):
            break

    # initial padding to add to have last block filled with 0x10
    at_least = i


attack(secret)
