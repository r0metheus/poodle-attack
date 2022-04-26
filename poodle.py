import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA3_256
from Crypto.Util.Padding import pad, unpad

master_key = get_random_bytes(16)
IV = get_random_bytes(16)
hmac_len = 64


def ssl_frame_gen(plaintext: str) -> bytes:
    cipher = AES.new(master_key, AES.MODE_CBC, iv=IV)
    h = HMAC.new(master_key, digestmod=SHA3_256)

    data = plaintext.encode()
    h.update(data)
    hmac = h.hexdigest().encode()
    padded = pad(data + hmac, cipher.block_size)

    return cipher.encrypt(padded)


def ssl_frame_verify(ciphertext: bytes) -> bool:
    decipher = AES.new(master_key, AES.MODE_CBC, iv=IV)
    h = HMAC.new(master_key, digestmod=SHA3_256)

    decrypted = decipher.decrypt(ciphertext)

    res = unpad(decrypted, decipher.block_size)
    plaintext = res[:-hmac_len]
    hmac = res[-hmac_len:]

    h.update(plaintext)
    generated_hmac = h.hexdigest().encode()

    if generated_hmac == hmac:
        return True
    return False


plaintext = "this is a secret"

# while(True):
#    frame = ssl_frame_gen(input())
#    print(base64.b64encode(frame))
# print(ssl_frame_verify(frame))

frame = ssl_frame_gen(plaintext)
print(base64.b64encode(frame))
