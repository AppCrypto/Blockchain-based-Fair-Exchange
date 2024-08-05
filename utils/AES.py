from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import time
import string
import random

def Encrypt(key, message):
    backend = default_backend()

    # A 16-byte random IV.
    iv = os.urandom(16)

    # Create a Cipher object using AES algorithm and CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    # The message is padded using a padding scheme
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message) + padder.finalize()

    # encrypte
    ct = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ct


def Decrypt(key, data):
    backend = default_backend()

    # Extract the IV and the ciphertext
    iv = data[:16]
    ct = data[16:]

    # Cipher objects are created using the AES algorithm and CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    # decrypt
    padded_data = decryptor.update(ct) + decryptor.finalize()

    # Reverse fill
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data

# 128-bite key

"""
key = b'0123456789abcdef0123456789abcdef'
#message = b'Hello, AESDJAKJDKLAJDALKJDALKJDAOID789765456AOIJA,DAKJDLKAJDAKNDM,ANDAKHDJKASHDJKADAM encryption!1564987564654564897987894545645623'

print(type(key))
# 1MB random string
text = ''.join(random.choices(string.ascii_letters + string.digits, k=400*1024*1024))
message = text.encode('utf-8')
#print(message)

t1 = time.time()
encrypted_data = Encrypt(key, message)
elapsed_time_ms = (time.time() - t1) * 1000
print(f'enc:{elapsed_time_ms:.4f}ms')

#print("Encrypted data:", encrypted_data)
t2 = time.time()
decrypted_data = Decrypt(key, encrypted_data)
elapsed_time_ms = (time.time() - t2) * 1000
print(f'dec:{elapsed_time_ms:.4f}ms')
#print("Decrypted data:", decrypted_data.decode('utf-8'))
"""
