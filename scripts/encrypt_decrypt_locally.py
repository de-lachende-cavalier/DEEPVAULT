from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA512
from os import system
import requests
import secrets
import json
import sys

deepapi_host = 'http://localhost:3004'
headers = {'Content-Type': 'application/json'}

deepvault_private_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
deepvault_public_key = deepvault_private_key.public_key()  # len == 266

deepvault_public_key_pem_spki = deepvault_public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo).decode()

count = 1

# ECDHE

ecdh_data = {'pub_key': deepvault_public_key_pem_spki,
             'counter': count}
count += 1

auth_post = requests.post(deepapi_host + '/auth', headers=headers,  data=json.dumps(ecdh_data))
deepapi_public_key = load_pem_public_key(auth_post.json()['pub_key'].encode(), default_backend())

shared_secret = deepvault_private_key.exchange(ec.ECDH(), deepapi_public_key)

# challenge-response

iv = secrets.token_bytes(16)

salt = secrets.token_bytes(32)
iterations = 150000

kdf = PBKDF2HMAC(
    algorithm=SHA512(),
    length=32,  # 32 * 8 = 256 bits
    salt=salt,
    iterations=iterations,
    backend = default_backend()
)

secret_key = kdf.derive(shared_secret)

cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
decryptor = cipher.decryptor()

nonce = secrets.token_bytes(64)
encrypted_nonce = encryptor.update(nonce) + encryptor.finalize()

nonce_data = {'nonce': encrypted_nonce.hex(),
              'counter': count,
              'iv': iv.hex(),
              'salt': salt.hex(),
              'iterations': iterations}

challenge_post = requests.post(deepapi_host + '/auth/challenge', headers=headers, data=json.dumps(nonce_data))

deepapi_nonce = challenge_post.json()['api_nonce']
deepapi_nonce = decryptor.update(bytes.fromhex(deepapi_nonce)) + decryptor.finalize()

# symmetric encryption 

if b'somerandomstuffhere' in deepapi_nonce:
    key_req = requests.get(deepapi_host + '/aes')
    enc_symmetric_key, iv = key_req.json()['key'], key_req.json()['iv']

    sym_cipher = Cipher(algorithms.AES(secret_key), modes.CBC(bytes.fromhex(iv)), backend=default_backend())
    sym_decryptor = sym_cipher.decryptor()

    # decrypt and unwrap the generated symmetric key
    symmetric_key = sym_decryptor.update(bytes.fromhex(enc_symmetric_key)) + sym_decryptor.finalize()
    symmetric_key = symmetric_key[:64].decode()
    nonce = secrets.token_hex(16)

    keyfile_name = secrets.token_hex(80)

    with open('/tmp/' + keyfile_name, 'w+') as kf:
        kf.write(f'{nonce}:{symmetric_key}')

    print(keyfile_name)

else:
    print("Protocol failed. Aborting.")
    sys.exit(-1)
