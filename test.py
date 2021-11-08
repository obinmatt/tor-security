import pickle
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

data = b"secret"
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CTR)
ct_bytes = cipher.encrypt(data)
nonce = cipher.nonce
result = nonce + ct_bytes

result = result.ljust(509, b'\0')

nonce = result[0:8]
ct = result[8:]
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
pt = cipher.decrypt(ct)
print("The message was: ", pt)
