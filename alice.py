import sys, socket, pickle

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Padding
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits
from hashlib import sha256
from random import sample
from select import select

PORT = 9005
SERVER = 'localhost'
DIR_PORT = 9000
DIR_SERVER = 'localhost'

HSK = []

# Diffie-Hellman
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485
g = 2
x1 = getrandbits(1024)
x2 = getrandbits(1024)
x3 = getrandbits(1024)

def getRouters():
  # get router info from the directory
  ssocket = connectSocket(DIR_SERVER, DIR_PORT)
  ssocket.send(b'G')
  msg = ssocket.recv(4096)
  routers = pickle.loads(msg)
  ssocket.close()
  return routers

def encryptAES(hsk, data):
  key = bytes.fromhex(hsk.hexdigest())
  cipher = AES.new(key, AES.MODE_CTR)
  ct_bytes = cipher.encrypt(data)
  nonce = cipher.nonce
  return ct_bytes, nonce

def decryptAES(hsk, data):
  key = bytes.fromhex(hsk.hexdigest())
  nonce = data['nonce']
  ct = data['cipherText']
  cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
  return cipher.decrypt(ct)

def createSocket(server, port):
  ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  ssocket.bind((server, port))
  ssocket.listen()
  return ssocket

def connectSocket(server, port):
  ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  ssocket.connect((server, port))
  return ssocket

def createCircuit(routers):
  # convert dict to list
  circuit = [(k, v) for k, v in routers.items()]
  # use sample to get random 3 routers from list
  circuit = sample(circuit, 3)
  # start DH key exchange with first router
  server, port = tuple(circuit[0][0].split(':'))
  ssocket = connectSocket(server, int(port))
  # calc gx1
  gx1 = pow(g, x1, p)
  # encypt gx1 using routers public key
  pubKey = RSA.importKey(circuit[0][1])
  cipher = PKCS1_OAEP.new(pubKey)
  cipherText = cipher.encrypt(str(gx1).encode())
  # send create msg
  circID = get_random_bytes(2)
  msg = circID + b'C' + cipherText
  ssocket.send(msg)
  # recv created back
  msg = ssocket.recv(512)
  cmd = msg[2:3]
  if cmd == b'C':
    print('Created Recieved')
    gy1 = int((msg[3:]).decode())
    # calc shared key with OR1
    sk1 = pow(gy1, x1, p)
    hsk1 = sha256(str(sk1).encode())
    # save in global list
    HSK.append(hsk1)
    # calc gx2
    gx2 = pow(g, x2, p)
    # encypt gx2 using routers public key
    pubKey = RSA.importKey(circuit[1][1])
    cipher = PKCS1_OAEP.new(pubKey)
    cipherText = cipher.encrypt(str(gx2).encode())
    # send relay to extend to second router
    innerData = {
      'StreamID': circuit[1][0],
      'CMD': b'E',
      'DATA': cipherText
    }
    innerData = pickle.dumps(innerData)
    cipherText, nonce = encryptAES(hsk1, innerData)
    data = {
      'cipherText': cipherText,
      'nonce': nonce
    }
    # send relay msg
    msg = circID + b'R' + pickle.dumps(data)
    ssocket.send(msg)
    # recv relay back
    msg = ssocket.recv(512)
    cmd = msg[2:3]
    if cmd == b'R':
      print('Relay recieved')
      # decrypt data using shared key
      encryptedData = pickle.loads(msg[3:])
      data = pickle.loads(decryptAES(hsk1, encryptedData))
      if data['CMD'] == b'E':
        # calc shared key with OR2
        gy2 = data['DATA']
        sk2 = pow(int(gy2), x2, p)
        hsk2 = sha256(str(sk2).encode())
        # save in global list
        HSK.append(hsk2)
        # calc gx3
        gx3 = pow(g, x3, p)
        # encypt gx3 using routers public key
        pubKey = RSA.importKey(circuit[2][1])
        cipher = PKCS1_OAEP.new(pubKey)
        cipherText = cipher.encrypt(str(gx3).encode())
        # send relay to extend to second router
        innerData = {
          'StreamID': circuit[2][0],
          'CMD': b'E',
          'DATA': cipherText
        }
        # encrypt innerData using shared key(s)
        for x in reversed(HSK):
          innerData, nonce = encryptAES(x, pickle.dumps(innerData))
          innerData = {
            'cipherText': innerData,
            'nonce': nonce
          }
        data = innerData
        # send relay msg
        msg = circID + b'R' + pickle.dumps(data)
        ssocket.send(msg)
        # recv relay back
        msg = ssocket.recv(512)
        cmd = msg[2:3]
        if cmd == b'R':
          print('Relay recieved')
          # decrypt data using shared key
          data = msg[3:]
          data = pickle.loads(data)
          for x in HSK:
            data = pickle.loads(decryptAES(x, data))
          if data['CMD'] == b'E':
            # calc shared key with OR3
            gy3 = data['DATA']
            sk3 = pow(int(gy3), x3, p)
            hsk3 = sha256(str(sk3).encode())
            # save in global list
            HSK.append(hsk3)
  return circID, ssocket, circuit

def sendRequest(url, circID, ssocket, circuit):
  print('Sending begin..')
  # send Begin
  innerData = {
    'StreamID': b'\0',
    'CMD': b'B',
    'DATA': url
  }
  # encrypt innerData using shared key(s)
  for x in reversed(HSK):
    innerData, nonce = encryptAES(x, pickle.dumps(innerData))
    innerData = {
      'cipherText': innerData,
      'nonce': nonce
    }
  data = innerData
  msg = circID + b'R' + pickle.dumps(data)
  ssocket.send(msg)
  # recv message
  msg = ssocket.recv(512)
  # size = int(msg.decode())
  # msg = ssocket.recv(size)
  data = msg[3:]
  data = pickle.loads(data)
  # decrypt response
  for x in HSK:
    data = pickle.loads(decryptAES(x, data))
  if data['CMD'] != 'Connected': exit('Sus')
  print('Sending request..')
  innerData = {
    'StreamID': b'\0',
    'CMD': b'D',
    'DATA': 'GET / HTTP/1.1\r\nHost: {}\r\n\r\n'.format(url)
  }
  # encrypt innerData using shared key(s)
  for x in reversed(HSK):
    innerData, nonce = encryptAES(x, pickle.dumps(innerData))
    innerData = {
      'cipherText': innerData,
      'nonce': nonce
    }
  data = innerData
  msg = circID + b'R' + pickle.dumps(data)
  ssocket.send(msg)
  print('Data sent!')
  response = list()
  # recv message
  while True:
    ready, _, _ = select([ssocket], [], [], len(circuit))
    if not ready: break
    chunk = ready[0].recv(512)
    data = chunk[3:]
    data = pickle.loads(data)
    # decrypt data
    for x in HSK:
      data = pickle.loads(decryptAES(x, data))
    response.append(data)
  print(b''.join(response))
  ssocket.close()
  return 

def main(url):
  # get onions routers
  routers = getRouters()
  # create circuit
  circID, ssocket, circuit = createCircuit(routers)
  # send request
  sendRequest(url, circID, ssocket, circuit)

if __name__ == '__main__':
  url = sys.argv[1]
  main(url)