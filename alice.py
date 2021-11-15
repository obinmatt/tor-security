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

def createSocket(server, port):
  ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  ssocket.bind((server, port))
  ssocket.listen()
  return ssocket

def connectSocket(server, port):
  ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  ssocket.connect((server, port))
  return ssocket

def encryptAES(hsk, data):
  key = bytes.fromhex(hsk.hexdigest())
  cipher = AES.new(key, AES.MODE_CTR, nonce=b'\0')
  ct_bytes = cipher.encrypt(data)
  return ct_bytes

def decryptAES(hsk, data):
  key = bytes.fromhex(hsk.hexdigest())
  cipher = AES.new(key, AES.MODE_CTR, nonce=b'\0')
  return cipher.decrypt(data)

def padData(length, data):
  return data.ljust(length, b'\0')

def unpadData(data):
  return data.rstrip(b'\0')

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
  data = padData(509, cipherText)
  msg = circID + b'C' + data
  ssocket.send(msg)
  # recv created back
  msg = ssocket.recv(512)
  cmd = msg[2:3]
  if cmd == b'C':
    print('Created Recieved')
    data = msg[3:]
    gy1 = int(unpadData(data))
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
    # send addr of next hop
    addr = circuit[1][0].encode()
    # pad addr with '\0' till 21 bytes
    data = padData(21, addr) + cipherText
    paddedData = padData(498, data)
    # StreamID + Digest + Len + CMD + DATA
    streamID = get_random_bytes(2)
    digest = HSK[0].digest()[0:6]
    length = len(data).to_bytes(2, sys.byteorder)
    relayHeader = streamID + digest + length + b'X' + paddedData
    # encrypt relayHeader
    cipherText = encryptAES(hsk1, relayHeader)
    # send relay msg
    msg = circID + b'R' + cipherText
    ssocket.send(msg)
    # update digest
    HSK[0].update(relayHeader)
    # recv relay back
    msg = ssocket.recv(512)
    cmd = msg[2:3]
    data = msg[3:]
    if cmd == b'R':
      print('Relay recieved')
      # decrypt data using shared key
      relayHeader = decryptAES(hsk1, data)
      streamID = relayHeader[0:2]
      digest = relayHeader[2:8]
      length = int.from_bytes(relayHeader[8:10], sys.byteorder)
      cmd = relayHeader[10:11]
      data = relayHeader[11:length+11]
      if HSK[0].digest()[0:6] == digest:
        # update digest
        HSK[0].update(relayHeader)
        if cmd == b'X':
          # calc shared key with OR2
          gy2 = data
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
          # send addr of next hop
          addr = circuit[2][0].encode()
          # pad addr with '\0' till 21 bytes
          data = padData(21, addr) + cipherText
          paddedData = padData(498, data)
          # StreamID + Digest + Len + CMD + DATA
          streamID = get_random_bytes(2)
          digest = HSK[1].digest()[0:6]
          length = len(data).to_bytes(2, sys.byteorder)
          relayHeader = streamID + digest + length + b'X' + paddedData
          data = relayHeader
          # encrypt data using shared key(s)
          for x in reversed(HSK):
            data = encryptAES(x, data)
          # send relay msg
          msg = circID + b'R' + data
          ssocket.send(msg)
          # update digest
          HSK[1].update(relayHeader)
          # recv relay back
          msg = ssocket.recv(512)
          cmd = msg[2:3]
          if cmd == b'R':
            print('Relay recieved')
            relayHeader = msg[3:]
            # decrypt relayHeader using shared key(s)
            for x in HSK:
              relayHeader = decryptAES(x, relayHeader)
            streamID = relayHeader[0:2]
            digest = relayHeader[2:8]
            length = int.from_bytes(relayHeader[8:10], sys.byteorder)
            cmd = relayHeader[10:11]
            data = relayHeader[11:length+11]
            if HSK[1].digest()[0:6] == digest:
              # update digest
              HSK[1].update(relayHeader)
              if cmd == b'X':
                # calc shared key with OR3
                gy3 = data
                sk3 = pow(int(gy3), x3, p)
                hsk3 = sha256(str(sk3).encode())
                # save in global list
                HSK.append(hsk3)
  return circID, ssocket, circuit

def sendRequest(url, circID, ssocket, circuit):
  print('Sending request..')
  # send Begin
  data = url.encode()
  paddedData = padData(498, data)
  # StreamID + Digest + Len + CMD + DATA
  streamID = get_random_bytes(2)
  digest = HSK[2].digest()[0:6]
  length = len(data).to_bytes(2, sys.byteorder)
  relayHeader = streamID + digest + length + b'B' + paddedData
  data = relayHeader
  # encrypt data using shared key(s)
  for x in reversed(HSK):
    data = encryptAES(x, data)
  msg = circID + b'R' + data
  ssocket.send(msg)
  # update digest
  HSK[2].update(relayHeader)
  # recv message
  msg = ssocket.recv(512)
  relayHeader = msg[3:]
  # decrypt relayHeader using shared key(s)
  for x in HSK:
    relayHeader = decryptAES(x, relayHeader)
  streamID = relayHeader[0:2]
  digest = relayHeader[2:8]
  length = int.from_bytes(relayHeader[8:10], sys.byteorder)
  cmd = relayHeader[10:11]
  data = relayHeader[11:length+11]
  if HSK[2].digest()[0:6] == digest:
    # update digest
    HSK[2].update(relayHeader)
    data = ('GET / HTTP/1.1\r\nHost: {}\r\n\r\n'.format(url)).encode()
    paddedData = padData(474, data)
    # StreamID + Digest + Len + CMD + DATA
    streamID = get_random_bytes(2)
    digest = HSK[2].digest()[0:6]
    length = len(data).to_bytes(2, sys.byteorder)
    relayHeader = streamID + digest + length + b'D' + paddedData
    data = relayHeader
    # encrypt relayHeader using shared key(s)
    for x in reversed(HSK):
      data = encryptAES(x, data)
    msg = circID + b'R' + data
    ssocket.send(msg)
    # update digest
    HSK[2].update(relayHeader)
    # recv message
    response = list()
    while True:
      ready, _, _ = select([ssocket], [], [], len(circuit))
      if not ready: break
      chunk = ready[0].recv(512)
      msg = unpadData(chunk)
      relayHeader = msg[3:]
      # decrypt relayHeader using shared key(s)
      for x in HSK:
        relayHeader = decryptAES(x, relayHeader)
      streamID = relayHeader[0:2]
      digest = relayHeader[2:8]
      length = int.from_bytes(relayHeader[8:10], sys.byteorder)
      cmd = relayHeader[10:11]
      data = relayHeader[11:length+11]
      # append data to list
      response.append(data)
      # update digest
      HSK[2].update(relayHeader)
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