import sys, socket, pickle

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Padding
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits
from router import GetRouters, Create, Created, Relay
from hashlib import sha256
from random import shuffle

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
  ssocket.send(pickle.dumps(GetRouters()))
  msg = ssocket.recv(4096)
  routers = pickle.loads(msg)
  ssocket.close()
  return routers

def encryptAES(sk, data):
  iv = get_random_bytes(16)
  key = bytes.fromhex(sk.hexdigest())
  cipher = AES.new(key, AES.MODE_CBC, iv)
  return cipher.encrypt(Padding.pad(pickle.dumps(data), 16)), iv

def decryptAES(hsk, data):
  cipherText = data['cipherText']
  iv = data['iv']
  key = bytes.fromhex(hsk.hexdigest())
  cipher = AES.new(key, AES.MODE_CBC, iv)
  plainText = cipher.decrypt(cipherText)
  return Padding.unpad(plainText, 16)

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
  # shuffle list to achieve random order of routers
  # shuffle(circuit)
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
  msg = Create(circID=1, data=cipherText)
  ssocket.send(pickle.dumps(msg))
  # recv created back
  msg = ssocket.recv(4096)
  # parse object
  obj = pickle.loads(msg)
  objType = obj.__class__.__name__
  if objType == 'Created':
    print('Created Recieved')
    gy1 = obj.data
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
      'cmd': 'Extend',
      'server': circuit[1][0],
      'value': cipherText
    }
    # encrypt innerData using hsk1
    iv = get_random_bytes(16)
    key = bytes.fromhex(hsk1.hexdigest())
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipherText = cipher.encrypt(Padding.pad(pickle.dumps(innerData), 16))
    data = {
      'cipherText': cipherText,
      'iv': iv
    }
    # send relay obj
    msg = Relay(circID=1, data=pickle.dumps(data))
    ssocket.send(pickle.dumps(msg))
    # recv relay back
    msg = ssocket.recv(4096)
    size = int(msg.decode())
    msg = ssocket.recv(size)
    # parse object
    obj = pickle.loads(msg)
    objType = obj.__class__.__name__
    if objType == 'Relay':
      print('Relay recieved')
      # decrypt data using shared key
      encryptedData = pickle.loads(obj.data)
      data = pickle.loads(decryptAES(hsk1, encryptedData))
      if data['cmd'] == 'Extended':
        # calc shared key with OR2
        gy2 = data['value']
        sk2 = pow(gy2, x2, p)
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
          'cmd': 'Extend',
          'server': circuit[2][0],
          'value': cipherText
        }
        # encrypt innerData using shared key(s)
        for x in reversed(HSK):
          iv = get_random_bytes(16)
          innerData, iv = encryptAES(x, innerData)
          innerData = {
            'cipherText': innerData,
            'iv': iv
          }
        data = innerData
        # create relay message
        msg = Relay(circID=1, data=pickle.dumps(data))
        ssocket.send(pickle.dumps(msg))
        # recv relay back
        msg = ssocket.recv(4096)
        size = int(msg.decode())
        msg = ssocket.recv(size)
        # parse object
        obj = pickle.loads(msg)
        objType = obj.__class__.__name__
        if objType == 'Relay':
          # decrypt data using shared key
          data = obj.data
          for x in HSK:
            encryptedData = pickle.loads(data)
            data = pickle.loads(decryptAES(x, encryptedData))
          if data['cmd'] == 'Extended':
            # calc shared key with OR3
            gy3 = data['value']
            sk3 = pow(gy3, x3, p)
            hsk3 = sha256(str(sk3).encode())
            # save in global list
            HSK.append(hsk3)
  return ssocket, circuit

def sendRequest(url, ssocket, circuit):
  print('Sending request..')
  innerData = {
    'cmd': 'Begin',
    'server': url,
    'value': ''
  }
  # encrypt innerData using shared key(s)
  for x in reversed(HSK):
    iv = get_random_bytes(16)
    innerData, iv = encryptAES(x, innerData)
    innerData = {
      'cipherText': innerData,
      'iv': iv
    }
  data = innerData
  # create relay message
  msg = Relay(circID=1, data=pickle.dumps(data))
  ssocket.send(pickle.dumps(msg))
  # recv message
  msg = ssocket.recv(4096)
  size = int(msg.decode())
  msg = ssocket.recv(size)
  obj = pickle.loads(msg)
  data = obj.data
  # decrypt response
  for x in HSK:
    encryptedData = pickle.loads(data)
    data = pickle.loads(decryptAES(x, encryptedData))
  if data['cmd'] == 'Connected':
    f = open('response.html','w')
    f.write(data['data'])
    f.close()
  ssocket.close()
  print('Response received!')
  return 

def main(url):
  # get onions routers
  routers = getRouters()
  # create circuit
  ssocket, circuit = createCircuit(routers)
  # send request
  sendRequest(url, ssocket, circuit)

if __name__ == '__main__':
  url = sys.argv[1]
  main(url)