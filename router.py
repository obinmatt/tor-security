import sys, socket, pickle, threading, time, requests

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Padding
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits
from base64 import b64encode, b64decode
from hashlib import sha256
from threading import Thread

class GetRouters:
  pass

class Register:
  def __init__(self, ip, port, pubKey):
    self.addr = f'{ip}:{port}'
    self.pubKey = pubKey

class Create:
  def __init__(self, circID, data):
    self.circID = circID
    self.data = data

class Created:
  def __init__(self, circID, data):
    self.circID = circID
    self.data = data

class Relay:
  def __init__(self, circID, data):
    self.circID = circID
    self.data = data

class Router:
  ip = None
  port = None
  dirIP = None
  dirPort = None
  priKey = None
  pubKey = None
  
  def __init__(self, ip, port):
    self.ip = ip
    self.port = int(port)
    self.dirIP = 'localhost'
    self.dirPort = 9000
  
  def generateRSAKeys(self):
    # generate keys
    key = RSA.generate(2048)
    pem = key.export_key(format='PEM', passphrase='dees')
    pub = key.publickey()
    pub_pem = pub.export_key(format='PEM')
    # save in state
    self.priKey = pem
    self.pubKey = pub_pem
  
  def createSocket(self, ip, port):
    ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssocket.bind((ip, port))
    ssocket.listen()
    return ssocket

  def connectSocket(self, ip, port):
    ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssocket.connect((ip, port))
    return ssocket
  
  def register(self):
    ssocket = self.connectSocket(self.dirIP, self.dirPort)
    msg = Register(self.ip, self.port, self.pubKey)
    ssocket.send(pickle.dumps(msg))
    ssocket.close()
  
  def decryptRSA(self, data):
    priKey = RSA.importKey(self.priKey, passphrase='dees')
    cipher = PKCS1_OAEP.new(priKey)
    plainText = cipher.decrypt(data)
    return plainText.decode()

  def encryptAES(self, hsk, data):
    key = bytes.fromhex(hsk.hexdigest())
    cipher = AES.new(key, AES.MODE_CTR)
    ct_bytes = cipher.encrypt(pickle.dumps(data))
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return ct, nonce

  def decryptAES(self, hsk, data):
    key = bytes.fromhex(hsk.hexdigest())
    nonce = b64decode(data['nonce'])
    ct = b64decode(data['cipherText'])
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ct)

  def handleClient(self, connection, address):
    print(f"New connection - {address}")
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485
    g = 2
    y = getrandbits(1024)
    hsk = None
    circID = None
    nextRouter = None
    while True:
      msg = connection.recv(4096)
      if not msg: break
      obj = pickle.loads(msg)
      objClass = obj.__class__.__name__
      if objClass == 'Create':
        circID = obj.circID
        # calc shared key
        gx = int(self.decryptRSA(obj.data))
        sk = pow(gx, y, p)
        hsk = sha256(str(sk).encode())
        # calc gy to send back
        gy = pow(g, y, p)
        # send back to sender
        msg = Created(circID=circID, data=gy)
        connection.send(pickle.dumps(msg))
        # wait for next msg
        continue
      elif objClass == 'Relay':
        # decrypt layer
        encryptedData = pickle.loads(obj.data)
        data = pickle.loads(self.decryptAES(hsk, encryptedData))
        # only to forward messages will have this key after decryption
        if 'cipherText' in data:
          # forward to next router
          msg = Relay(circID=circID+1, data=pickle.dumps(data))
          nextRouter.send(pickle.dumps(msg))
          # recv message
          msg = nextRouter.recv(4096)
          size = int(msg.decode())
          msg = nextRouter.recv(size)
          obj = pickle.loads(msg)
          objClass = obj.__class__.__name__
          if objClass == 'Relay':
            cipherText, nonce = self.encryptAES(hsk, obj.data)
            data = {
              'cipherText': cipherText,
              'nonce': nonce
            }
            # send relay obj back to connection
            msg = Relay(circID=circID, data=pickle.dumps(data))
            msg = pickle.dumps(msg)
            size = str(len(msg)).encode()
            connection.send(size)
            time.sleep(1)
            connection.send(msg)
        else:
          # execute cmd
          if data['cmd'] == 'Extend':
            # send create to next router
            server = data['server']
            ex = data['value']
            ip, port = tuple(server.split(':'))
            nextRouter = self.connectSocket(ip, int(port))
            # send create
            msg = Create(circID=circID+1, data=ex)
            nextRouter.send(pickle.dumps(msg))
            # recv created
            msg = nextRouter.recv(4096)
            obj = pickle.loads(msg)
            gy = obj.data
            # create relay message
            innerData = {
              'cmd': 'Extended',
              'server': '',
              'value': gy
            }
            cipherText, nonce = self.encryptAES(hsk, innerData)
            data = {
              'cipherText': cipherText,
              'nonce': nonce
            }
            # send relay obj back to connection
            msg = Relay(circID=1, data=pickle.dumps(data))
            msg = pickle.dumps(msg)
            size = str(len(msg)).encode()
            connection.send(size)
            time.sleep(1)
            connection.send(msg)
          elif data['cmd'] == 'Begin':
            # send request to web server
            url = data['server']
            r = requests.get(url)
            # encrypt data
            innerData = {
              'cmd': 'Connected',
              'data': r.text
            }
            # encrypt innerData using hsk
            cipherText, nonce = self.encryptAES(hsk, innerData)
            data = {
              'cipherText': cipherText,
              'nonce': nonce
            }
            # send relay obj back to connection
            msg = Relay(circID=circID, data=pickle.dumps(data))
            msg = pickle.dumps(msg)
            size = str(len(msg)).encode()
            connection.send(size)
            time.sleep(1)
            connection.send(msg)
      continue
    connection.close()

  def listen(self):
    # create server socket
    ip = self.ip
    port = self.port
    ssocket = self.createSocket(ip, port)
    print(f"Server is listening on {ip}:{port}")
    while True:
      connection, address = ssocket.accept()
      thread = threading.Thread(target=self.handleClient, args=(connection, address))
      thread.start()
      print(f"Number of connections: {threading.activeCount() - 1}")
    ssocket.close()
  
def main(ip, port):
  # create router obj
  router = Router(ip, port)
  # create RSA keypair
  router.generateRSAKeys()
  # register with directory
  router.register()
  # start listening
  router.listen()

if __name__ == '__main__':
  ip = sys.argv[1]
  port = sys.argv[2]
  main(ip, port)