import sys, socket, pickle, threading, time, requests, dns.resolver

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Padding
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits
from hashlib import sha256
from threading import Thread

class GetRouters:
  pass

class Register:
  def __init__(self, ip, port, pubKey):
    self.addr = f'{ip}:{port}'
    self.pubKey = pubKey

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
    nonce = cipher.nonce
    return ct_bytes, nonce

  def decryptAES(self, hsk, data):
    key = bytes.fromhex(hsk.hexdigest())
    nonce = data['nonce']
    ct = data['cipherText']
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ct)

  def handleClient(self, connection, address):
    print('New connection - {}'.format(address))
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485
    g = 2
    y = getrandbits(1024)
    hsk = None
    circID = None
    nextRouter = None
    nextCircID = None
    while True:
      msg = connection.recv(4096)
      if not msg: break
      cmd = msg[2:3]
      if cmd == b'C':
        circID = msg[0:2]
        # calc shared key
        gx = int(self.decryptRSA(msg[3:]))
        sk = pow(gx, y, p)
        hsk = sha256(str(sk).encode())
        # calc gy to send back
        gy = pow(g, y, p)
        # send back to sender
        msg = circID + b'C' + str(gy).encode()
        connection.send(msg)
        # wait for next msg
        continue
      elif cmd == b'R':
        # decrypt layer
        encryptedData = pickle.loads(msg[3:])
        data = pickle.loads(self.decryptAES(hsk, encryptedData))
        # only to forward messages will have this key after decryption
        if 'cipherText' in data:
          # forward to next router
          msg = nextCircID + b'R' + pickle.dumps(data)
          nextRouter.send(msg)
          # recv message
          msg = nextRouter.recv(4096)
          size = int(msg.decode())
          msg = nextRouter.recv(size)
          cmd = msg[2:3]
          if cmd == b'R':
            cipherText, nonce = self.encryptAES(hsk, msg[3:])
            data = {
              'cipherText': cipherText,
              'nonce': nonce
            }
            # send relay obj back to connection
            msg = circID + b'R' + pickle.dumps(data)
            size = str(len(msg)).encode()
            connection.send(size)
            time.sleep(1)
            connection.send(msg)
        else:
          # execute cmd
          if data['CMD'] == 'Extend':
            # send create to next router
            server = data['StreamID']
            ex = data['DATA']
            ip, port = tuple(server.split(':'))
            nextRouter = self.connectSocket(ip, int(port))
            # send create
            msg = get_random_bytes(2) + b'C' + ex
            nextRouter.send(msg)
            # recv created
            msg = nextRouter.recv(4096)
            cmd = msg[2:3]
            if cmd != b'C': break
            gy = msg[3:]
            # create relay message
            innerData = {
              'StreamID': circID,
              'CMD': 'Extended',
              'DATA': gy
            }
            cipherText, nonce = self.encryptAES(hsk, innerData)
            data = {
              'cipherText': cipherText,
              'nonce': nonce
            }
            # send relay obj back to connection
            nextCircID = get_random_bytes(2)
            msg = nextCircID + b'R' + pickle.dumps(data)
            size = str(len(msg)).encode()
            connection.send(size)
            time.sleep(1)
            connection.send(msg)
          elif data['CMD'] == 'Data':
            # send request to web server
            url = data['DATA']
            r = requests.get(f'https://{url}')
            # encrypt data
            innerData = {
              'CMD': 'Connected',
              'DATA': r.text
            }
            # encrypt innerData using hsk
            cipherText, nonce = self.encryptAES(hsk, innerData)
            data = {
              'cipherText': cipherText,
              'nonce': nonce
            }
            # send relay obj back to connection
            msg = circID + b'R' + pickle.dumps(data)
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
    print('Server is listening on {}:{}'.format(ip, port))
    while True:
      connection, address = ssocket.accept()
      thread = threading.Thread(target=self.handleClient, args=(connection, address))
      thread.start()
      print('Number of connections: {}'.format(threading.activeCount() - 1))
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