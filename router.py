import sys, socket, threading, time, pickle

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Padding
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits
from hashlib import sha256
from threading import Thread
from select import select

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
    data = {
      'ip': self.ip,
      'port': self.port,
      'pubKey': self.pubKey
    }
    msg = b'R' + pickle.dumps(data)
    ssocket.send(msg)
    ssocket.close()
  
  def decryptRSA(self, data):
    priKey = RSA.importKey(self.priKey, passphrase='dees')
    cipher = PKCS1_OAEP.new(priKey)
    plainText = cipher.decrypt(data)
    return plainText.decode()

  def encryptAES(self, hsk, data):
    key = bytes.fromhex(hsk.hexdigest())
    cipher = AES.new(key, AES.MODE_CTR, nonce=b'\0')
    ct_bytes = cipher.encrypt(data)
    return ct_bytes

  def decryptAES(self, hsk, data):
    key = bytes.fromhex(hsk.hexdigest())
    cipher = AES.new(key, AES.MODE_CTR, nonce=b'\0')
    return cipher.decrypt(data)

  def padData(self, length, data):
    return data.ljust(length, b'\0')

  def unpadData(self, data):
    return data.rstrip(b'\0')

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
      msg = connection.recv(512)
      if not msg: break
      cmd = msg[2:3]
      data = msg[3:]
      if cmd == b'C':
        circID = msg[0:2]
        data = self.unpadData(data)
        # calc shared key
        gx = int(self.decryptRSA(data))
        sk = pow(gx, y, p)
        hsk = sha256(str(sk).encode())
        # calc gy to send back
        gy = pow(g, y, p)
        data = self.padData(509, str(gy).encode())
        # send back to sender
        msg = circID + b'C' + data
        connection.send(msg)
        # wait for next msg
        continue
      elif cmd == b'R':
        # decrypt layer
        relayHeader = self.decryptAES(hsk, data)
        streamID = relayHeader[0:2]
        digest = relayHeader[2:8]
        length = int.from_bytes(relayHeader[8:10], sys.byteorder)
        cmd = relayHeader[10:11]
        data = relayHeader[11:length+11]
        # check if digest is valid
        if hsk.digest()[0:6] == digest:
          # update hsk
          hsk.update(relayHeader)
          # execute cmd
          if cmd == b'X':
            # send create to next router
            router = self.unpadData(data[0:21]).decode()
            ip, port = tuple(router.split(':'))
            nextRouter = self.connectSocket(ip, int(port))
            # send create
            nextCircID = get_random_bytes(2)
            ex = data[21:]
            data = self.padData(509, ex)
            msg = nextCircID + b'C' + data
            nextRouter.send(msg)
            # recv created
            msg = nextRouter.recv(512)
            cmd = msg[2:3]
            if cmd != b'C': break
            data = msg[3:]
            gy = self.unpadData(data)
            # create relay message
            streamID = get_random_bytes(2)
            digest = hsk.digest()[0:6]
            length = len(gy).to_bytes(2, sys.byteorder)
            relayHeader = streamID + digest + length + b'X' + self.padData(498, gy)
            cipherText = self.encryptAES(hsk, relayHeader)
            # send relay back to connection
            msg = circID + b'R' + cipherText
            connection.send(msg)
            # update hsk
            hsk.update(relayHeader)
          elif cmd == b'B':
            url = data.decode()
            # create tcp connection
            try:
              nextRouter = self.connectSocket(url, 80)
            except Exception as inst:
              print(inst)
            # build msg
            streamID = get_random_bytes(2)
            digest = hsk.digest()[0:6]
            length = get_random_bytes(2)
            relayHeader = streamID + digest + length + b'C' + self.padData(498, b'')
            cipherText = self.encryptAES(hsk, relayHeader)
            # send relay back to connection
            msg = circID + b'R' + cipherText
            connection.send(msg)
            # update hsk
            hsk.update(relayHeader)
          elif cmd == b'D':
            request = self.unpadData(data)
            # send request
            nextRouter.send(request)
            # recv response
            while True:
              ready, _, _ = select([nextRouter], [], [], 1)
              if not ready: break
              chunk = ready[0].recv(498)
              # create relay message
              streamID = get_random_bytes(2)
              digest = hsk.digest()[0:6]
              length = (498).to_bytes(2, sys.byteorder)
              relayHeader = streamID + digest + length + b'D' + chunk
              cipherText = self.encryptAES(hsk, relayHeader)
              # send relay back to connection
              msg = circID + b'R' + cipherText
              connection.send(msg)
              # update hsk
              hsk.update(relayHeader)
        else:
          # forward to next router
          msg = nextCircID + b'R' + relayHeader
          nextRouter.send(msg)
          # recv message
          while True:
            ready, _, _ = select([nextRouter], [], [], 1)
            if not ready: break
            msg = ready[0].recv(512)
            cmd = msg[2:3]
            data = msg[3:]
            if cmd == b'R':
              cipherText = self.encryptAES(hsk, data)
              # send relay back to connection
              msg = circID + b'R' + cipherText
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