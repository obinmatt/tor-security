import sys
import socket
import threading
import pickle

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Padding
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits
from hashlib import sha256
from random import sample
from select import select

P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485

SOCKS_VERSION = 5
DIR_PORT = 9001
DIR_SERVER = 'localhost'

class OP:
    ip = None
    port = None
    username = None
    password = None


    def __init__(self, ip, port):
        self.ip = ip
        self.port = int(port)
        self.username = 'username'
        self.password = 'password'


    def getRouters(self):
        # get router info from the directory
        ssocket = self.connectSocket(DIR_SERVER, DIR_PORT)
        ssocket.send(b'G')
        msg = ssocket.recv(4096)
        routers = pickle.loads(msg)
        ssocket.close()
        return routers


    def createSocket(self, ip, port):
        ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssocket.bind((ip, port))
        ssocket.listen()
        return ssocket


    def connectSocket(self, ip, port):
        ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssocket.connect((ip, port))
        return ssocket


    def encryptAES(self, hsk, nonce, data):
        key = bytes.fromhex(hsk.hexdigest())
        nonce = nonce.digest()[0:8]
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        ct_bytes = cipher.encrypt(data)
        return ct_bytes


    def decryptAES(self, hsk, nonce, data):
        key = bytes.fromhex(hsk.hexdigest())
        nonce = nonce.digest()[0:8]
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        return cipher.decrypt(data)


    def padData(self, length, data):
        return data.ljust(length, b'\0')


    def unpadData(self, data):
        return data.rstrip(b'\0')
    

    def authenticateConnection(self, connection):
        version = ord(connection.recv(1))
        assert version == 1
        # username
        username_len = ord(connection.recv(1))
        username = connection.recv(username_len).decode()
        # password
        password_len = ord(connection.recv(1))
        password = connection.recv(password_len).decode()
        # auth
        if username == self.username and password == self.password:
            # success, status = 0
            msg = (version).to_bytes(1, sys.byteorder) + (0).to_bytes(1, sys.byteorder)
            connection.send(msg)
            return True
        else:
            # failure, status != 0
            msg = (version).to_bytes(1, sys.byteorder) + (1).to_bytes(1, sys.byteorder)
            connection.send(msg)
            connection.close()
            return False


    def createCircuit(self, routers):
        # diffie-hellman
        p = P
        g = 2
        x1 = getrandbits(1024)
        x2 = getrandbits(1024)
        x3 = getrandbits(1024)
        # shared keys and nonces
        hsk = []
        nonces = []
        # convert dict to list
        circuit = [(k, v) for k, v in routers.items()]
        # use sample to get random 3 routers from list
        circuit = sample(circuit, 3)
        
        # start DH key exchange with first router
        server, port = tuple(circuit[0][0].split(':'))
        ssocket = self.connectSocket(server, int(port))
        # calc gx1
        gx1 = pow(g, x1, p)
        # encypt gx1 using routers public key
        pubKey = RSA.importKey(circuit[0][1])
        cipher = PKCS1_OAEP.new(pubKey)
        cipherText = cipher.encrypt(str(gx1).encode())
        # send create msg
        circID = get_random_bytes(2)
        # create random nonce
        nonce = get_random_bytes(8)
        nonces.append(sha256(nonce))
        data = nonce + cipherText
        paddedData = self.padData(509, data)
        msg = (circID
               + b'\x01'
               + paddedData)
        ssocket.send(msg)
        
        # recv created back
        msg = ssocket.recv(512)
        cmd = msg[2:3]
        # created
        if cmd == b'\x02':
            data = msg[3:]
            gy1 = int(self.unpadData(data))
            # calc shared key with OR1
            sk1 = pow(gy1, x1, p)
            hsk1 = sha256(str(sk1).encode())
            # save in global list
            hsk.append(hsk1)
            # calc gx2
            gx2 = pow(g, x2, p)
            # encypt gx2 using routers public key
            pubKey = RSA.importKey(circuit[1][1])
            cipher = PKCS1_OAEP.new(pubKey)
            cipherText = cipher.encrypt(str(gx2).encode())
            # send addr of next hop
            addr = circuit[1][0].encode()
            # pad addr with '\0' till 21 bytes
            nonce = get_random_bytes(8)
            nonces.append(sha256(nonce))
            data = (nonce
                    + self.padData(21, addr)
                    + cipherText)
            paddedData = self.padData(498, data)
            # StreamID + Digest + Len + CMD + DATA
            streamID = get_random_bytes(2)
            digest = hsk[0].digest()[0:6]
            length = len(data).to_bytes(2, sys.byteorder)
            relayHeader = (streamID
                           + digest
                           + length
                           + b'\x04'
                           + paddedData)
            # encrypt relayHeader
            cipherText = self.encryptAES(hsk[0], nonces[0], relayHeader)
            # send relay msg
            msg = (circID
                   + b'\x03'
                   + cipherText)
            ssocket.send(msg)
            # update digest
            hsk[0].update(relayHeader)
            nonces[0].update(relayHeader)
            
            # recv relay back
            msg = ssocket.recv(512)
            cmd = msg[2:3]
            data = msg[3:]
            # relay
            if cmd == b'\x03':
                # decrypt data using shared key
                relayHeader = self.decryptAES(hsk[0], nonces[0], data)
                streamID = relayHeader[0:2]
                digest = relayHeader[2:8]
                length = int.from_bytes(relayHeader[8:10], sys.byteorder)
                cmd = relayHeader[10:11]
                data = relayHeader[11:length+11]
                # auth
                if hsk[0].digest()[0:6] == digest:
                    # extended
                    if cmd == b'\x05':
                        # calc shared key with OR2
                        gy2 = data
                        sk2 = pow(int(gy2), x2, p)
                        hsk2 = sha256(str(sk2).encode())
                        # save in global list
                        hsk.append(hsk2)
                        # calc gx3
                        gx3 = pow(g, x3, p)
                        # encypt gx3 using routers public key
                        pubKey = RSA.importKey(circuit[2][1])
                        cipher = PKCS1_OAEP.new(pubKey)
                        cipherText = cipher.encrypt(str(gx3).encode())
                        # send addr of next hop
                        addr = circuit[2][0].encode()
                        # pad addr with '\0' till 21 bytes
                        nonce = get_random_bytes(8)
                        nonces.append(sha256(nonce))
                        data = (nonce 
                                + self.padData(21, addr)
                                + cipherText)
                        paddedData = self.padData(498, data)
                        # StreamID + Digest + Len + CMD + DATA
                        streamID = get_random_bytes(2)
                        digest = hsk[1].digest()[0:6]
                        length = len(data).to_bytes(2, sys.byteorder)
                        relayHeader = (streamID
                                       + digest
                                       + length
                                       + b'\x04'
                                       + paddedData)
                        data = relayHeader
                        # encrypt data using shared key(s)
                        i = 1
                        for x in reversed(hsk):
                            data = self.encryptAES(x, nonces[i], data)
                            i = i - 1
                        # send relay msg
                        msg = (circID
                               + b'\x03'
                               + data)
                        ssocket.send(msg)
                        # update digest
                        hsk[1].update(relayHeader)
                        nonces[1].update(relayHeader)
                        
                        # recv relay back
                        msg = ssocket.recv(512)
                        cmd = msg[2:3]
                        # relay
                        if cmd == b'\x03':
                            relayHeader = msg[3:]
                            # decrypt relayHeader using shared key(s)
                            for j in range(len(hsk)):
                                relayHeader = self.decryptAES(hsk[j], nonces[j], relayHeader)
                            streamID = relayHeader[0:2]
                            digest = relayHeader[2:8]
                            length = int.from_bytes(relayHeader[8:10], sys.byteorder)
                            cmd = relayHeader[10:11]
                            data = relayHeader[11:length+11]
                            if hsk[1].digest()[0:6] == digest:
                                # extended
                                if cmd == b'\x05':
                                    # calc shared key with OR3
                                    gy3 = data
                                    sk3 = pow(int(gy3), x3, p)
                                    hsk3 = sha256(str(sk3).encode())
                                    # save in global list
                                    hsk.append(hsk3)
        return circID, hsk, nonces, ssocket 


    def destroyCircuit(self, circID, hsk, nonces, ssocket):
        # StreamID + Digest + Len + CMD + DATA
        streamID = get_random_bytes(2)
        digest = hsk[2].digest()[0:6]
        length = get_random_bytes(2)
        relayHeader = (streamID
                       + digest
                       + length
                       + b'\x09'
                       + self.padData(498, b''))
        data = relayHeader
        # encrypt relayHeader using shared key(s)
        n = 2
        for x in reversed(hsk):
            data = self.encryptAES(x, nonces[n], data)
            n = n - 1
        msg = (circID
               + b'\x03'
               + data)
        ssocket.send(msg)
        # update digest
        hsk[2].update(relayHeader)
        nonces[2].update(relayHeader)
        
        # recv message
        msg = ssocket.recv(512)
        relayHeader = msg[3:]
        # decrypt relayHeader using shared key(s)
        for l in range(len(hsk)):
            relayHeader = self.decryptAES(hsk[l], nonces[l], relayHeader)
        streamID = relayHeader[0:2]
        digest = relayHeader[2:8]
        length = int.from_bytes(relayHeader[8:10], sys.byteorder)
        cmd = relayHeader[10:11]
        data = relayHeader[11:length+11]
        if hsk[2].digest()[0:6] == digest:
            # pop values
            hsk.pop()
            nonces.pop()
            # StreamID + Digest + Len + CMD + DATA
            streamID = get_random_bytes(2)
            digest = hsk[1].digest()[0:6]
            length = get_random_bytes(2)
            relayHeader = (streamID
                           + digest
                           + length
                           + b'\x09'
                           + self.padData(498, b''))
            data = relayHeader
            # encrypt relayHeader using shared key(s)
            n = 1
            for x in reversed(hsk):
                data = self.encryptAES(x, nonces[n], data)
                n = n - 1
            msg = (circID
                   + b'\x03'
                   + data)
            ssocket.send(msg)
            # update digest
            hsk[1].update(relayHeader)
            nonces[1].update(relayHeader)
            
            # recv message
            msg = ssocket.recv(512)
            relayHeader = msg[3:]
            # decrypt relayHeader using shared key(s)
            for l in range(len(hsk)):
                relayHeader = self.decryptAES(hsk[l], nonces[l], relayHeader)
            streamID = relayHeader[0:2]
            digest = relayHeader[2:8]
            length = int.from_bytes(relayHeader[8:10], sys.byteorder)
            cmd = relayHeader[10:11]
            data = relayHeader[11:length+11]
            # auth
            if hsk[1].digest()[0:6] == digest:
                # pop values
                hsk.pop()
                nonces.pop()
                # StreamID + Digest + Len + CMD + DATA
                streamID = get_random_bytes(2)
                digest = hsk[0].digest()[0:6]
                length = get_random_bytes(2)
                relayHeader = (streamID
                               + digest
                               + length
                               + b'\x09'
                               + self.padData(498, b''))
                data = relayHeader
                # encrypt relayHeader using shared key(s)
                n = 0
                for x in reversed(hsk):
                    data = self.encryptAES(x, nonces[n], data)
                    n = n - 1
                msg = (circID
                       + b'\x03'
                       + data)
                ssocket.send(msg)
                # update digest
                hsk[0].update(relayHeader)
                nonces[0].update(relayHeader)
                
                # recv message
                msg = ssocket.recv(512)
                relayHeader = msg[3:]
                # decrypt relayHeader using shared key(s)
                for l in range(len(hsk)):
                    relayHeader = self.decryptAES(hsk[l], nonces[l], relayHeader)
                streamID = relayHeader[0:2]
                digest = relayHeader[2:8]
                length = int.from_bytes(relayHeader[8:10], sys.byteorder)
                cmd = relayHeader[10:11]
                data = relayHeader[11:length+11]
                if hsk[0].digest()[0:6] == digest:
                    # pop values
                    hsk.pop()
                    nonces.pop()
                    ssocket.close()
                    print('Circuit closed.')
        return None


    def exchangeData(self, circID, hsk, nonces, connection, ssocket):
        while True:
            # wait until connection or server is available for read
            r, w, e = select([connection, ssocket], [], [])
            # from browser
            if connection in r:
                try:
                    data = connection.recv(498)
                    if len(data) <= 0: break
                    paddedData = self.padData(498, data)
                    # StreamID + Digest + Len + CMD + DATA
                    streamID = get_random_bytes(2)
                    digest = hsk[2].digest()[0:6]
                    length = len(data).to_bytes(2, sys.byteorder)
                    relayHeader = (streamID
                                   + digest
                                   + length
                                   + b'\x08'
                                   + paddedData)
                    data = relayHeader
                    # encrypt relayHeader using shared key(s)
                    i = 2
                    for x in reversed(hsk):
                        data = self.encryptAES(x, nonces[i], data)
                        i = i - 1
                    msg = (circID
                           + b'\x03'
                           + data)
                    # update digest
                    hsk[2].update(relayHeader)
                    nonces[2].update(relayHeader)
                    # send to server
                    ssocket.send(msg)
                except ConnectionResetError:
                    break
            # from server
            if ssocket in r:
                try:
                    data = ssocket.recv(512)
                    if len(data) <= 0: break
                    relayHeader = data[3:]
                    # decrypt relayHeader using shared key(s)
                    for m in range(len(hsk)):
                        relayHeader = self.decryptAES(hsk[m], nonces[m], relayHeader)
                    streamID = relayHeader[0:2]
                    digest = relayHeader[2:8]
                    length = int.from_bytes(relayHeader[8:10], sys.byteorder)
                    cmd = relayHeader[10:11]
                    data = relayHeader[11:length+11]
                    if hsk[2].digest()[0:6] == digest:
                        # send to browser
                        connection.send(data)
                except (ConnectionResetError, BrokenPipeError):
                    break
        return None


    def handleClient(self, connection, address):
        print('New connection - {}'.format(address))
        # recv header
        header = connection.recv(2)
        version = int.from_bytes(header[0:1], sys.byteorder)
        nmethods = int.from_bytes(header[1:2], sys.byteorder)
        
        # socks 5
        assert version == SOCKS_VERSION
        assert nmethods > 0
        
        # get available methods
        methods = []
        for i in range(nmethods):
            methods.append(ord(connection.recv(1)))
        
        # accept only USERNAME/PASSWORD auth 2
        if 2 not in set(methods):
            # close connection
            connection.close()
            return
        
        # send welcome message
        msg = version.to_bytes(1, sys.byteorder) + (2).to_bytes(1, sys.byteorder)
        connection.send(msg)
        # authenticate response
        if not self.authenticateConnection(connection):
            return
        
        # recv request
        request = connection.recv(4)
        version = int.from_bytes(request[0:1], sys.byteorder)
        cmd = int.from_bytes(request[1:2], sys.byteorder)
        rsv = int.from_bytes(request[2:3], sys.byteorder)
        addressType = int.from_bytes(request[3:4], sys.byteorder)
        assert version == SOCKS_VERSION
        # continue based on address type
        if addressType == 1:  # IPv4
            address = socket.inet_ntoa(connection.recv(4))
        elif addressType == 3:  # Domain name
            domainLength = connection.recv(1)[0]
            address = connection.recv(domainLength)
            address = socket.gethostbyname(address)
        # this one must be big to work
        port = int.from_bytes(connection.recv(2), 'big')
        # respond
        try:
            if cmd == 1:  # CONNECT
                # get onions routers
                routers = self.getRouters()
                # create circuit
                circID, hsk, nonces, ssocket = self.createCircuit(routers)
                # get correct address from socket
                bindAddress = ssocket.getsockname()
                # send begin
                data = ('{}:{}'.format(address, port)).encode()
                paddedData = self.padData(498, data)
                # StreamID + Digest + Len + CMD + DATA
                streamID = get_random_bytes(2)
                digest = hsk[2].digest()[0:6]
                length = len(data).to_bytes(2, sys.byteorder)
                relayHeader = (streamID
                               + digest
                               + length
                               + b'\x06'
                               + paddedData)
                data = relayHeader
                # encrypt using shared key(s)
                i = 2
                for x in reversed(hsk):
                    data = self.encryptAES(x, nonces[i], data)
                    i = i - 1
                msg = (circID
                       + b'\x03'
                       + data)
                ssocket.send(msg)
                # update digest
                hsk[2].update(relayHeader)
                nonces[2].update(relayHeader)
                
                # recv message
                msg = ssocket.recv(512)
                relayHeader = msg[3:]
                # decrypt relayHeader using shared key(s)
                for j in range(len(hsk)):
                    relayHeader = self.decryptAES(hsk[j], nonces[j], relayHeader)
                streamID = relayHeader[0:2]
                digest = relayHeader[2:8]
                length = int.from_bytes(relayHeader[8:10], sys.byteorder)
                command = relayHeader[10:11]
                data = relayHeader[11:length+11]
                # auth
                if hsk[2].digest()[0:6] == digest:
                    print('Connected to {} {}'.format(address, port))
                else:
                    connection.close()
                    return
            addr = socket.inet_aton(bindAddress[0])
            port = (bindAddress[1]).to_bytes(2, sys.byteorder)
            msg = ((SOCKS_VERSION).to_bytes(1, sys.byteorder)
                   + b'\x00'
                   + b'\x00'
                   + b'\x01'
                   + addr
                   + port)
        except Exception:
            connection.close()
            return
        # send 
        connection.send(msg)
        
        # establish data exchange
        if msg[1] == 0 and cmd == 1:
            self.exchangeData(circID, hsk, nonces, connection, ssocket)
        
        # destory circuit
        self.destroyCircuit(circID, hsk, nonces, ssocket)
        # close connection
        print('Closing connection to {}'.format(address))
        connection.close()
        return None


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
        return None


def main(ip, port):
    op = OP(ip, port)
    op.listen()
    return None


if __name__ == '__main__':
    ip = sys.argv[1]
    port = sys.argv[2]
    main(ip, port)
