import socket
import pickle
import ssl
import sys

PORT = NULL
SERVER = NULL
SERVER_CERT    = './path/to/cert'
SERVER_PRIVATE = './path/to/key'

ROUTERS = {}

def listen():
    # Set up the TLS context 
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain(SERVER_CERT, SERVER_PRIVATE, '4444')
    ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssocket.bind((SERVER, PORT))
    ssocket.listen()
    TLSsock = context.wrap_socket(ssocket, server_side=True)       #TLS handshake
    print('Directory is listening on {}:{}'.format(SERVER, PORT))
    while True:
        connection, address = TLSsock.accept()
        print('New connection from {}'.format(address))
        # recv message
        msg = connection.recv(4096)
        cmd = msg[0:1]
        if cmd == b'R':
            data = msg[1:]
            obj = pickle.loads(data)
            addr = '{}:{}'.format(obj['ip'], obj['port'])
            pubKey = obj['pubKey']
            # save router info
            ROUTERS.update({addr:pubKey})
            print('Router {} registered'.format(addr))
        elif cmd == b'G':
            data = pickle.dumps(ROUTERS)
            connection.send(data)
            print('{} fetched routers'.format(address))
        connection.close()
    return None


def main():
    listen()
    return None


if __name__ == '__main__':
    main()
