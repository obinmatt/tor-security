import socket, pickle

from router import Register, GetRouters

PORT = 9000
SERVER = 'localhost'

ROUTERS = {}

def listen():
  ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  ssocket.bind((SERVER, PORT))
  ssocket.listen()
  print(f'Directory is listening on {SERVER}:{PORT}')
  while True:
    connection, address = ssocket.accept()
    print(f'New connection from {address}')
    # recv message
    msg = connection.recv(4096)
    obj = pickle.loads(msg)
    objClass = obj.__class__.__name__
    if objClass == 'Register':
      addr = obj.addr
      pubKey = obj.pubKey
      # save router info
      ROUTERS.update({addr:pubKey})
      print(f'Router {addr} registered')
    elif objClass == 'GetRouters':
      data = pickle.dumps(ROUTERS)
      connection.send(data)
      print(f'{address} fetched routers')
    connection.close()
  return

def main():
  listen()

if __name__ == '__main__':
  main()