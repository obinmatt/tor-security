import socket, pickle

PORT = 9000
SERVER = 'localhost'

ROUTERS = {}

def listen():
  ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  ssocket.bind((SERVER, PORT))
  ssocket.listen()
  print('Directory is listening on {}:{}'.format(SERVER, PORT))
  while True:
    connection, address = ssocket.accept()
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
  return

def main():
  listen()

if __name__ == '__main__':
  main()