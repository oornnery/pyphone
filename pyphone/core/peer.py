import socket
import threading
from typing import Callable
from enum import Enum



class PeerType(Enum):
    UDP = 'udp'
    TCP = 'tcp'
    TLS = 'tls'
    WS = 'ws'



class Peer:
    def __init__(self, transport, callback: Callable):
        self.callback = callback
        self.transport = transport

    def start(self):
        transport = socket.SOCK_DGRAM if self.transport.protocol.value == 'udp' else socket.SOCK_STREAM
        self.sock = socket.socket(socket.AF_INET, transport)
        self.sock.bind(('', 0))
        self.t1 = threading.Thread(target=self.receive)
        self.t1.start()
        print(f'Started UDP listener on {self.sock.getsockname()}')
    
    def receive(self):
        while True:
            data, addr = self.sock.recvfrom(self.transport.buffer_size)
            self.callback(data, addr)
            print(f'Received {len(data)} bytes | from {addr}')

    def send(self, data, addr):
        self.s.sendto(data, addr)
        print(f'Sent {len(data)} bytes | to {addr}')

    def stop(self):
        self.t1.join()
        self.s.close()
        print(f'Stopped {self.cfg.protocol} listener')

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop



