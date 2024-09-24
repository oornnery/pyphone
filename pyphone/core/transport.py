import socket
import threading
from typing import Callable
from dataclasses import dataclass, field
from enum import Enum



class PeerType(Enum):
    UDP = 'udp'
    TCP = 'tcp'
    TLS = 'tls'
    WS = 'ws'


@dataclass
class CfgTransport:
    protocol: PeerType
    local_address: str
    local_port: str
    public_address: str
    public_port: str
    buffer_size: int = field(default=1024)


class Transport:
    def __init__(self, cfg: CfgTransport, callback: Callable):
        self.callback = None
        self.cfg = None

    def start(self):
        transport = socket.SOCK_DGRAM if self.cfg.protocol == 'udp' else socket.SOCK_STREAM
        self.sock = socket.socket(socket.AF_INET, transport)
        self.sock.bind(('', 0))
        self.t1 = threading.Thread(target=self.receive)
        self.t1.start()
        print(f'Started UDP listener on {self.sock.getsockname()}')
    
    def receive(self):
        while True:
            data, addr = self.sock.recvfrom(self.t.buffer_size)
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



