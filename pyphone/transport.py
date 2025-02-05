import socket
import threading
from typing import Callable, Tuple, Literal
from dataclasses import dataclass

from utils import log, console

TransportProtocol = Literal['udp', 'tcp']
TransportAddr = Tuple[str, int]

@dataclass
class TransportConfig:
    target_addr: TransportAddr
    local_addr: TransportAddr = ('0.0.0.0', 0)
    protocol: TransportProtocol = 'udp'
    buffer_size: int = 4096
    timeout: float = 5.0
    
    def __post_init__(self):
        self.protocol = self.protocol.lower()
        # TODO: Improve validation

class Transport:
    def __init__(self, cfg: TransportConfig, callback: Callable):
        self.cfg = cfg
        self.callback = callback
        self.running = False
        self.sock = None
        self._thread = None

    def _create_socket(self) -> socket.socket:
        _sock_type = socket.SOCK_DGRAM if self.cfg.protocol == 'udp' \
            else socket.SOCK_STREAM
        sock = socket.socket(socket.AF_INET, _sock_type)
        # Allow reusing the same address
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(self.cfg.timeout)
        # Listen for incoming connections
        sock.bind(self.cfg.local_addr)
        if self.cfg.protocol == 'tcp':
            sock.listen(5)
        return sock

    def send(self, data, addr=None):
        self.sock.connect(addr or self.cfg.remote_addr)
        self.sock.sendall(data)
    
    def _received_loop(self):
        while self.running:
            try:
                if self.cfg.protocol == 'udp':
                    data, addr = self.sock.recvfrom(self.cfg.buffer_size)
                    self.callback(data, addr)
                elif self.cfg.protocol == 'tcp':
                    conn, addr = self.sock.accept()
                    with conn:
                        while self.running:
                            data = conn.recv(self.cfg.buffer_size)
                            if not data:
                                break
                            self.callback(data, addr)
            except (ConnectionResetError, socket.timeout):
                pass
            except Exception as e:
                break
    
    def start(self):
        self.running = True
        self.sock = self._create_socket()
        self._thread = threading.Thread(target=self._received_loop)
        self._thread.start()
        
    
    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
            self.sock = None
        if self._thread:
            self._thread.join()
            self._thread = None
    
    def __del__(self):
        self.stop()
    
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()
            
