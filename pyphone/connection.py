from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Callable, Tuple
import socket
import threading


class ProtocolType(Enum):
    UDP = auto()
    TCP = auto()
    TLS = auto()


@dataclass
class ConnectionConfig:
    local_address: str = field(default='0.0.0.0')
    local_port: int = field(default=5060)
    public_address: str = field(default='0.0.0.0')
    public_port: int = field(default=10060)
    protocol: ProtocolType = field(default=ProtocolType.UDP)
    buffer_size: int = field(default=4096)
    reliable: bool = field(default=False)
    congestion_controlled: bool = field(default=False)



class Connection(threading.Thread):
    def __init__(self, config: ConnectionConfig, targe_address: Tuple[str, int], callback: Callable):
        self.config = config
        self.target_address = targe_address
        self.callback = callback
        self._socket = None
        self._recv_thread = None
        self._is_running = False
        self.daemon = True
        self.start()
        
    
    @property
    def session_id(self):
        return self._session_id
    
    @session_id.setter
    def session_id(self, value):
        self._session_id = value

    def start(self):
        try:
            sock_type = socket.SOCK_STREAM if self.config.protocol in (ProtocolType.TCP, ProtocolType.TLS) else socket.SOCK_DGRAM
            self._socket = socket.socket(socket.AF_INET, sock_type)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind(self.target_address)
            if self.config.protocol in (ProtocolType.TCP, ProtocolType.TLS):
                self._socket.listen()
            self._is_running = True
            self.receive()
        except Exception as e:
            self.stop()
            raise e
    
    def send(self, data: bytes, targe_address: Tuple[str, int] = None):
        try:
            if isinstance(data, str):
                data = data.encode()
            if self.config.protocol in (ProtocolType.TCP, ProtocolType.TLS):
                self._socket.send(data)
            else:
                self._socket.sendto(data, targe_address or self.target_address)
        except Exception as e:
            raise RuntimeError(f"Error sending data: {e} to {targe_address or self.target_address}")
    
    def receive(self):
        if not self._socket:
            raise Exception("Socket not initialized")
        while self._is_running:
            try:
                if self.config.protocol in (ProtocolType.TCP, ProtocolType.TLS):
                    conn, addr = self._socket.accept()
                    try:
                        with conn:
                            data = conn.recv(self.config.buffer_size)
                    except Exception:
                        pass
                else:
                    data, addr = self._socket.recvfrom(self.config.buffer_size)
                self.callback(data, addr)
            except Exception as e:
                raise RuntimeError(f"Error receiving data: {e}")
    
    def stop(self):
        self._is_running = False
        if self._socket:
            try:
                self._socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self._socket.close()
        self._socket = None
        self.join()
