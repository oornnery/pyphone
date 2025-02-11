import socket
import threading
from dataclasses import dataclass
from typing import Callable

@dataclass
class ConnCfg:
    remote_addr: str
    remote_port: int
    local_addr: str = '0.0.0.0'
    local_port: int = 0
    protocol: str = "UDP"
    recv_buf: int = 4096


class ConnectionHandler:
    def __init__(self, cfg: ConnCfg, callback: Callable):
        self.cfg = cfg
        self.callback = callback
        self.receive_thread = None
        self.running = False
        self.conn = None

    def _create_connection(self, cfg: ConnCfg, callback: Callable):
        sck_type = socket.SOCK_DGRAM if cfg.protocol == "UDP" else socket.SOCK_STREAM
        conn = socket.socket(socket.AF_INET, sck_type)
        # Set socket options
        conn.setblocking(False)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, cfg.recv_buf)
        conn.bind((cfg.local_addr, cfg.local_port))
        conn.connect_ex((cfg.remote_addr, cfg.remote_port))
        if cfg.protocol == "TCP":
            conn.listen(5)
        self.conn = conn

    def start(self):
        self._create_connection(self.cfg, self.callback)
        self.running = True
        self.receive_thread = threading.Thread(target=self.receive_loop)
        self.receive_thread.start()

    def stop(self):
        self.running = False
        self.receive_thread.join()
    
    def send(self, data: bytes):
        self.conn.send(data)

    def receive_loop(self):
        while self.running:
            try:
                if self.cfg.protocol == "UDP":
                    data, addr = self.conn.recvfrom(self.cfg.recv_buf)
                    self.callback(data, addr)
                elif self.cfg.protocol == "TCP":
                    # callback tcp with data and addr
                    conn = self.conn.accept()
                    with conn:
                        data = conn.recv(self.cfg.recv_buf)
                        self.callback(data, conn)
            except BlockingIOError:
                # No data available at the moment
                pass
            except Exception as e:
                print(f"Error in receive_loop: {e}")
                break
        # self.remove_connection(self.connections[idx])

