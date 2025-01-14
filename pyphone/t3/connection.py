import socket
import threading
from typing import Callable, Optional, Tuple, Union
from enum import Enum


class Protocol(Enum):
    TCP = 'tcp'
    UDP = 'udp'


class Connection:
    def __init__(
        self,
        address: str,
        port: int,
        protocol: Union[str, Protocol] = Protocol.UDP,
        callback: Optional[Callable[[bytes, Tuple[str, int]], None]] = None,
        buffer_size: int = 1024
    ):
        self.address = address
        self.port = port
        self.protocol = Protocol(protocol) if isinstance(protocol, str) else protocol
        self.callback = callback
        self.buffer_size = buffer_size
        self.sock: Optional[socket.socket] = None
        self.is_running = False
        self._recv_thread: Optional[threading.Thread] = None

    def start(self):
        try:
            sock_type = socket.SOCK_DGRAM if self.protocol == Protocol.UDP else socket.SOCK_STREAM
            self.sock = socket.socket(socket.AF_INET, sock_type)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.address, self.port))
            
            if self.protocol == Protocol.TCP:
                self.sock.listen(5)
            
            self.is_running = True
            self._recv_thread = threading.Thread(target=self._recv_loop)
            self._recv_thread.daemon = True  # Thread daemon para terminar com o programa principal
            self._recv_thread.start()
        
        except Exception as e:
            self.close()
            raise RuntimeError(f"Erro ao iniciar sessão: {e}")
    
    def close(self):
        self.is_running = False
        
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass  # Ignora erros de shutdown
            self.sock.close()
            self.sock = None
        
        if self._recv_thread and self._recv_thread.is_alive():
            self._recv_thread.join(timeout=1.0)  # Timeout para evitar bloqueio indefinido
        

    def send(self, data: Union[bytes, str], target_address: Optional[Tuple[str, int]] = None):
        if not self.sock:
            raise RuntimeError("Socket não inicializado")

        try:
            # Converte str para bytes se necessário
            if isinstance(data, str):
                data = data.encode()

            if self.protocol == Protocol.TCP:
                self.sock.send(data)
            else:
                addr = target_address or (self.address, self.port)
                self.sock.sendto(data, addr)
        
        except Exception as e:
            raise RuntimeError(f"Erro ao enviar dados: {e}")

    def _recv_loop(self):
        if not self.sock:
            return

        while self.is_running:
            try:
                if self.protocol == Protocol.TCP:
                    conn, addr = self.sock.accept()
                    try:
                        with conn:
                            data = conn.recv(self.buffer_size)
                            if data and self.callback:
                                self.callback(data, addr)
                    except Exception as e:
                        print(f"Erro na conexão TCP: {e}")
                else:
                    data, addr = self.sock.recvfrom(self.buffer_size)
                    if data and self.callback:
                        self.callback(data, addr)

            except Exception as e:
                if self.is_running:  # Só loga erro se ainda estiver rodando
                    print(f"Erro ao receber dados: {e}")

    def __enter__(self) -> 'Connection':
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()