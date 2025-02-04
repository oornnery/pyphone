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
            

# Exemplo de uso
if __name__ == '__main__':
    import re
    import time
    
    def split_sip_message(data) -> tuple[dict, dict]:
            parts = re.split(r'\r\n\r\n|\n\n', data, maxsplit=1)
            first_line = str(parts[0].split('\r\n')[0]).strip()
            _header = list(x for x in parts[0].split('\r\n')[1:])
            _body = list(x for x in (parts[1] if len(parts) > 1 else '').split('\r\n'))
            
            header = {}
            body = {}
            
            for i, line in enumerate(_header):
                values = line.split(':', 1)
                header[i] = [v.strip() for v in values if v]
            
            for i, line in enumerate(_body) if len(_body) > 1 else []:
                values = line.split('=', 1)
                if len(values) <= 1:
                    continue
                body[i] = [v.strip() for v in values if v]
                
            return first_line, header, body

    def handle_data(data: bytes, addr: TransportAddr):
        console.print(f"\nReceived data from {addr}:\n")
        console.print(data.decode())
        # console.print("\nParsed message:\n")
        # message = split_sip_message(data.decode())
        # console.print(message)
        
    # Criar conexão UDP
    cfg = TransportConfig(
        target_addr=('demo.mizu-voip.com', 37075),
        protocol='udp',
    )

    sdp = (
        'v=0\r\n'
        f'o=- 0 0 IN IP4 {cfg.local_addr[0]}\r\n'
        's=session\r\n'
        f'c=IN IP4 {cfg.local_addr[0]}\r\n'
        't=0 0\r\n'
        'm=audio 5002 RTP/AVP 9 0 8 18 101\r\n'
        'a=rtpmap:0 PCMU/8000\r\n'
        'a=rtpmap:0 PCMA/8000\r\n'
        'a=rtpmap:101 telephone-event/8000\r\n'
        'a=fmtp:101 0-16\r\n'
        'a=sendrecv\r\n'
    )
    
    remote_uri = f'sip:{cfg.target_addr[0]}:{cfg.target_addr[1]}'
    via_uri = f'sip:{cfg.local_addr[0]}:{cfg.local_addr[1]};rport;branch=z9hG4bK1234567890'
    from_uri = f'<sip:anonymous@{cfg.local_addr[0]}>'
    to_uri = f'<sip:{cfg.target_addr[0]}:{cfg.target_addr[1]}>'
    message = (
        f'OPTIONS sip:{cfg.target_addr[0]} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP {via_uri}\r\n'
        f'From: {from_uri}\r\n'
        f'To: {to_uri}\r\n'
        'Call-ID: 1234567890\r\n'
        'CSeq: 1 OPTIONS\r\n'
        'Max-Forwards: 70\r\n'
        f'Content-Length: 0\r\n'
        '\r\n'
    )
    with Transport(cfg, handle_data) as conn:
        for x in range(5):
            conn.send(message.encode(), cfg.target_addr)
            time.sleep(1)

