import socket
import threading
from typing import Callable, Tuple, Literal, AnyStr
from dataclasses import dataclass

from pyphone.utils import log, console

TransportProtocol = Literal['udp', 'tcp']
TransportAddr = Tuple[str, int]

@dataclass
class ConnectionConfig:
    target_addr: TransportAddr
    protocol: TransportProtocol
    local_addr: TransportAddr = ('0.0.0.0', 0)
    buffer_size: int = 4096
    timeout: float = 5.0

class Connection:
    def __init__(self, config: ConnectionConfig, callback: Callable):
        self.config = config
        self.callback = callback
        self.socket = None
        self.running = False
        self._thread = None

    def start(self):
        if self.config.protocol == 'udp':
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(self.config.local_addr)
        self.socket.settimeout(self.config.timeout)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        if self.config.protocol == 'tcp':
            self.socket.listen(1)
        
        self.running = True
        self.thread = threading.Thread(target=self._receive_loop)
        self.thread.start()
        log.info(f"Started {self.config.protocol.upper()} connection on {self.config.local_addr}")

    def _receive_loop(self):
        while self.running:
            try:
                if self.config.protocol == 'udp':
                    data, addr = self.socket.recvfrom(self.config.buffer_size)
                else:
                    conn, addr = self.socket.accept()
                    data = conn.recv(self.config.buffer_size)
                    conn.close()

                log.debug(f"Received data from {addr}: bytes {len(data)}")
                self.callback(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                log.warning(f"Error in receive loop: {e}")
                continue

    def send(self, data: AnyStr):
        try:
            log.debug(f"Sending data to {self.config.target_addr}: \n{data}")
            if isinstance(data, str):
                data = data.encode()
            if self.config.protocol == 'udp':
                self.socket.sendto(data, self.config.target_addr)
            else:
                with socket.create_connection(self.config.target_addr, timeout=self.config.timeout) as conn:
                    conn.sendall(data)
            log.debug(f"Sent data to {self.config.target_addr}: bytes {len(data)}")
        except Exception as e:
            log.error(f"Error sending data: {e}")

    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()
        if self.thread:
            self.thread.join()
        log.info(f"Stopped {self.config.protocol.upper()} connection on {self.config.local_addr}")



# Exemplo de uso
if __name__ == '__main__':
    import re
    


    def split_sip_message(data: AnyStr) -> tuple[dict, dict]:
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
        console.print(f"\nReceived data from {addr}:")
        # console.print(data.decode())
        message = split_sip_message(data.decode())
        console.print(message)
        
    # Criar conexão UDP
    cfg = ConnectionConfig(
        target_addr=('demo.mizu-voip.com', 37075),
        protocol='udp',
        local_addr=('0.0.0.0', 5001)
    )
    conn = Connection(cfg, handle_data)
    conn.start()

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
    
    message = (
        'OPTIONS sip:siptrunkbr.net2phone.com SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP {cfg.local_addr[0]};rport;branch=z9hG4bK1234567890\r\n'
        'From: <sip:ping@localhost>\r\n'
        'To: <sip:siptrunkbr.net2phone.com>\r\n'
        'Call-ID: 1234567890\r\n'
        'CSeq: 1 OPTIONS\r\n'
        'Max-Forwards: 70\r\n'
        f'Content-Length: {len(sdp)}\r\n'
        'Content-Type: application/sdp\r\n'
        '\r\n'
        f'{sdp}'
    )
    console.print(split_sip_message(message))
    # Enviar dados
    conn.send(message)
    
    # Manter o programa rodando por um tempo
    import time
    time.sleep(10)

    # Fechar conexões
    conn.stop()
