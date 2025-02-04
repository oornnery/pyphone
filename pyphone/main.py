

import socket
import threading
from datetime import datetime
from typing import List, TypedDict



message = {
    'first_line': '',
    'via': [],
    'from': '',
    'to': '',
    'call_id': '',
    'cseq': '',
    'contact': '',
    'content_type': '',
    'extra_headers': {},
    'body': ''
}

class Transport:
    def __init__(self, protocol: str, local_addr: tuple, remote_addr: tuple, callback: callable, timeout: int=5, bufsize: int=4096):
        self.protocol = protocol
        self.local_addr = local_addr
        self.remote_addr = remote_addr
        self.timeout = timeout
        self.bufsize = bufsize
        self.callback = callback
        self.running = False
        self.sock = None
        self._thread = None

    def _create_socket(self) -> socket.socket:
        _sock_type = socket.SOCK_DGRAM if self.protocol.lower() == 'udp' else socket.SOCK_STREAM
        sock = socket.socket(socket.AF_INET, _sock_type)
        # Allow reusing the same address
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(self.timeout)
        # Listen for incoming connections
        sock.bind(self.local_addr)
        if self.protocol.lower() == 'tcp':
            sock.listen(5)
        return sock

    def send(self, data, addr=None):
        self.sock.connect(addr or self.remote_addr)
        self.sock.sendall(data)
    
    def _received_loop(self):
        while self.running:
            try:
                if self.protocol.lower() == 'udp':
                    data, addr = self.sock.recvfrom(self.bufsize)
                    self.callback(data, addr)
                elif self.protocol.lower() == 'tcp':
                    conn, addr = self.sock.accept()
                    with conn:
                        while self.running:
                            data = conn.recv(self.bufsize)
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


class Message:
    def __init__(
            self,
            first_line: str,
            headers: dict,
            body: dict
        ):
        self._first_line = first_line
        self._headers = headers
        self._body = body
    
    def get(self, key, default=None):
        return self.headers.get(key, default)
    
    def add(self, key, value):
        self.headers[key] = value
    
    def is_request(self):
        return self._first_line.startswith('SIP/2.0')
    
    def is_response(self):
        return self._first_line.endswith('SIP/2.0')

    def from_string(self, s: str):
        pass
    
    def to_bytes(self):
        pass
    
    def to_summary(self):
        pass


class Request(Message): ...

class Response(Message): ...

class Transaction:
    def __init__(self, m: Message):
        self.messages: List[Message] = [m]
        self.branch = m.branch
        self.status = None

    def on_transaction_update(self, m: Message):
        self.messages.append(m)
        if isinstance(m, Request):
            self.status = 'trying'
        elif isinstance(m, Response):
            if m.status_code > 100 and m.status_code < 200:
                self.status = 'connecting'
            elif m.status_code >= 200 and m.status_code < 300:
                self.status = 'completed'
            elif m.status_code >= 300 and m.status_code < 400:
                self.status = 'redirected'
            elif m.status_code >= 400 and m.status_code < 500:
                self.status = 'terminated'
            elif m.status_code >= 500 and m.status_code < 600:
                self.status = 'server_error'
            else:
                self.status = 'unknown' 
        else:
            self.status = 'unknown'

class Dialog:
    _started_at = None
    _ended_at = None
    
    def __init__(self, tr: Transaction):
        self.tr = tr
        self.transactions: List[Transaction] = []
    
    @property
    def started_at(self):
        if not self._started_at:
            self._started_at = datetime.now().timestamp()
        return self._started_at
    
    @property
    def ended_at(self):
        if not self._ended_at:
            self._ended_at = datetime.now().timestamp()
        return self._ended_at

    async def on_dialog_update(self, m: Message):
        for _tr in self.transactions:
            if _tr.branch == m.branch:
                tr = _tr
        else:
            tr = Transaction(m)
            self.transactions.append(tr)
        await tr.on_transaction_update(m)
    def re_invite(self):
        pass
    
    def ack(self):
        pass
    
    def bye(self):
        pass
    
    def cancel(self):
        pass
    

if __name__ == '__main__':
    import time
    
    def callback(data, addr):
        print(f'\nReceived from: {addr}\n')
        print(data)
    
    local_addr = ('0.0.0.0', 10080)
    remote_addr = ('demo.mizu-voip.com', 37075)
    remote_uri = f'sip:{remote_addr[0]}:{remote_addr[1]}'
    via_uri = f'sip:{local_addr[0]}:{local_addr[1]}'
    from_uri = f'sip:anonymous@{local_addr[0]}'
    to_uri = 'sip:demo.mizu-voip.com:37075'
    message = (
        f'OPTIONS sip:{remote_addr[0]} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP {via_uri};rport;branch=z9hG4bK1234567890\r\n'
        f'From: <{from_uri}>\r\n'
        f'To: <{to_uri}>\r\n'
        'Call-ID: 1234567890\r\n'
        'CSeq: 1 OPTIONS\r\n'
        'Max-Forwards: 70\r\n'
        f'Content-Length: 0\r\n'
        '\r\n'
    )
    
    tp = Transport('udp', local_addr, remote_addr, callback)
    tp.start()
    
    tp.send(message.encode())
    time.sleep(5)
    tp.stop()
    
    