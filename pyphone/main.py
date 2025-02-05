

from datetime import datetime
from dataclasses import dataclass
import uuid
from typing import List, TypedDict

from pyphone.transport import TransportAddr, TransportConfig, Transport, Address
from pyphone.utils import console, log

from rich.panel import Panel



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


@dataclass
class UserAgent:
    username: str
    password: str
    domain: str
    port: int = 5060
    transport: str = 'udp'
    display_name: str = None
    contact: str = None
    expires: int = 3600
    realm: str = None
    conn_cfg: TransportConfig = None

class Session:
    def __init__(self, transport_cfg: TransportConfig):
        self.cfg = transport_cfg
        self._transport = Transport(transport_cfg, self.handle_data)
        self._dialogs = []
    
    
    def handle_data(self, data: bytes, addr: TransportAddr):
        log.info(f"Received data from {addr}:\n")
        log.debug(Panel(
            data.decode(),
            title="Received data from {addr}",
            subtitle=f"{len(data)} bytes"))
    
    def _generate_branch(self):
        return f'z9hG4bK{str(uuid.uuid4())[:8]}'
    
    def _generate_call_id(self):
        return str(uuid.uuid4())
    
    def _generate_tag(self):
        return str(uuid.uuid4())[:4]

    def _generate_uri(
            self,
            addr: Address,
            tag: bool = False,
            branch: bool = False,
            rport: bool = False,
            extra_params: dict = None,
            ):
        
        uri = f'sip:{addr.addr}'
        if addr.port:
            uri += f':{addr.port}'
        if tag:
            uri += f';tag={self._generate_tag()}'
        if rport:
            uri += f';rport'
        if branch:
            uri += f';branch={self._generate_branch()}'
        for k, v in extra_params.items() if extra_params else {}:
            if v:
                uri += f';{k}={v}'
                continue
            uri += f';{k}'
        return uri
    
    def options(self, ua: UserAgent = None, extra_headers: list[tuple[str, str]] = None):
        
        msg = (
            f'OPTIONS {self._generate_uri(Address(*self.cfg.local_addr), branch=True)} SIP/2.0\r\n'
            f'Via: SIP/2.0/{self.cfg.protocol} {self._generate_uri(Address(*self.cfg.local_addr), branch=True)}\r\n'
            f'From: {self._generate_uri(Address(*self.cfg.local_addr), tag=True)}\r\n'
            f'To: {self._generate_uri(Address(*self.cfg.target_addr))}\r\n'
            f'Call-ID: {self._generate_call_id()}\r\n'
            f'CSeq: 1 OPTIONS\r\n'
            f'Max-Forwards: 70\r\n'
            f'Content-Length: 0\r\n'
            '\r\n'
        )

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

    
    