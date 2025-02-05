

from datetime import datetime
from dataclasses import dataclass
import uuid
from typing import List, TypedDict

from transport import TransportAddr, TransportConfig, Transport
from utils import console, log

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
    domain: str
    port: int = 5060
    login: str = None
    password: str = None
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
        self._running = False
    
    def handle_data(self, data: bytes, addr: TransportAddr):
        log.info(f"Received data from {addr}:\n")
        console.print(Panel(
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
            addr: str,
            port: int = None,
            tag: bool = False,
            _tag: str = None,
            branch: bool = False,
            branch_default: str = None,
            rport: bool = False,
            bracket: bool = False,
            extra_params: dict = None,
            ):
        
        uri = f'sip:{addr}'
        if port and port != 0:
            uri += f':{port}'
        if tag:
            uri += f';tag={_tag or self._generate_tag()}'
        if rport:
            uri += f';rport'
        if branch:
            uri += f';branch={branch_default or self._generate_branch()}'
        for k, v in extra_params.items() if extra_params else {}:
            if v:
                uri += f';{k}={v}'
                continue
            uri += f';{k}'
        if bracket:
            uri = f'<{uri}>'
        return uri
    
    def request(self, method: str, ua: UserAgent = None, branch: str = None, extra_headers: list[tuple[str, str]] = None):
        for d in self._dialogs:
            if d.tr.branch == branch:
                dialog = d
        if not dialog:
            dialog = Dialog(Transaction(Request()))
            self._dialogs.append(dialog)
        
        msg = (
            f'{method.upper()} {self._generate_uri(addr=ua.domain, port=ua.port)} SIP/2.0\r\n'
            f'Via: SIP/2.0/{self.cfg.protocol} {self._generate_uri(addr=self.cfg.local_addr[0], port=self.cfg.local_addr[1], branch=True)}\r\n'
            f'From: {self._generate_uri(addr=self.cfg.local_addr[0], port=self.cfg.local_addr[1], tag=True, bracket=True)}\r\n'
            f'To: {self._generate_uri(addr=ua.domain, port=ua.port, bracket=True)}\r\n'
            f'Call-ID: {self._generate_call_id()}\r\n'
            f'CSeq: 1 {method.upper()}\r\n'
            f'Max-Forwards: 70\r\n'
            f'Content-Length: 0\r\n'
            # f'{k}: {v}\r\n' for k, v in extra_headers if extra_headers else []
            '\r\n'
        )
        
        self._transport.send(msg.encode(), (ua.domain, ua.port))

    def start(self):
        self._transport.start()
        self._running = True
        
    def stop(self):
        self._transport.stop()
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()
        self._running = False
    

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
    
    with Session(cfg) as s:
        for x in range(5):
            s.request(
                method='OPTIONS',
                ua=UserAgent(
                    username='ping-pong',
                    domain='demo.mizu-voip.com',
                    port=37075,
                    transport='udp',
                    ))
            time.sleep(1)

    
    