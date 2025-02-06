

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
            raw: str = None,
        ):
        self.raw = raw
        self.parser(raw)

    def get(self, key, default=None):
        return self.headers.get(key, default)
    
    def add(self, key, value):
        self.headers[key] = value
    
    def is_request(self):
        return self._first_line.startswith('SIP/2.0')
    
    def is_response(self):
        return self._first_line.endswith('SIP/2.0')

    def parser(self, s: str):
        pass
    
    def to_bytes(self):
        pass
    
    def to_summary(self):
        pass


class Request(Message): ...

class Response(Message): ...

class Transaction:
    def __init__(self, req: Request):
        self.req = req
        self.res: List[Response] = []
        self.status = None

    @property
    def branch(self):
        return re.findall(r'branch=(\w+)', self.req.get('Via'))
    
    def on_transaction_update(self, m: Message):
        self.res.append(m)
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

class Dialog:
    _started_at = None
    _ended_at = None
    _branch = None
    _local_tag = None
    _remote_tag = None
    _call_id = None
    
    def __init__(self):
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
    
    @property
    def branch(self):
        try:
            if self.transactions == []:
                return self._generate_branch()
            return self.transactions[0].branch
        except IndexError:
            return self._generate_branch()
        
    @property
    def local_tag(self):
        try:
            if self.transactions == []:
                return self._generate_tag()
            return self.transactions[0].req.get('To', {}).get('tag', self._generate_tag())
        except IndexError:
            return self._generate_tag()
        
    @property
    def remote_tag(self):
        try:
            if self.transactions == []:
                return None
            return self.transactions[-1].res[0].get('From', {}).get('tag', None)
        except IndexError:
            return None
        
    @property
    def call_id(self):
        try:
            if self.transactions == []:
                return self._generate_call_id()
            return self.transactions[0].req.get('Call-ID', self._generate_call_id())
        except IndexError:
            return self._generate_call_id()

    @property
    def seq(self):
        try:
            if self.transactions == []:
                return 1
            return self.transactions[-1].req.get('CSeq', {}).get('seq', 0) + 1
        except IndexError:
            return 1
    
    @property
    def method_seq(self):
        try:
            if self.transactions == []:
                return None
            return self.transactions[-1].req.get('CSeq', {}).get('method', None)
        except IndexError:
            return None
    
    def new_transaction(self, m: Message):
        tr = Transaction(m)
        self.transactions.append(tr)
        return tr

    def on_transaction(self, m: Message):
        for _tr in self.transactions:
            if _tr.branch == m.branch:
                tr = _tr
        else:
            tr = self.new_transaction(m)
        tr.on_transaction_update(m)
    
    def re_invite(self):
        pass
    
    def _generate_branch(self):
        return f'z9hG4bK{str(uuid.uuid4())[:8]}'
    
    def _generate_call_id(self):
        return str(uuid.uuid4())
    
    def _generate_tag(self):
        return str(uuid.uuid4())[:4]


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

    def _build_uri(
            self,
            addr: str,
            port: int = None,
            tag: str = None,
            branch: str = None,
            rport: bool = False,
            bracket: bool = False,
            ):
        
        uri = f'sip:{addr}'
        if port and port != 0:
            uri += f':{port}'
        if tag:
            uri += f';tag={tag}'
        if rport:
            uri += f';rport'
        if branch:
            uri += f';branch={branch}'
        # for k, v in extra_params.items() if extra_params else {}:
        #     if v:
        #         uri += f';{k}={v}'
        #         continue
        #     uri += f';{k}'
        if bracket:
            uri = f'<{uri}>'
        return uri
    
    def request(
            self,
            method: str,
            ua: UserAgent = None,
            dialog: Dialog = None,
            rport: bool = False,
            extra_headers: list[tuple[str, str]] = None
            ):
        if not dialog:
            dialog = Dialog()
        
        method = method.upper()
        protocol = self.cfg.protocol.upper()
        req_uri = self._build_uri(addr=ua.domain, port=ua.domain)
        via_uri = self._build_uri(addr=self.cfg.local_addr[0], port=self.cfg.local_addr[1], branch=dialog.branch, rport=rport)
        from_uri = self._build_uri(addr=ua.domain, port=ua.port, tag=dialog.local_tag, bracket=True)
        to_uri = self._build_uri(addr=ua.domain, port=ua.port, tag=dialog.remote_tag, bracket=True)
        call_id = dialog.call_id
        seq = dialog.seq
        method_seq = dialog.method_seq or method
        # extra_headers = extra_headers or []

        msg = (
            f'{method} {req_uri} SIP/2.0\r\n'
            f'Via: SIP/2.0/{protocol} {via_uri}\r\n'
            f'From: {from_uri}\r\n'
            f'To: {to_uri}\r\n'
            f'Call-ID: {call_id}\r\n'
            f'CSeq: {seq} {method_seq}\r\n'
            f'Max-Forwards: 70\r\n'
            f'Content-Length: 0\r\n'
            # f'{k}: {v}\r\n' for k, v in extra_headers if extra_headers else []
            '\r\n'
        )
        
        dialog.new_transaction(Request(msg))
        self._dialogs.append(dialog)
        self._transport.send(msg, (ua.domain, ua.port))

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

    
    