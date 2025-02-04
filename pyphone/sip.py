'''
Session Initiation Protocol (SIP)
RFC 3261: https://tools.ietf.org/html/rfc3261
'''
from datetime import datetime
from typing import AnyStr, Dict, List, Optional
from dataclasses import dataclass, field
import re
from uuid import uuid4

from pyphone.transport import Connection, ConnectionConfig, TransportProtocol, TransportAddr

type CallID = AnyStr
type Transaction = Dict[AnyStr, AnyStr]
type Transactions = Dict[CallID, List[Transaction]]


COMPACT_HEADERS = {
    "v": "Via",
    "f": "From",
    "t": "To",
    "m": "Contact",
    "i": "Call-ID",
    "e": "Contact-Encoding",
    "l": "Content-Length",
    "c": "Content-Type",
    "s": "Subject",
    "k": "Supported",
}

@dataclass
class UserAgent:
    username: str
    domain: TransportAddr
    login: str
    password: str
    transport: TransportProtocol = 'UDP'
    display_name: str = None
    realm: str = None
    conn_cfg: ConnectionConfig = None

    @property
    def uri(self):
        return f'sip:{self.username}@{self.domain[0]}:{self.domain[0]}'

@dataclass
class Message:
    method: Optional[str] = None
    uri: Optional[str] = None
    status_code: Optional[int] = None
    reason: Optional[str] = None
    headers: Optional[Dict[str, AnyStr]] = field(default_factory=dict)
    body: Optional[Dict[str, AnyStr]] = field(default_factory=dict)
    
    @property
    def branch(self):
        via = self.headers.get('Via', '')
        return via.split('branch=').split(';')[-1] if 'branch=' in via else ''
    
    @property
    def uri(self):
        return self.headers.get('To', '').split(' ')[1]
    
    def add_header(self, key: str, value: AnyStr):
        if key in self.headers:
            if not isinstance(self.headers[key], list):
                self.headers[key] = [self.headers[key]]
            self.headers[key].append(value)
        else:
            self.headers[key] = value
    
    def add_body(self, key: str, value: AnyStr):
        if key in self.body:
            if not isinstance(self.body[key], list):
                self.body[key] = [self.body[key]]
            self.body[key].append(value)
        else:
            self.body[key] = value
        self.add_header('Content-Length', len('/r/n'.join(f'{k}: {v}'for k, v in self.body.values())))
    
    @classmethod
    def parser(cls, data: AnyStr) -> 'Message':
        '''
        Parse a SIP message
        '''
        parts = re.split(r'\r\n\r\n|\n\n', data, maxsplit=1)
        _first_line = str(parts[0].split('\r\n')[0]).strip()
        _header = list(x for x in parts[0].split('\r\n')[1:])
        _body = list(x for x in (parts[1] if len(parts) > 1 else '').split('\r\n'))
        m = Message()
        for k, v in _header.split(':', 1):
            m.add_header(k, v)
        for k, v in _body.split('=', 1):
            m.add_body(k, v)
        if _first_line.startswith('SIP/2.0'):
            _, status_code, reason = _first_line.split(' ')
            m.status_code = int(status_code)
            m.reason = reason
            return m
        else:
            method, uri, _ = _first_line.split(' ')
            
            m.method = method
            m.uri = uri
            return m
            
    def to_string(self):
        '''
        Convert the message to a string
        '''
        _m = []
        if self.method:
            _m.append(f'{self.method} {self.uri} SIP/2.0')
        elif self.status_code:
            _m.append(f'SIP/2.0 {self.status_code} {self.reason}')
        for v in self.headers.items():
            _m.append(f'{v[0]}: {v[1]}')
        _m.append('')
        for v in self.body.items():
            _m.append(f'{v[0]}={v[1]}')
        return '\r\n'.join(_m)
    
    @classmethod
    def request(cls, method: str, uri: str,  header: dict = None, sdp: dict = None) -> 'Message':
        '''
        Build a request message
        '''
        cls(
            method=method,
            uri=uri,
            headers=header,
            body=sdp
        )
    @classmethod
    def response(cls, status_code, reason: str, header: dict, sdp: dict = None) -> 'Message':
        '''
        Build a response message
        '''
        cls(
            status_code=status_code,
            reason=reason,
            headers=header,
            body=sdp
        )

class Transaction:
    def __init__(self, message: Message):
        self.initial_message = message
        self.messages = [message]
        self.state = 'TRYING'
        self.created_at = datetime.now()
    
    def add_message(self, m: Message):
        self.messages.append(m)
        self._update_status(m)
        
    def _update_status(self, m: Message):
        if m.status_code == 200:
            self.state = 'COMPLETED'
        elif m.status_code in (300, 699):
            self.state = 'REDIRECTED'
        elif m.status_code in (400, 699):
            self.state = 'FAILED'
        elif m.status_code in (100, 199):
            self.state = 'PROCEEDING'
        elif m.status_code in (401, 407):
            self.state = 'CHALLENGED'
        else:
            self.state = 'TRYING'


class Dialog:
    def __init__(
            self,
            initial_message: Message,
            ):
        self.initial_message = initial_message
        self.transactions[initial_message.branch] = [Transaction(initial_message)]

    def add_transaction(self, m: Message):
        self.transactions[m.branch].append(Transaction(m))


class Session:
    '''
    Session Initiation Protocol (SIP) RFC 3261
    https://tools.ietf.org/html/rfc3261
    '''
    def __init__(self, user_agent: UserAgent):
        self.ua = user_agent
        self.dialogs: Dict[str, Dialog] = {}
    
    def start(self):
        self.conn = Connection(self.ua.conn_cfg, self.handle_message)
        self.conn.start()
    
    def stop(self):
        self.conn.stop()

    def handle_message(self, data: AnyStr, addr: TransportAddr):
        m = Message.parser(data)
        if m.method:
            self._handle_request(m)
        else:
            self._handle_response(m)

    def _handle_request(self, m: Message):
        self.dialogs[m.branch].add_transaction(m)
    
    def _handle_response(self, m: Message):
        if not m.call_id in self.dialogs:
            self.
    
    def _challenges_auth(self, m: Message):
        if m.status_code == 401:
            m.add_headers([('Authorization', 'Digest')])
        elif m.status_code == 407:
            m.add_headers([('Proxy-Authorization', 'Digest')])
        else:
            pass
    
    def _generate_branch(self):
        return f'z9hG4bK-{uuid4().hex}'
    
    def _generate_call_id(self):
        return uuid4().hex
    
    def _generate_tag(self):
        return uuid4().hex[:8]
    
    def request(self, method: str, uri: str, call_id: str,  extra_headers: dict = None, sdp: dict = None):
        if self.dialogs[call_id]:
            seq = len(self.dialogs[call_id].transactions) + 1
        else:
            seq = 1
        
        m = Message.request(method, uri)
        m.add_header('Via', f'SIP/2.0/{self.ua.transport} {self.ua.domain[0]}{self.ua.domain[1]};branch={self._generate_branch()}')
        m.add_header('From', f'<sip:{self.ua.username}@{self.ua.domain[0]}:{self.ua.domain[1]}>')
        m.add_header('To', f'<sip:{uri}>')
        m.add_header('Call-ID', f'{call_id}')
        m.add_header('CSeq', f'{seq} {method}')
        m.add_header('Max-Forwards', '70')
        for k, v in extra_headers.items():
            m.add_header(k, v)
        if sdp:
            m.add_header('Content-Type', 'application/sdp')
            for k, v in sdp.items():
                m.add_body(k, v)
        self.dialogs[call_id].add_transaction(m)
        self.conn.send(m.to_string())

    def response(self, status_code: int, reason: str, m: Message, extra_headers: dict = None, sdp: dict = None):
        # Build the response message with the same headers of the request
        m = Message.response(status_code, reason, m.headers)
        for k, v in extra_headers.items():
            m.add_header(k, v)
        if sdp:
            for k, v in sdp.items():
                m.add_body(k, v)
        self.dialogs[m.branch].add_transaction(m)
    
    def _challenges_auth(self, m: Message):
        pass
    
        



