import socket
import time
import uuid
import logging
import base64
import hashlib
import re
import asyncio
from uuid import uuid4
from enum import Enum, IntEnum
from dataclasses import dataclass, field
from typing import List, Dict, Union, Tuple, Optional
from collections import defaultdict
from abc import ABC, abstractmethod


from pyphone.utils import log

class SipMethod(Enum):
    INVITE = "INVITE"
    ACK = "ACK"
    BYE = "BYE"
    CANCEL = "CANCEL"
    REGISTER = "REGISTER"
    OPTIONS = "OPTIONS"
    INFO = "INFO"
    SUBSCRIBE = "SUBSCRIBE"
    NOTIFY = "NOTIFY"

    def __str__(self):
        return self.value


class SipStatusCode(IntEnum):
    TRYING = (100, "Trying")
    RINGING = (180, "Ringing")
    OK = (200, "OK")
    UNAUTHORIZED = (401, "Unauthorized")
    FORBIDDEN = (403, "Forbidden")
    NOT_FOUND = (404, "Not Found")
    REQUEST_TIMEOUT = (408, "Request Timeout")
    INTERNAL_SERVER_ERROR = (500, "Internal Server Error")
    BUSY_HERE = (486, "Busy Here")
    REQUEST_TERMINATED = (487, "Request Terminated")
    SERVER_TIMEOUT = (504, "Server Timeout")
    BUSY_EVERYWHERE = (600, "Busy Everywhere")
    DECLINE = (603, "Decline")
    NOT_ACCEPTABLE = (606, "Not Acceptable")

    def __new__(cls, value, phrase):
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.phrase = phrase
        return obj

    def __str__(self):
        return f"{self.value} {self.phrase}"


class DialogState(Enum):
    INIT = "INIT"
    EARLY = "EARLY"
    CONFIRMED = "CONFIRMED"
    TERMINATED = "TERMINATED"

    def __str__(self):
        return self.value


@dataclass
class Uri:
    user: str
    host: str
    port: int = field(default=5060)
    scheme: str = field(default='sip')
    # password: str = field(default=None)
    parameters: dict = field(default_factory=dict)

    _SYNTAX = re.compile('^(?P<scheme>[a-zA-Z][a-zA-Z0-9\+\-\.]*):'# scheme
            + '(?:(?:(?P<user>[a-zA-Z0-9\-\_\.\!\~\*\'\(\)&=\+\$,;\?\/\%]+)' # user 
            # + '(?::(?P<password>[^:@;\?]+))?)@)?' # password
            + '(?:(?:(?P<host>[^;\?:]*)(?::(?P<port>[\d]+))?))' # host, port
            + '(?:;(?P<params>[^\?]*))?' # parameters
            )
    
    def __str__(self):
        uri = f"{self.scheme}:{self.user}@{self.host}"
        if self.port != 5060:
            uri += f":{self.port}"
        # if self.password:
        #     uri += f":{self.password}"
        if self.parameters:
            uri += f";{';'.join([f'{k}={v}' for k, v in self.parameters.items()])}"
        return uri

    @classmethod
    def parser(cls, uri: str) -> 'Uri':
        _match = cls._SYNTAX.match(uri)
        if not _match:
            raise ValueError(f"Invalid URI: {uri}")
        _params = {}
        if _match.group('params'):
            _params = dict([p.split('=') for p in _match.group('params').split(';')])
        return Uri(
            scheme=_match.group('scheme'),
            user=_match.group('user'),
            host=_match.group('host'),
            port=int(_match.group('port')) if _match.group('port') else 5060,
            # password=_match.group('password'),
            parameters=_params,
        )


class Address:
    uri: Uri
    display_name: str = None
    tag: str = None

    _SYNTAX = [
        re.compile('^(?P<display_name>[a-zA-Z0-9\-\.\_\+\~\ \t]*)<(?P<uri>[^>]+)>'),
        re.compile('^(?:"(?P<display_name>[a-zA-Z0-9\-\.\_\+\~\ \t]+)")[\ \t]*<(?P<uri>[^>]+)>'),
        re.compile('^[\ \t]*(?P<display_name>)(?P<uri>[^;]+)'),
        ]
    
    def __str__(self):
        address = f'"{self.display_name}" ' if self.display_name else ''
        address += f"<{self.uri}>"
        if self.tag:
            address += f";tag={self.tag}"
        return address
    
    @classmethod
    def parser(cls, address: str) -> 'Address':
        _match = cls._SYNTAX.match(address)
        if not _match:
            raise ValueError(f"Invalid Address: {address}")
        _uri = Uri().parser(_match.group('uri'))
        return Address(
            uri=_uri,
            display_name=_match.group('display_name'),
        )

class Field:
    def __init__(self, name: str, value: str, separator: str = ':'):
        self.name = name.strip()
        self.value = value.strip()
        self.separator = separator
    
    def __str__(self):
        return f"{self.name}{self.separator}{self.value}"
    
    @classmethod
    def parser(cls, field: str, separator: str = ':') -> 'Field':
        _name, _value = field.split(separator)
        return Field(
            name=_name,
            value=_value,
            separator=separator,
        )

    def generate_call_id(self) -> str:
        return str(uuid4())[0:8]

    def generate_tag(self) -> str:
        return str(uuid4())[0:6]

    def generate_branch(self) -> str:
        return f"z9hG4bK-{self.generate_tag()}"


class Via(Field):
    def __init__(
        self,
        host: str,
        port: int = 5060,
        branch: str = None,
        received: str = None,
        rport: int = None,
        protocol: str = 'SIP/2.0',
        transport: str = 'UDP'
    ):
        self.host = host
        self.port = port
        self.branch = branch or self.generate_branch()
        self.received = received
        self.rport = rport
        self.protocol = protocol
        self.transport = transport
        super().__init__('via', self._to_string())
    
    def _to_string(self):
        _host = (f"{self.host}:{self.port}" if self.port != 5060 else self.host)
        via = f"{self.protocol}/{self.transport} {_host};branch={self.branch}"
        if self.received:
            via += f";received={self.received}"
        if self.rport:
            via += f";rport={self.rport}"
        return via
    
    @classmethod
    def parser(cls, field: str) -> 'Via':
        _params = dict([p.split('=') for p in field.split(';')])
        _host, _port = _params.get('host').split(':')
        return Via(
            host=_host,
            port=int(_port),
            branch=_params.get('branch'),
            received=_params.get('received'),
            rport=int(_params.get('rport')),
            protocol=_params.get('protocol'),
            transport=_params.get('transport'),
        )


class From(Field):
    def __init__(
        self,
        address: Address,
        tag: str = None
    ):
        self.address = address
        self.tag = tag or self.generate_tag()
        super().__init__('From', self._to_string(), separator=':')
    
    def _to_string(self):
        _tag = f';tag={self.tag}' if self.tag else ''
        return f'{self.address}{_tag}'

    @classmethod
    def parser(cls, field: str) -> 'From':
        _tag = re.search(r';tag=(\w+)', field)
        if _tag:
            _tag = _tag.group(1)
            field = field.replace(f';tag={_tag}', '')
        return From(
            address=Address.parser(field),
            tag=_tag,
        )

class To(Field):
    def __init__(
        self,
        address: Address,
        tag: str = None
    ):
        self.address = address
        self.tag = tag or self.generate_tag()
        super().__init__('To', self._to_string(), separator=':')
    
    def _to_string(self):
        _tag = f';tag={self.tag}' if self.tag else ''
        return f'{self.address}{_tag}'

    @classmethod
    def parser(cls, field: str) -> 'To':
        _tag = re.search(r';tag=(\w+)', field)
        if _tag:
            _tag = _tag.group(1)
            field = field.replace(f';tag={_tag}', '')
        return From(
            address=Address.parser(field),
            tag=_tag,
        )


class Contact(Field):
    def __init__(
        self,
        address: Address,
        expires: str = None
    ):
        self.address = address
        self.expires = expires or self.generate_tag()
        super().__init__('Contact', self._to_string(), separator=':')
    
    def _to_string(self):
        _expires = f";expires={self.expires}" if self.expires else ''
        return f'{self.address}{_expires}'

    @classmethod
    def parser(cls, field: str) -> 'Contact':
        _expires = re.search(r';expires=(\d+)', field)
        if _expires:
            _expires = _expires.group(1)
            field = field.replace(f';expires={_expires}', '')
        return Contact(
            address=Address.parser(field),
            expires=_expires,
        )


class CallId(Field):
    def __init__(self, call_id: str = None):
        self.call_id = call_id or self.generate_call_id()
        super().__init__('Call-ID', self.call_id)

    @classmethod
    def parser(cls, field: str) -> 'CallId':
        _, _call_id = field.split(':')
        return CallId(_call_id)


class CSeq(Field):
    def __init__(self, method: str, seq: int):
        self.method = method
        self.seq = seq
        super().__init__('Cseq', self._to_string())
    
    def _to_string(self):
        return f"{self.seq} {self.method}"

    @classmethod
    def parser(cls, field: str) -> 'CSeq':
        _, _seq = field.split(':')
        _seq, _method = _seq.split(' ')
        return CSeq(_method, int(_seq))


class MaxForword(Field):
    def __init__(self, max_forword: int = 70):
        super().__init__('Max-Forwords', str(max_forword))

    @classmethod
    def parser(cls, field: str) -> 'MaxForword':
        _, _max_forword = field.split(':')
        return MaxForword(int(_max_forword))


class ContentType(Field):
    def __init__(self, content_type: str = 'application/sdp'):
        super().__init__('Content-Type', content_type)

    @classmethod
    def parser(cls, field: str) -> 'ContentType':
        _, _content_type = field.split(':')
        return ContentType(_content_type)


class ContentLength(Field):
    def __init__(self, content_length: int = 0):
        super().__init__('Content-Length', str(content_length))

    @classmethod
    def parser(cls, field: str) -> 'ContentLength':
        _, _content_length = field.split(':')
        return ContentLength(int(_content_length))


class Authorization(Field):
    def __init__(self, username: str, password: str, realm: str, nonce: str, uri: str, response: str):
        self.username = username
        self.password = password
        self.realm = realm
        self.nonce = nonce
        self.uri = uri
        self.response = response
        super().__init__('Authorization', self._to_string())
    
    def _to_string(self):
        return f"Digest username={self.username}, realm={self.realm}, nonce={self.nonce}, uri={self.uri}, response={self.response}"

    @classmethod
    def parser(cls, field: str) -> 'Authorization':
        _params = dict([p.split('=') for p in field.split(',')])
        return Authorization(
            username=_params.get('username'),
            password=_params.get('password'),
            realm=_params.get('realm'),
            nonce=_params.get('nonce'),
            uri=_params.get('uri'),
            response=_params.get('response'),
        )


@dataclass
class SipHeader:
    via: Via
    from_: From
    to: To
    call_id: CallId
    cseq: CSeq
    contact: Contact = None
    max_forword: MaxForword = field(default_factory=MaxForword)
    content_type: ContentType = field(default_factory=ContentType)
    content_length: ContentLength = field(default_factory=ContentLength)
    authorization: Authorization = None
    extras_fields: Dict[str, Field] = field(default_factory=dict)

    COMPACT_HEADERS_FIELDS = {
        'v': 'Via', 'f': 'From', 't': 'To', 'm': 'Contact',
        'i': 'Call-ID', 's': 'Subject', 'l': 'Content-Length',
        'c': 'Content-Type', 'k': 'Supported', 'o': 'Allow',
        'p': 'P-Associated-URI'
    }

    def __post_init__(self):
        if self.name.lower() in self.COMPACT_HEADERS_FIELDS:
            self.name = self.COMPACT_HEADERS_FIELDS[self.name.lower()]

    def __str__(self):
        pass
    
    @classmethod
    def parser(cls, headers: str) -> 'SipHeader':
        _headers = {}
        lines = headers.split('\r\n')
        for line in lines:
            name, value = line.split(':')
            match name.lower():
                case 'via':
                    _headers['via'] = Via.parser(value)
                case 'from':
                    _headers['from'] = From.parser(value)
                case 'to':
                    _headers['to'] = To.parser(value)
                case 'contact':
                    _headers['contact'] = Contact.parser(value)
                case 'call-id':
                    _headers['call_id'] = CallId.parser(value)
                case 'cseq':
                    _headers['cseq'] = CSeq.parser(value)
                case 'max-forword':
                    _headers['max_forword'] = MaxForword.parser(value)
                case 'content-type':
                    _headers['content_type'] = ContentType.parser(value)
                case 'content-length':
                    _headers['content_length'] = ContentLength.parser(value)
                case 'authorization':
                    _headers['authorization'] = Authorization.parser(value)
                case _:
                    _headers[name] = Field.parser(name, value)
        return SipHeader(**_headers)

@dataclass
class SdpMedia:
    owner: Body
    connection_info: Body = None
    media_description: Body = None
    session_name: Body = None
    media_session: Body = None
    ptime: Body = None
    attributes: List[Body] = field(default_factory=list)
    extras_fields: Dict[str, Body] = field(default_factory=dict)


class SipMessage(ABC):
    def __init__(self, headers: dict[str, list[Header]] = None, body: dict[str, list[Body]] = None):
        self.headers = headers or defaultdict(list)
        self.body = body or defaultdict(list)
    
    def add_header(self, header: Header):
        self.headers[header.name].append(header)
    
    def get_header(self, name: str) -> Header:
        return self.headers.get(name)

    def add_body(self, body: Body):
        self.body[body.name].append(body)
    
    def get_body(self, name: str) -> Body:
        return self.body.get(name)

    def to_bytes(self):
        return str(self).encode()
    
    @abstractmethod
    def parser(cls, message: bytes) -> 'SipMessage':
        pass
    
    @abstractmethod
    def __str__(self):
        pass
    
    

class SipRequest(SipMessage):
    def __init__(self, method: SipMethod, uri: Uri, headers: dict[str, list[Header]] = None, body: dict[str, list[Body]] = None):
        super().__init__(headers, body)
        self.method = method
        self.uri = uri
    
    def __str__(self):
        return f"{self.method} {self.uri} SIP/2.0\n" + '\n'.join([str(h) for h in self.headers]) + '\n' + '\n'.join([str(b) for b in self.body])

    @classmethod
    def parser(cls, message) -> 'SipRequest':
        _lines = message.split(b'\n')
        _method, _uri, _version = _lines[0].split(b' ')
        _headers = defaultdict(list)
        _body = defaultdict(list)
        _current = None
        for line in _lines[1:]:
            if not line:
                continue
            if ':' in line:
                _header = Header.parser(line.decode())
                _headers[_header.name].append(_header)
            elif '=' in line:
                _body = Body.parser(line.decode())
                _body[_body.name].append(_body)
            else:
                continue
        return SipRequest(
            method=SipMethod(_method),
            uri=Uri.parser(_uri),
            headers=_headers,
            body=_body
        )


class SipResponse(SipMessage):
    def __init__(self, status_code: SipStatusCode, headers: dict[str, list[Header]] = None, body: dict[str, list[Body]] = None):
        super().__init__(headers, body)
        self.status_code = status_code
    
    def __str__(self):
        return f"SIP/2.0 {self.status_code}\n" + '\n'.join([str(h) for h in self.headers]) + '\n' + '\n'.join([str(b) for b in self.body])

    @classmethod
    def parser(cls, message) -> 'SipResponse':
        _lines = message.split(b'\n')
        _version, _status_code, _phrase = _lines[0].split(b' ')
        _headers = defaultdict(list)
        _body = defaultdict(list)
        _current = None
        for line in _lines[1:]:
            if not line:
                continue
            if ':' in line:
                _header = Header.parser(line.decode())
                _headers[_header.name].append(_header)
            elif '=' in line:
                _body = Body.parser(line.decode())
                _body[_body.name].append(_body)
            else:
                continue
        return SipResponse(
            status_code=SipStatusCode(_status_code),
            headers=_headers,
            body=_body
        )


class SipDialog:
    def __init__(self, call_id: str, local_tag: str, remote_tag: str):
        self.call_id = call_id
        self.local_tag = local_tag
        self.remote_tag = remote_tag
        self.state = DialogState.INIT
        self.local_seq = 0
        self.remote_seq = 0
    
    def update_state(self, state: DialogState):
        log.info(f"Dialog {self.call_id} state updated: {self.state} -> {state}")
        self.state = state
    
    def update_local_seq(self, seq: int):
        log.info(f"Dialog {self.call_id} local seq updated: {self.local_seq} -> {seq}")
        self.local_seq = seq
    
    def update_remote_seq(self, seq: int):
        log.info(f"Dialog {self.call_id} remote seq updated: {self.remote_seq} -> {seq}")
        self.remote_seq = seq


class SipTransaction:
    def __init__(self, request: SipRequest):
        self.request = request
        self.response = None
        self.state = None
        self.timer = asyncio.create_task(self.transaction_timer())
        self.retransmit = 0
    
    async def transaction_timer(self):
        await asyncio.sleep(32)  # RFC 3261 recommends 32 seconds
        if self.state != "COMPLETED":
            logging.warning(f"Transaction {self.request.get_header('CSeq')} timed out")
            self.state = "TERMINATED"
    
    def retransmit_request(self):
        pass
    
    def receive_response(self, response: SipResponse):
        self.response = response
        if response.status_code in [SipStatusCode.TRYING, SipStatusCode.RINGING]:
            self.state = "COMPLETED"
            if self.timer:
                self.timer.cancel()
        elif response.status_code in [SipStatusCode.OK]:
            self.state = "TERMINATED"
            if self.timer:
                self.timer.cancel()
        else:
            self.retransmit += 1
            if self.retransmit == 7:
                self.state = "TERMINATED"
                if self.timer:
                    self.timer.cancel()
            else:
                self.retransmit_request()


class SipRegister(SipTransaction):
    pass

class SipCall(SipTransaction):
    pass


class SipSubscribe(SipTransaction):
    pass


class SipMessage(SipTransaction):
    pass


class SipKeepAlive(SipTransaction):
    pass

class SocketInterface(ABC):
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        self.sock = None
        self._running = False
    
    def _connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.ip, self.port))
        self._running = True
    
    def _disconnect(self):
        self._running = False
        self.sock.close()
    
    async def _send(self, data: bytes):
        if not self.sock:
            self._connect()
        await asyncio.get_event_loop().sock_sendto(self.sock, data, (self.ip, self.port))
    
    async def _receive(self):
        while self._running:
            data, addr = await asyncio.get_event_loop().sock_recv(self.sock, 4096)
            yield data, addr


class SipHandler(SocketInterface):
    def __init__(self, ip: str, port: int, callback: callable):
        super().__init__(ip, port)
        self.callback = callback
        self._receive_task = None
    
    async def send(self, message: SipMessage):
        await self._send(message.to_bytes())
    
    async def receive(self):
        for data, addr in self._receive():
            message = SipRequest.parser(data)
            self.callback(message, addr)

    async def start(self):
        self._connect()
        self._receive_task = await asyncio.create_task(self.receive())
    
    async def close(self):
        self._disconnect()
        await self._receive_task.cancel()


class RtpHandler(SocketInterface):
    def __init__(self, ip: str, port: int, callback: callable):
        super().__init__(ip, port)
        self.callback = callback
        self._receive_task = None
    
    async def send(self, data: bytes):
        await self._send(data)
    
    async def receive(self):
        for data, addr in self._receive():
            self.callback(data, addr)

    async def start(self):
        self._connect()
        self._receive_task = await asyncio.create_task(self.receive())
    
    async def close(self):
        self._disconnect()
        await self._receive_task.cancel()


class DtmfHandler(SocketInterface):
    def __init__(self, ip, port, callback):
        super().__init__(ip, port)
        self.callback = callback
        self._receive_task = None
    
    async def send(self, digit: str):
        await self._send(digit.encode())
    
    async def receive(self):
        for data, addr in self._receive():
            self.callback(data, addr)
    
    async def start(self):
        self._connect()
        self._receive_task = await asyncio.create_task(self.receive())
    
    async def close(self):
        self._disconnect()
        await self._receive_task.cancel()


@dataclass
class UserAgentConfig:
    username: str
    server: str
    port: int = field(default=5060)
    login: str = field(default=None)
    password: str = field(default=None)
    realm: str = field(default=None)
    proxy: str = field(default=None)
    user_agent: str = field(default="PyPhone")
    time_out: int = field(default=30)
    expires: int = field(default=30)


class SipClient:
    transactions: dict[str, SipTransaction] = {}
    dialogs: dict[str, SipDialog] = {}
    cseq = 0
    
    def __init__(
        self,
        local_ip: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        ua_cfg: UserAgentConfig,
        event_loop = None
    ):
        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.ua_cfg = ua_cfg

        self.event_loop = event_loop or asyncio.get_event_loop()
        self.sock: SipHandler = SipHandler(local_ip, local_port, self.on_received_message)
        self.rtp: RtpHandler = None
        self.dtmf: DtmfHandler = None
        self._receive_message_task = None
    
    async def start(self):
        await self.sock.start()

    async def close(self):
        await self.sock.close()
        await self._receive_message_task.cancel()
    
    async def send_message(self, message: SipMessage):
        log.info(f"Sending SIP message: {message}")
        await self.sock.send(message)

    async def on_received_message(self, message: SipMessage, addr: Tuple[str, int]):
        match message:
            case isinstance(message, SipRequest):
                log.info(f"Received SIP request: {message}")
            case isinstance(message, SipResponse):
                log.info(f"Received SIP response: {message}")
            case _:
                log.error(f"Invalid SIP message: {message}")
        return None
    
    async def send_rtp(self, data: bytes):
        pass
    
    async def on_received_rtp(self, data: bytes):
        pass
    
    async def send_dtmf(self, digit: str):
        pass
    
    async def on_received_dtmf(self, digit: str):
        pass
    
    def create_request(self, method: SipMethod, to_address: Address):
        self.cseq += 1
        request = SipRequest(
            method=method,
            uri=to_address.uri,
            headers={
                'CSeq': [Header('CSeq', f"{self.cseq} {method}")]
            }
        )
        return request
    
    def create_response(self, request: SipRequest, status_code: SipStatusCode):
        response = SipResponse(
            status_code=status_code,
            headers={
                'CSeq': [Header('CSeq', f"{request.get_header('CSeq').value} {request.method}")]
            }
        )
        return response

if __name__ == '__main__':
    pass
