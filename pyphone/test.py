import socket
import time
import uuid
import logging
import base64
import hashlib
import re
import asyncio
from enum import Enum, IntEnum
from dataclasses import dataclass, field
from typing import List, Dict, Union, Tuple, Optional
from collections import defaultdict


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

    _SYNTAX = [
        re.compile('^(?P<display_name>[a-zA-Z0-9\-\.\_\+\~\ \t]*)<(?P<uri>[^>]+)>'),
        re.compile('^(?:"(?P<display_name>[a-zA-Z0-9\-\.\_\+\~\ \t]+)")[\ \t]*<(?P<uri>[^>]+)>'),
        re.compile('^[\ \t]*(?P<display_name>)(?P<uri>[^;]+)'),
        ]
    
    def __str__(self):
        address = f'"{self.display_name}" ' if self.display_name else ''
        address += f"<{self.uri}>"
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


@dataclass
class Header:
    name: str
    value: str
    
    _SYNTAX = re.compile('^(?P<name>[a-zA-Z0-9\-\.\_]+):[\ \t]*(?P<value>.*)$')
    COMPACT_HEADERS_FIELDS = {
        'v': 'Via', 'f': 'From', 't': 'To', 'm': 'Contact',
        'i': 'Call-ID', 's': 'Subject', 'l': 'Content-Length',
        'c': 'Content-Type', 'k': 'Supported', 'o': 'Allow',
        'p': 'P-Associated-URI'
    }

    def __post_init__(self):
        self.name = self.name.strip()
        if self.name.lower() in self.COMPACT_HEADERS_FIELDS:
            self.name = self.COMPACT_HEADERS_FIELDS[self.name.lower()]
        self.value = self.value.strip()
    
    def __str__(self):
        return f"{self.name}: {self.value}"

    @classmethod
    def parser(cls, header: str) -> 'Header':
        _match = cls._SYNTAX.match(header)
        if not _match:
            raise ValueError(f"Invalid Header: {header}")
        return Header(
            name=_match.group('name'),
            value=_match.group('value'),
        )


@dataclass
class Body:
    name: str
    value: str
    
    _SYNTAX = re.compile('^(?P<name>[a-zA-Z0-9\-\.\_]+s)=[\ \t]*(?P<value>.*)$')
    
    def __post_init__(self):
        self.name = self.name.strip()
        self.value = self.value.strip()
    
    def __str__(self):
        return f"{self.name}={self.value}"
    
    @classmethod
    def parser(cls, body: str) -> 'Body':
        _match = cls._SYNTAX.match(body)
        if not _match:
            raise ValueError(f"Invalid Body: {body}")
        return Body(
            name=_match.group('name'),
            value=_match.group('value'),
        )


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
    
    def receive_response(self, response: SipResponse):
        self.response = response
        if response.status_code in [SipStatusCode.TRYING, SipStatusCode.RINGING]:
            self.state = "COMPLETED"
            if self.timer:
                self.timer.cancel()