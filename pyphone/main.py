import asyncio
import time
import socket
import random
import re
import uuid
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple, Union

"""
SIP (Session Initiation Protocol)
RFC 3261: https://tools.ietf.org/html/rfc3261

SDP (Session Description Protocol)
RFC 4566: https://tools.ietf.org/html/rfc4566

RTP (Real-time Transport Protocol)
RFC 3550: https://tools.ietf.org/html/rfc3550

DTMF (Dual-tone multi-frequency signaling)
RFC 4733: https://tools.ietf.org/html/rfc4733

"""

# Logging
logger = logging.getLogger(__name__)

# Constants
EOL = r'\r\n'
SIP_SCHEME = 'SIP'
SIP_VERSION = '2.0'
SIP_BRANCH = 'z9hG4bK'
SIP_MAX_FORWARDS = 70
SIP_CONTENT = "application"
SIP_CONTENT_TYPE = "sdp"

COMPACT_HEADERS = {
    "v": "via",
    "f": "from",
    "t": "to",
    "m": "contact",
    "i": "call-id",
    "e": "contact-encoding",
    "l": "content-length",
    "c": "content-type",
    "s": "subject",
    "k": "supported",
}

HEADERS = {
    "via": "Via",
    "from": "From",
    "to": "To",
    "contact": "Contact",
    "call-id": "Call-ID",
    "cseq": "CSeq",
    "max-forwards": "Max-Forwards",
    "content-length": "Content-Length",
    "content-type": "Content-Type",
    "authorization": "Authorization",
    "www-authenticate": "WWW-Authenticate",
    "proxy-authenticate": "Proxy-Authenticate",
}

SDP_HEADERS = {
    "version": "v",
    "origin": "o",
    "session_name": "s",
    "connection_info": "c",
    "bandwidth_info": "b",
    "time_description": "t",
    "media_description": "m",
    "attribute": "a",
    "email_address": "e",
    "phone_number": "p",
    "uri": "u",
    "repeat_time": "r",
    "time_zone": "z",
}

# Regex Patterns
REQUEST_LINE_PATTERN = r'(?P<method>\w+)\s+(?P<uri>.+)\s+(?P<scheme>SIP)/(?P<version>\d+\.\d+)'
STATUS_LINE_PATTERN = r'^(?P<scheme>SIP)/(?P<version>\d+\.\d+)\s+(?P<status_code>\d+)\s+(?P<reason>.+)'
URI_PATTERN = r'(?:\"(?P<display_info>[^\"]+)\"\s+)?<sip:(?:\+)?(?P<user>[^@]+)@(?P<host>[^:;>]+)(?::(?P<port>\d+))?(?:;(?P<params>[^>]+))?>(?:;tag=(?P<tag>[^>\s]+))?'
ADDRESS_PATTERN = r'^(?P<scheme>SIP)/(?P<version>\d+\.\d+)/(?P<protocol>\w+)\s+(?P<address>[\d\.]+):(?P<port>\d+);branch=(?P<branch>[\w\.]+)'
HEADER_PATTERN = r'(?P<name>[\w-]+):\s+(?P<value>.+)'
BODY_PATTERN = r'(?P<name>\w+)\s*=\s*(?P<value>.+)'


# Exceptions
class SipException(Exception): ...

# Utils
def generate_branch(len: int = 8):
    """Generate a random branch ID."""
    return f"{SIP_BRANCH}-{uuid.uuid4().hex[:len]}"

def generate_call_id(host: str = None):
    """Generate a random call ID."""
    host = host or socket.gethostbyname(socket.gethostname())
    return f"{uuid.uuid4().hex}@{host}"

def generate_tag(len: int = 6):
    """Generate a random tag."""
    return f"{uuid.uuid4().hex[:len]}"

def parser_request_line(line: str):
    """Parse a SIP request line."""
    ...

def parser_status_line(line: str):
    """Parse a SIP status line."""
    ...

def parse_uri(uri: str):
    """Parse a SIP URI."""
    ...
    
def parser_address(address: str):
    """Parse a SIP address."""
    ...

def parse_header(header: str):
    """Parser a SIP header normal or compact."""
    ...
    
def parse_body(body: str):
    """Parser a SIP body."""
    ...


# Enums (Enumerations)
class SipMethod(Enum):
    INVITE = 'INVITE'
    ACK = 'ACK'
    BYE = 'BYE'
    CANCEL = 'CANCEL'
    REGISTER = 'REGISTER'
    OPTIONS = 'OPTIONS'
    
    @classmethod
    def request_line(cls, method: str, uri: str):
        return f"{method} {uri} SIP/2.0"

    @classmethod
    def from_string(cls, method: str):
        return cls(method.upper())
    
    @classmethod
    def methods(cls):
        return [method for method in cls]

class SipStatusCode(Enum):
    # SIP Status Codes 1xx
    TRYING = (100, 'Trying')
    RINGING = (180, 'Ringing')
    SESSION_PROGRESS = (183, 'Session Progress')
    # SIP Status Codes 2xx
    OK = (200, 'OK')
    ACCEPTED = (202, "Accepted")
    # SIP Status Codes 4xx
    UNAUTHORIZED = (401, "Unauthorized")
    FORBIDDEN = (403, "Forbidden")
    NOT_FOUND = (404, "Not Found")
    PROXY_AUTHENTICATION_REQUIRED = (407, "Proxy Authentication Required")
    REQUEST_TIMEOUT = (408, "Request Timeout")
    TEMPORARILY_UNAVAILABLE = (480, "Temporarily Unavailable")
    BUSY_HERE = (486, "Busy Here")
    REQUEST_TERMINATED = (487, "Request Terminated")
    # SIP Status Codes 5xx
    SERVER_INTERNAL_ERROR = (500, "Server Internal Error")
    NOT_IMPLEMENTED = (501, "Not Implemented")
    SERVER_TIMEOUT = (504, "Server Time-out")
    # SIP Status Codes 6xx
    BUSY_EVERYWHERE = (600, "Busy Everywhere")
    DECLINE = (603, "Decline")
    
    @classmethod
    def response_line(cls, status_code: int, reason: str):
        return f"SIP/2.0 {status_code} {reason}"

    @classmethod
    def from_string(cls, status_code: str):
        return cls(status_code.upper())

class ProtocolType(Enum):
    UDP = 'UDP'
    TCP = 'TCP'


# Configs (Configurations)
@dataclass
class NetworkConfig:
    local_ip: str = '0.0.0.0'
    local_port: int = 5060
    remote_ip: str = '0.0.0.0'
    remote_port: int = 5060
    local_port: int = 10080


@dataclass
class UserAgentConfig:
    username: str
    domain: str
    port: int = 5060
    login: str = None
    password: str = None
    realm: str = None
    user_agent: str = "PyPhone"
    time_out: int = 30
    expires: int = 30
    contact: str = None

# Connections (Network Layer)
class NetworkLayer:
    def send(self): ...
    def receive(self): ...
    def start(self): ...
    def close(self): ...

class TransportLayer(NetworkLayer):
    def retransmit(self): ...
    def on_received(self): ...
    def on_timeout(self): ...
    def on_error(self): ...

class SipHandler(TransportLayer):
    pass

class RtpHandler(TransportLayer):
    pass

class DtmfHandler(TransportLayer):
    pass


# Messages (Message Layer)
class Message:
    def parser(self): ...
    def data(self): ...
    def summary(self): ...
    def header(self): ...
    def body(self): ...

class Header: ...
class Body: ...
class Authentication: ...

class SipRequest:
    pass

class SipResponse:
    pass


class ApplicationLayer:
    transactions: dict[str, str] = {}
    dialogers: dict[str, str] = {}
    cseq = 0
    
    def __init__(
        self,
        nw_cfg: NetworkConfig,
        ua_cfg: UserAgentConfig,
        event_loop = None
    ):
        self.nw_cfg = nw_cfg
        self.ua_cfg = ua_cfg
        self.event_loop = event_loop or asyncio.get_event_loop()
        # Handlers
        self.sock: SipHandler = None
        self.rtp: RtpHandler = None
        self.dtmf: DtmfHandler = None
        # Taskss
        self._receive_message_task = None
    
    async def start(self): ...
    async def close(self): ...
    async def send_message(self, message: SipMessage): ...
    async def received_message(self, message: SipMessage, addr: Tuple[str, int]): ...
    async def send_rtp(self, data: bytes): ...
    async def received_rtp(self, data: bytes): ...
    async def send_dtmf(self, digit: str): ...
    async def received_dtmf(self, digit: str): ...
    def create_request(self, method: SipMethod, to_address: Address): ...
    def create_response(self, request: SipMessage, status_code: SipStatusCode): ...


# Sessions (Session Layer)
class SessionLayer(ApplicationLayer): ...


if __name__ == '__main__':
    pass