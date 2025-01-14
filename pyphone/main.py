import socket
import time
import uuid
import logging
import base64
import hashlib
import re
import asyncio
from uuid import uuid4
import random
from enum import Enum, IntEnum
from dataclasses import dataclass, field
from typing import List, Dict, Union, Tuple, Optional
from collections import defaultdict
from abc import ABC, abstractmethod


from pyphone.message import SipMessage, Field, Address

# Exceptions
class SipException(Exception): ...
class SipParseException(SipException): ...
class SipTransportException(SipException): ...
class SipTransactionException(SipException): ...

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

# Utils
def generate_branch(): ...
def generate_call_id(): ...
def generate_tag(): ...
def parse_uri(uri: str): ...
def parse_address(address: str): ...
def parse_header(header: str): ...
def parse_body(body: str): ...


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
    dialoggers: dict[str, str] = {}
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
        self.sock: Connection = None
        self.rtp: RtpHandler = None
        self.dtmf: DtmfHandler = None
        self._receive_message_task = None
    
    async def start(self):
        await self.sock.start()

    async def close(self):
        await self.sock.close()
        await self._receive_message_task.cancel()
    
    async def send_message(self, message: SipMessage):
        logger.info(f"Sending SIP message: {message}")
        await self.sock.send(message)

    async def on_received_message(self, message: SipMessage, addr: Tuple[str, int]):
        match message:
            case message.is_request():
                logger.info(f"Received SIP request: {message}")
            case message.is_response():
                logger.info(f"Received SIP response: {message}")
            case _:
                logger.error(f"Invalid SIP message: {message}")
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
        request = SipMessage(
            method=method,
            uri=to_address.uri,
            headers={
                'CSeq': [Field('CSeq', f"{self.cseq} {method}")]
            }
        )
        return request
    
    def create_response(self, request: SipMessage, status_code: SipStatusCode):
        response = SipMessage(
            status_code=status_code,
            headers={
                'CSeq': [Field('CSeq', f"{request.get_header('CSeq').value} {request.method}")]
            }
        )
        return response


# Sessions (Session Layer)
class SessionLayer(ApplicationLayer): ...


if __name__ == '__main__':
    pass