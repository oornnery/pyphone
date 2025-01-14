import socket
import time
import uuid
import loggerging
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


# Messages (Message Layer)
class Message:
    def parser(self): ...
    def data(self): ...
    def summary(self): ...
    def header(self): ...
    def body(self): ...

class SipRequest:
    pass

class SipResponse:
    pass

# Connections (Network Layer)
class Connection:
    def send(self): ...
    def receive(self): ...
    def start(self): ...
    def close(self): ...

class SipHandler(Connection):
    pass

class RtpHandler(Connection):
    pass

class DtmfHandler(Connection):
    pass


class SipClient:
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


if __name__ == '__main__':
    pass