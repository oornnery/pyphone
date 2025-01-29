"""
SIP (Session Initiation Protocol)
RFC 3261: https://tools.ietf.org/html/rfc3261

RTP (Real-time Transport Protocol)
RFC 3550: https://tools.ietf.org/html/rfc3550

SDP (Session Description Protocol)
RFC 4566: https://tools.ietf.org/html/rfc4566

DTMF (Dual-tone multi-frequency signaling)
RFC 4733: https://tools.ietf.org/html/rfc4733

"""

import asyncio
import re
import random
import uuid
import time
import socket
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Union

from rich.console import Console
from rich.logging import RichHandler


# Set up logging
console = Console()
logging.basicConfig(
    level="NOTSET",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, console=console)]
)

log = logging.getLogger("rich")

EOL = r"\r\n"
SIP_BRANCH = "z9hG4bK"

# Exceptions
class SIPError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)
    
    def __rich__(self):
        return f"[bold red]{self.message}[/bold red]"

# SIP module
@dataclass
class SIPRequest:
    method: str
    uri: str
    headers: List[Dict[str, str]]
    content: List[Dict[str, str]]

@dataclass
class SIPResponse:
    status_code: int
    reason_phrase: str
    headers: List[Dict[str, str]]
    content: List[Dict[str, str]]

class SIPMessage:
    def __init__(self, message: Union[SIPRequest, SIPResponse]):
        self.message = message

    def _generate_branch(self, len: int = 8):
        """Generate a random branch ID."""
        return f"{SIP_BRANCH}-{uuid.uuid4().hex[:len]}"

    def _generate_call_id(self, host: str = None):
        """Generate a random call ID."""
        host = host or socket.gethostbyname(socket.gethostname())
        return f"{uuid.uuid4().hex}@{host}"

    def _generate_tag(self, len: int = 6):
        """Generate a random tag."""
        return f"{uuid.uuid4().hex[:len]}"

    def _generate_uri(
        self,
        display_name: str = None,
        scheme: str = "sip",
        user: str = None,
        host: str = None,
        port: int = None,
        params: str = None,
        tag: str = None
    ) -> str:
        """Generate a SIP URI."""
        uri = f"<{scheme}:{user}@{host}:{port}>"
        if display_name:
            uri = f"\"{display_name}\" {uri}"
        if params:
            uri = f"{uri};{params}"
        if tag:
            uri = f"{uri};tag={tag}"
        return uri
    
    def _generate_address(
            self,
            address: str,
            port: int = None,
            branch: str = None,
            scheme: str = "SIP",
            version: str = "2.0",
            protocol: str = "UDP",
        ) -> str:
        """Generate a SIP address."""
        branch = branch or self._generate_branch()
        addrs = f"{scheme}/{version}/{protocol} {address}"
        if port:
            addrs = f"{addrs}:{port}"
        if branch:
            addrs = f"{addrs};branch={branch}"
        return addrs
            
    def _parser_headers(self, headers: str) -> List[Dict[str, str]]:
        """Parse SIP headers."""
        return [
            {k: v for k, v in re.findall(r"(?P<key>[\w-]+)\s*:\s*(?P<value>.+)", headers)}
        ]

    def _parser_sdp(self, content: str) -> List[Dict[str, str]]:
        """Parse SIP content."""
        return [
            {k: v for k, v in re.findall(r"(?P<key>\w+)\s*=\s*(?P<value>.+)", content)}
        ]
        
    def _parser_request_line(self, line: str) -> Tuple[str, str, str]:
        """Parse a SIP request line."""
        return re.match(r"(?P<method>\w+) (?P<uri>.+) (?P<scheme>\w+)/(?P<version>\d+\.\d+)", line).groups()

    def _parser_status_line(self, line: str) -> Tuple[str, str, str]:
        """Parse a SIP status line."""
        return re.match(r"(?P<scheme>\w+)/(?P<version>\d+\.\d+) (?P<status_code>\d+) (?P<reason_phrase>.+)", line).groups()

    def _parse_uri(self, uri: str) -> Tuple[str, str, str]:
        """Parse a SIP URI."""
        # display_name, scheme, user, host, port, params, tag
        return re.match(r'(?:\"(?P<display_info>[^\"]+)\"\s+)?<(?P<scheme>\w+):(?:\+)?(?P<user>[^@]+)@(?P<host>[^:;>]+)(?::(?P<port>\d+))?(?:;(?P<params>[^>]+))?>(?:;tag=(?P<tag>[^>\s]+))?', uri).groups()

    def _parser_address(self, address: str) -> Tuple[str, str, str, str, str]:
        """Parse a SIP address."""
        return re.match(r"(?P<scheme>\w+)/(?P<version>\d+\.\d+)/(?P<protocol>\w+) (?P<address>[\d\.]+):(?P<port>\d+);branch=(?P<branch>[\w\.]+)", address).groups()
    
    def __str__(self):
        message = []
        if isinstance(self.message, SIPRequest):
            message.append(f"{self.message.method} {self.message.uri} SIP/{self.message.version}")
        elif isinstance(self.message, SIPResponse):
            message.append(f"SIP/{self.message.version} {self.message.status_code} {self.message.reason_phrase}")
        message.extend(
            {f"{k}: {v}" for header in self.message.headers for k, v in header.items()}
        )
        if self.message.content:
            message.append(EOL)
            message.extend(
                {f"{k}={v}" for content in self.message.content for k, v in content.items()}
            )
        return ''.join([f"{line}{EOL}" for line in message])

    @staticmethod
    def parse(data: str):
        lines = data.split(EOL)
        if lines[0].startswith("SIP"):
            version, status_code, reason_phrase = SIPMessage._parser_status_line(lines[0])
            headers = SIPMessage._parser_headers(EOL.join(lines[1:]))
            content = SIPMessage._parser_sdp(EOL.join(lines[1:]))
            return SIPMessage(SIPResponse(status_code, reason_phrase, headers, content))
        else:
            method, uri, version = SIPMessage._parser_request_line(lines[0])
            headers = SIPMessage._parser_headers(EOL.join(lines[1:]))
            content = SIPMessage._parser_sdp(EOL.join(lines[1:]))
            return SIPMessage(SIPRequest(method, uri, version, headers, content))
    
    def summary(self):
        return self.__str__()
    
    def data(self):
        return self.__str__()




class SIPProtocol:
    def __init__(self):
        self.transport = None
        self.message = None
        self.response = None
        self.buffer = b""
        self._waiter = None

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        self.buffer += data
        if EOL.encode() in self.buffer:
            self._waiter.set_result(self.buffer)
            self.buffer = b""

    def send_message(self, message: SIPMessage):
        self.transport.write(str(message).encode())

    async def send_request(self, message: SIPMessage):
        self._waiter = asyncio.Future()
        self.send_message(message)
        await self._waiter
        return self._waiter.result()

    async def send_response(self, message: SIPMessage):
        self._waiter = asyncio.Future()
        self.send_message(message)
        await self._waiter
        return self._waiter.result()

    def connection_lost(self, exc):
        self.transport = None
    

# RTP module
class RTPProtocol: ...

# SDP module
class SDPProtocol: ...

# DTMF module
class DTMFProtocol: ...

# Audio module
@dataclass
class DeviceConfig: ...

class AudioProtocol: ...

# SIP Client module
@dataclass
class UserAgent: ...

class SIPClient:
    def __init__(
        self,
        user_agent: UserAgent,
        sip_protocol: SIPProtocol = None,
        rtp_protocol: RTPProtocol = None,
        sdp_protocol: SDPProtocol = None,
        dtmf_protocol: DTMFProtocol = None,
        audio_protocol: AudioProtocol = None,
    ):
        self.user_agent = user_agent
        self.sip_protocol = sip_protocol or SIPProtocol()
        self.rtp_protocol = rtp_protocol or RTPProtocol()
        self.sdp_protocol = sdp_protocol or SDPProtocol()
        self.dtmf_protocol = dtmf_protocol or DTMFProtocol()
        self.audio_protocol = audio_protocol or AudioProtocol()

    async def register(self):
        pass
    
    async def make_call(self):
        pass
    
    async def answer_call(self):
        pass
    
    async def reject_call(self):
        pass
    
    async def end_call(self):
        pass
    
    async def send_dtmf(self):
        pass
    
    async def send_message(self):
        pass
    
    async def on(self, event: str):
        pass
    
    async def _await_for_response(self):
        pass
    
    async def _await_for_request(self):
        pass