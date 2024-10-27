from dataclasses import dataclass, field
from typing import Annotated, TypedDict, Dict, List, Optional, Tuple, Callable
from enum import property, Enum
import re
from datetime import datetime
import uuid
import hashlib
import socket
import asyncio
import time
from abc import ABC


from rich.panel import Panel
from rich.text import Text
from rich.pretty import Pretty












#### Transaction and Connection

class SIPConnection:
    def __init__(self, host: str, port: int, transport: str = 'udp', callback: Callable[[SIPMessage], None] = None):
        self.host = host
        self.port = port
        self.transport = transport
        self.callback = callback
        self.reader: asyncio.StreamReader = None
        self.writer: asyncio.StreamWriter = None
        self.obj_recv = asyncio.get_event_loop().create_task(self.recv)

    async def connect(self):
        if self.transport == 'udp':
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), timeout=5)
        elif self.transport == 'tcp':
            self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        elif self.transport == 'tls':
            self.reader, self.writer = await asyncio.open_connection(self.host, self.port, ssl=True)
        else:
            raise ValueError(f'Invalid transport {self.transport}')

    async def send(self, message: SIPMessage):
        self.writer.write(message.to_bytes())
        await self.writer.drain()

    async def recv(self):
        while True:
            data = await self.reader.read(1024)
            if data:
                message = SIPMessage.from_bytes(data)
                if self.callback:
                    self.callback(message)
            else:
                break


@dataclass
class Transport:
    local_ip: str = field(default='0.0.0.0')
    local_port: str = field(default='10060')
    public_ip: str = field(default='0.0.0.0')
    public_port: str = field(default='0')
    protocol: SIPTransportType = field(default=SIPTransportType.UDP)


@dataclass
class UserAgent:
    domain: str
    port: str
    username: str
    password: str = None


class StackDict(TypedDict):
    call_id: str
    message: SIPMessage


class SIPSession:
    def __init__(self, transport: Transport, user_agent: UserAgent):
        self.transport = transport
        self.user_agent = user_agent
        self.request: StackDict = {}
        self.response: StackDict = {}
        self.auth: Optional[SIPAuthentication] = None
        self.sock = SIPConnection(
            host=self.user_agent.domain,
            port=self.user_agent.port,
            transport=self.transport.protocol,
            callback=self.handle_message
        )
        self.rtp = None

    def handle_message(self, message):
        pass
    
    def set_credentials(self, username: str, password: str):
        """Set authentication credentials"""
        self.auth = SIPAuthentication(username, password)

    def create_sdp(self) -> SDPBody:
        return SDPBody(
            originator_information=f'- {str(uuid.uuid4())} 1 IN IP4 {self.transport.local_ip}',
            session_name=f'{self.user_agent.username}',
            connection_information=f'IN IP4 {self.transport.local_ip}',
            session_time='0 0',
            media_information=(f'audio {self.transport.public_port} RTP/AVP 0 8 101'),
            media_attributes=[
                ('rtpmap', '0 PCMU/8000'),
                ('rtpmap', '8 PCMA/8000'),
                ('ptime', '20'),
                ('rtpmap', '101 telephone-event/8000'),
                ('fmtp', '101 0-15'),
                ('', 'sendrecv')
                ]
        )
    
    def create_header(self) -> SIPHeader:
        return SIPHeader(
            
        )
    
    def


class PyPhone:
    pass
    
    
    
    

if __name__ == '__main__':
    from rich.console import Console
    
    cl = Console()
    
    sdp_str = 'v=0\r\no=root 42852867 42852867 IN IP4 10.130.130.114\r\ns=call\r\nu=call@10.130.130.114\r\ne=mjh@isi.edu\r\np=+1 617 253 6011\r\nz=2882844526 -1h 2898848070 0\r\nt=3034423619 3042462419\r\nt=0 0\r\nr=604800 3600 0 90000\r\nm=audio 61896 RTP 0 8 3 101\r\nm=video 61896 RTP 0 8 3 101\r\nc=IN IP4 10.130.130.114\r\nb=X-YZ:128\r\nk=base64:\r\na=rtpmap:0 pcmu/8000\r\na=rtpmap:8 pcma/8000\r\na=rtpmap:3 gsm/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\na=ptime:20\r\na=sendrecv\r\n'
    sdp = SDPBody.parser(sdp_str)
    
    header_str = 'SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.14.11.146:10060;rport=1024;received=187.75.34.66;branch=z9hG4bK8cafcde14db593eecde1f\r\nv: SIP/2.0/UDP 10.14.11.146:10060;rport=1024;received=187.75.34.66;branch=z9hG4bK8cafcde14db593eecde1f\r\nRecord-Route: <sip:177.53.194.248;transport=tcp;r2=on;ftag=3882100124;lr;did=e4c.5c22>\r\nRecord-Route: <sip:177.53.194.248:5060;r2=on;ftag=3882100124;lr;did=e4c.5c22>\r\nFrom: "P2x9137" <sip:062099137@177.53.194.248:5060>;tag=3882100124\r\nTo: <sip:039959137@177.53.194.248:5060>;tag=as2a08438b\r\nCall-ID: 0_3882207522@10.14.11.146\r\nContact: <sip:039959137@177.53.194.248:5060>\r\nCSeq: 1 INVITE\r\nServer: IDT Brasil Hosted UA\r\nAllow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH\r\nSupported: replaces, timer\r\nContent-Type: application/sdp\r\nX-voipnow-recording: enabled;status: unconditional\r\nX-voipnow-video: deny\r\nContent-Length: 332\r\n\r\nv=0\r\no=root 221186565 221186565 IN IP4 177.53.194.248\r\ns=VoipNow\r\nc=IN IP4 177.53.194.248\r\nt=0 0\r\na=msid-semantic: WMS\r\nm=audio 18590 RTP/AVP 0 8 101\r\nc=IN IP4 177.53.194.248\r\na=rtcp:18591 IN IP4 177.53.194.248\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\na=ptime:20\r\na=sendrecv\r\n'
    header = SIPHeader.parser(header_str)
    
    req = SIPRequest(method=SIPMethod.INVITE, uri='pabx.org:5060', header=header, sdp=sdp)

    cl.print(req)
    username = 'root'
    local_ip = '0.0.0.0'
    public_port = 66666
    sdp3 = SDPBody(
            originator_information=f'- {str(uuid.uuid4())} 1 IN IP4 {local_ip}',
            session_name=f'{username}',
            connection_information=f'IN IP4 {local_ip}',
            session_time='0 0',
            media_information=f'audio {public_port} RTP/AVP 0 8 101',
            media_attributes=[
                ('rtpmap', '0 PCMU/8000'),
                ('rtpmap', '8 PCMA/8000'),
                ('ptime', '20'),
                ('rtpmap', '101 telephone-event/8000'),
                ('fmtp', '101 0-15'),
                ('', 'sendrecv')
                ]
        )
    
    print(sdp3)