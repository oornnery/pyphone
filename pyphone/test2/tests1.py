import signal
from dataclasses import dataclass

import logging
import uuid
import socket
from socket import gethostname, gethostbyname, gethostbyname_ex

from typing import Optional, List, Union, Dict, AnyStr

from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from enum import Enum

console = Console()

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(
        console=console,
        rich_tracebacks=True,
        omit_repeated_times=False
        )]
)
logging.getLogger("rich")



class ProtocolType(Enum):
    UDP = ('UDP', socket.SOCK_STREAM)
    TCP = ('TCP', socket.SOCK_DGRAM)

    def __new__(self, desc, s_type):
        obj = object.__new__(self)
        obj.desc = desc
        obj.socket_type = s_type
        return obj

@dataclass
class SIPResponse:
    status_code: int
    status_message: str
    headers: dict
    raw_response: str
    response_time: float
    sequence: int


@dataclass
class UserConfig:
    username: str
    password: str
    remote_ip: str
    remote_port: int
    display_info: str
    local_ip: str
    local_port: str
    public_ip: str
    public_port: str
    user_agent: str


def get_sock(protocol: ProtocolType = ProtocolType.UDP):
    _s = socket.socket()

class EndPoint:
    def __init__(self, host: str, port: int, buffer_size: int = 4096):
        self.host = self._resolve_host(host)
        self.port = port
        self.buffer_size = buffer_size
        self._opt = (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._s = None
        self._c_sock = None

    @staticmethod
    def get_local_ip() -> str:
        '''Get local machine IP address'''
        try:
            _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            _s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            _s.connect(('8.8.8.8', 80))
            local_ip = _s.getsockname()[0]
            _s.close()
            return local_ip
        except Exception as e:
            raise '127.0.0.1'

    @staticmethod
    def get_machine_ips() -> List[str]:
        '''Get all IP address associated with the machine'''
        hostname = gethostname()
        try:
            _, _, ips = gethostbyname(hostname)
            return ips
        except Exception as e:
            return [EndPoint.get_local_ip()]
    
    @staticmethod
    def resolve_dns(hostname: str) -> tuple[str, list[str]]:
        '''Resolve hostname to IP address'''
        try:
            hostname_full, aliases, ips = gethostbyname_ex(hostname)
            return ips[0], ips
        except Exception as e:
            return hostname, [hostname]
    
    def _resolve_host(self, host: str) -> str:
        if host in ('', 'localhost', '0.0.0.0'):
            return self.get_local_ip()
        ip, _ = self.resolve_dns(host)
        return ip

    def create_server(self, protocol: str = 'udp'):
        socket_type = socket.SOCK_DGRAM if protocol.upper() == 'UDP' else socket.SOCK_STREAM
        self._sock = socket.socket(socket.AF_INET, socket_type)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        
        if self.protocol == 'TCP':
            self._sock.listen(5)
        
        return self

    def create_client(self):
        self._c_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self


class Header:
    _headers: Dict[str, Union[AnyStr, List[str], Dict[str, AnyStr]]] = {}

    def _parser_in(name: str):
        return name.replace('-', '_').lower().strip()
        
    def _parser_out(name: str):
        if name.lower().strip() == 'cseq':
            return'CSeq'
        return ''.join([
            x.capitalize() for x in name.replace('_', '-').split('-')
            ]).strip()

    def __getattribute__(self, name):
        _name = self._parser_in(name)
        return self._headers.get(name, None)

    def __setitem__(self, key, value):
        _name = self._parser_in(key)
        _key = self.get(key, None)

        if isinstance(_key, list):
            _key.append(value)
            return
        self._headers.update({key: value})

    def __str__(self):
        h = []
        for k, v in self._headers.items():
            k = self._parser_out(k)
            if isinstance(v, list):
                for x in v:
                    h.append(f'{k}: {x}')
                continue
            h.append(f'{k}: {v}')
        return '\r\n'.join(h)

class Sdp:
    _sdp = {}


class SipMessage:
    def __init__(self, headers: Header, sdp: Sdp = None, **kwargs):
        self.headers: Header = headers
        self.sdp: Sdp = sdp
        self.kwargs = kwargs

    @staticmethod
    def _gen_branch():
        _id = str(uuid.uuid4())[:8]
        return str(f'z9hG4bK{_id}')

    @staticmethod
    def _gen_local_tag():
        return str(uuid.uuid4())[:6]
    
    @staticmethod
    def _gen_call_id() -> str:
        return str(uuid.uuid4())[:23]

    def add_via(self):
        pass

    def add_from(self):
        pass
    
    def add_to(self):
        pass
    
    def add_contact(self):
        pass

    def add_call_id(self):
        pass
    
    def add_cseq(self):
        pass
    
    def add_user_agent(self):
        pass
    
    def add_content_type(self):
        pass
    
    def add_max_forwards(self):
        pass
    
    def add_content_length(self):
        pass

    def get_via(self):
            pass
        
    def get_from(self):
            pass
        
    def get_to(self):
            pass
    
    def get_contact(self):
            pass
    
    def get_call_id(self):
            pass
        
    def get_cseq(self):
            pass
        
    def get_user_agent(self):
            pass
        
    def get_content_type(self):
            pass
        
    def get_max_forwards(self):
            pass
        
    def get_content_length(self):
            pass

    @classmethod
    def parser(cls, message: str) -> 'SipMessage':
        # parser header
        lines = message.split('\r\n')
        if not lines:
            raise ValueError('SipMessage: Empty SIP message')
        # Parser message
        header = []
        sdp = []
        for line in lines[1:]:
            if not line:
                continue
            if ':' in line:
                key, value = line.split(':', 1)
                header.append({key.strip(): value.strip()})
            elif '=' in line:
                key, value = line.split('=', 1)
                sdp.append({key.strip(): value.strip()})
        # Check if is req or res
        if lines[0].startswith('SIP/2.0'):
            status_line = lines[0]
            return SipResponse(status_line=status_line, header=header, sdp=sdp)
        request_line = lines[0]
        return SipRequest(request_line=request_line, header=header, sdp=sdp)


class SipRequest(SipMessage):
    def __init__(self, request_line: str, header: list, sdp: list = None):
        self.request_line = request_line
        self.header: Header = header
        self.sdp = sdp
        super().__init__(self, header=self.header, sdp=self.sdp)

    def __repr__(self):
        _sdp = (f'\r\n{self.sdp}' if self.sdp else '')
        return f'{self.request_line}\r\n{self.header}\r\n{_sdp}'

    @classmethod
    def options(
        cls,
        local_ip: str,
        local_port: str,
        remote_ip: str,
        remote_port: str,
        username: str,
        user_agent: str,
        cseq: str,
        call_id: str = None,
        local_tag: str = None,
        branch: str = None,
        display_info: str = None,
        ):
        h = cls._header_base(
            local_ip=local_ip,
            local_port=local_port,
            branch=(branch if branch else cls.gen_branch()),
            remote_ip=remote_ip,
            remote_port=remote_port,
            local_tag=(local_tag if local_tag else cls.gen_local_tag()),
            user_agent=user_agent,
            call_id=(call_id if call_id else cls.gen_call_id()),
            cseq=cseq,
            method='INVITE',
            display_info=display_info,
            username=username
        )
        request_line = f'INVITE sip:{username}@{remote_ip} SIP/2.0'
        return SipRequest(request_line=request_line, header=h)



class SipResponse(SipMessage):
    def __init__(self, status_line: str, header: list, sdp: list = None):
        self.status_line = status_line
        self.header = header
        self.sdp = sdp

    def __repr__(self):
        return (self.status_line)



class SipOptions:
    def __init__(
        self,
        host: str,
        port: int,
        timeout: int = 3,
        protocol: str = 'udp',
        interval: float = 1.0
        ):
        

        
        self.responses: list[SIPResponse] = []
        self.interrupted = False
        self.start_time = None
        self.end_time = None
        
        
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        logging.info("[yellow]Interrupted by user. Calculating statistics...[/yellow]")
        self.interrupted = True
    




if __name__ == '__main__':
    
    raw_req = "INVITE sip:039959137@177.53.194.248:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.14.11.146:10060;branch=z9hG4bK8cafcde14db593eecde1f\r\nFrom: \"P2x9137\" <sip:062099137@177.53.194.248:5060>;tag=3882100124\r\nTo: <sip:039959137@177.53.194.248:5060>\r\nCall-ID: 0_3882207522@10.14.11.146\r\nCSeq: 1 INVITE\r\nContact: <sip:062099137@10.14.11.146:10060>\r\nContent-Type: application/sdp\r\nAllow: INVITE, INFO, PRACK, ACK, BYE, CANCEL, OPTIONS, NOTIFY, REGISTER, SUBSCRIBE, REFER, PUBLISH, UPDATE, MESSAGE\r\nMax-Forwards: 70\r\nUser-Agent: Yealink SIP-T27G 69.86.0.15\r\nAllow-Events: talk,hold,conference,refer,check-sync\r\nSupported: replaces\r\nContent-Length: 306\r\n\r\nv=0\r\no=- 20211 20211 IN IP4 10.14.11.146\r\ns=SDP data\r\nc=IN IP4 10.14.11.146\r\nt=0 0\r\nm=audio 11808 RTP/AVP 9 0 8 18 101\r\na=rtpmap:9 G722/8000\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:18 G729/8000\r\na=fmtp:18 annexb=no\r\na=ptime:20\r\na=sendrecv\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\n"
    raw_res = "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.14.11.146:10060;rport=1024;received=187.75.34.66;branch=z9hG4bK8cafcde14db593eecde1f\r\nRecord-Route: <sip:177.53.194.248;transport=tcp;r2=on;ftag=3882100124;lr;did=e4c.5c22>\r\nRecord-Route: <sip:177.53.194.248:5060;r2=on;ftag=3882100124;lr;did=e4c.5c22>\r\nFrom: \"P2x9137\" <sip:062099137@177.53.194.248:5060>;tag=3882100124\r\nTo: <sip:039959137@177.53.194.248:5060>;tag=as2a08438b\r\nCall-ID: 0_3882207522@10.14.11.146\r\nContact: <sip:039959137@177.53.194.248:5060>\r\nCSeq: 1 INVITE\r\nServer: IDT Brasil Hosted UA\r\nAllow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH\r\nSupported: replaces, timer\r\nContent-Type: application/sdp\r\nX-voipnow-recording: enabled;status: unconditional\r\nX-voipnow-video: deny\r\nContent-Length: 332\r\n\r\nv=0\r\no=root 221186565 221186565 IN IP4 177.53.194.248\r\ns=VoipNow\r\nc=IN IP4 177.53.194.248\r\nt=0 0\r\na=msid-semantic: WMS\r\nm=audio 18590 RTP/AVP 0 8 101\r\nc=IN IP4 177.53.194.248\r\na=rtcp:18591 IN IP4 177.53.194.248\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\na=ptime:20\r\na=sendrecv\r\n"
    # req = SipMessage.parser(message=raw_req)
    # console.print(req)
    
    # res = SipMessage.parser(message=raw_res)
    # console.print(res)
    
    # o = SipRequest.options(
    #     local_ip='client.domain.com',
    #     local_port=10060,
    #     remote_ip='domain.com',
    #     remote_port=5060,
    #     username='1001',
    #     user_agent='PyPhone',
    #     cseq=1,
    # )
    # print(o)
    
    h = Header()
    h.add({'Via': 'SIP/2.0/UDP'})
