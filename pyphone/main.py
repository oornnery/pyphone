import logging
import sys
import re
import hashlib
import time
import uuid
import asyncio
import ssl
import random
from abc import ABC, abstractmethod
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple, Any, Callable, Set
from datetime import datetime
from asyncio import StreamReader, StreamWriter

from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/pyphone.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


#############
# Exception #
#############

class SIPError(Exception):
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.details = details or {}
        logger.error(Panel(f"[red]{message}[/red]\n\n{self.details}", title="SIP Error", subtitle=self.__class__.__name__, expand=False, border_style="red"))


class ConfigError(SIPError):
    pass


class AuthenticationError(SIPError):
    pass


class TransportError(SIPError):
    pass


class DialogError(SIPError):
    pass


class TransactionError(SIPError):
    pass


class MediaError(SIPError):
    pass


class SDPError(SIPError):
    pass


class DTMFError(SIPError):
    pass


class TimeoutError(SIPError):
    pass


#######################
# Enum and structures #
#######################

class LogLevel(Enum):
    DEBUG = auto()
    INFO = auto()
    WARNING = auto()
    ERROR = auto()
    CRITICAL = auto()


class SIPMethod(Enum):
    REGISTER = auto()
    INVITE = auto()
    ACK = auto()
    BYE = auto()
    CANCEL = auto()
    OPTIONS = auto()
    INFO = auto()
    MESSAGE = auto()
    NOTIFY = auto()
    SUBSCRIBE = auto()
    REFER = auto()
    UPDATE = auto()
    PRACK = auto()


class SIPStatusCode(Enum):
    pass


class TransportProtocol(Enum):
    UDP = auto()
    TCP = auto()
    TLS = auto()
    WS = auto()
    WSS = auto()


class DialogState(Enum):
    INIT = auto()
    EARLY = auto()
    CONFIRMED = auto()
    TERMINATED = auto()


class TransactionState(Enum):
    TRYING = auto()
    PROCEEDING = auto()
    CALLING = auto()
    COMPLETED = auto()
    CONFIRMED = auto()
    CANCELLED = auto()
    FAILED = auto()
    TERMINATED = auto()


class MediaType(Enum):
    AUDIO = auto()
    VIDEO = auto()
    TEXT = auto()
    APPLICATION = auto()
    MESSAGE = auto()


class AuthState(Enum):
    INIT = auto()
    UNAUTHORIZED = auto()
    AUTHORIZED = auto()
    FAILED = auto()


@dataclass
class NetworkConfig:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    transport: TransportProtocol = TransportProtocol.UDP
    use_tls: bool = False
    tls_cert: Optional[str] = None
    tls_key: Optional[str] = None


@dataclass
class MediaConfig:
    rtp_port_range: Tuple[int, int] = (10000, 20000)
    supported_codecs: Dict[str, List[str]] = field(default_factory=lambda: {
        'audio': ['PCMU', 'PCMA', 'telephone-event'],
        'video': ['H264', 'VP8']
    })
    dtmf_mode: str = "rfc2833"
    ptime: int = 20
    maxptime: int = 150


@dataclass
class SIPConfig:
    network: NetworkConfig
    media: MediaConfig
    keep_alive_interval: int = 30
    registration_interval: int = 3600
    timeout: int = 5
    max_retries: int = 3
    user_agent: str = "Pyphone"
    log_level: LogLevel = LogLevel.INFO

    def __post_init__(self):
        self.validate()

    def validate(self):
        if not self.network.local_ip:
            raise ConfigError("Local IP is required")
        if not (0 < self.network.local_port < 65536):
            raise ConfigError("Invalid local port")
        if not self.network.remote_ip:
            raise ConfigError("Remote IP is required")
        if not (0 < self.network.remote_port < 65536):
            raise ConfigError("Invalid remote port")
        if self.network.use_tls and not (self.network.tls_cert and self.network.tls_key):
            raise ConfigError("TLS certificates required when TLS is enabled")
        if not (0 <= self.media.rtp_port_range[0] < self.media.rtp_port_range[1] <= 65535):
            raise ConfigError("Invalid RTP port range")


@dataclass
class AuthCredentials:
    username: str
    password: str
    realm: str
    nonce: str = None
    algorithm: str = field(default="MD5")
    qop: str = field(default="auth")
    cnonce: str = None
    nc: int = field(default=0)
    status: AuthState = field(default=AuthState.INIT)


@dataclass
class Uri:
    scheme: str
    user: str
    host: str
    port: str = None

    def __str__(self):
        return f"{self.scheme}{self.user}@{self.host}{f':{self.port}' if self.port else ''}"


@dataclass
class HeaderField:
    name: str
    value: str

    def __str__(self):
        return f"{self.name}: {self.value}"


@dataclass
class SDPField:
    name: str
    value: str

    def __str__(self):
        return f"{self.name}={self.value}"



#########
# Utils #
#########


def generate_branch() -> str:
    return f"z9hG4bK{uuid.uuid4().hex[:8]}"

def generate_tag() -> str:
    return uuid.uuid4().hex[:8]

def generate_call_id() -> str:
    return str(uuid.uuid4())

def parse_uri(uri: str) -> Dict[str, str]:
    try:
        if uri.startswith(("sip:", "sips:")):
            scheme = uri[:4] if uri.startswith("sip:") else uri[:5]
            rest = uri[len(scheme):]
        else:
            scheme = "sip:"
            rest = uri

        # split user@host:port
        if '@' in rest:
            user, host_port = rest.split('@', 1)
        else:
            user, host_port = None, rest

        # split host:port
        if ':' in host_port:
            host, port = host_port.rsplit(':', 1)
        else:
            host, port = host_port, None

        return {
            'scheme': scheme,
            'user': user,
            'host': host,
            'port': port
        }
    except Exception as e:
        raise ConfigError(f"Invalid SIP URI: {e}")


##################
# Authentication #
##################

class SIPAuthentication:
    def __init__(self, credentials: AuthCredentials):
        self.credentials = credentials
    
    def parser_auth_header(self, auth_header: str) -> None:
        try:
            # parser realm, nonce, qop, algorithm
            realm, nonce, qop, algorithm = 'realm="([^"]+)"', 'nonce="([^"]+)"', \
                'qop="?([^",]+)"?', 'algorithm="?([^",]+)"?'
            if match := re.search(realm, auth_header):
                self.credentials['realm'] = match.group(1)
            if match := re.search(nonce, auth_header):
                self.credentials['nonce'] = match.group(1)
            if match := re.search(qop, auth_header):
                self.credentials['qop'] = match.group(1)
            if match := re.search(algorithm, auth_header):
                self.credentials['algorithm'] = match.group(1)
            logger.debug(
                f"Parsed auth header: realm={self.credentials.realm}, "
                f"nonce={self.credentials.nonce}, qop={self.credentials.qop}"
            )
        except Exception as e:
            raise AuthenticationError(f"Failed to parse auth header: {e}")
    
    def generate_response(self, method: SIPMethod, uri: str) -> Dict[str, str]:
        try:
            # generate HA1
            ha1 = hashlib.md5(
                f"{self.credentials.username}:{self.credentials.realm}:"
                f"{self.credentials.password}".encode()
            ).hexdigest()
            
            # Gera HA2
            ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
            if self.credentials.qop:
                self.credentials.nc
                self.credentials.cnonce = hashlib.md5(
                    str(time.time()).encode()
                ).hexdigest()[:8]

                response = hashlib.md5(
                    f"{ha1}:{self.credentials.nonce}:"
                    f"{self.credentials.nc:08x}:{self.credentials.cnonce}:"
                    f"{self.credentials.qop}:{ha2}".encode()
                ).hexdigest()

                auth_params = {
                    "username": self.credentials.username,
                    "realm": self.credentials.realm,
                    "nonce": self.credentials.nonce,
                    "uri": uri,
                    "response": response,
                    "algorithm": self.credentials.algorithm,
                    "qop": self.credentials.qop,
                    "nc": f"{self.credentials.nc:08x}",
                    "cnonce": self.credentials.cnonce
                }
            else:
                response = hashlib.md5(
                    f"{ha1}:{self.credentials.nonce}:{ha2}".encode()
                ).hexdigest()

                auth_params = {
                    "username": self.credentials.username,
                    "realm": self.credentials.realm,
                    "nonce": self.credentials.nonce,
                    "uri": uri,
                    "response": response,
                    "algorithm": self.credentials.algorithm
                }

            return auth_params

        except Exception as e:
            logger.error(f"Error generating auth response: {e}")
            raise AuthenticationError(f"Failed to generate auth response: {e}")


#############
# Transport #
#############

class TransportBase(ABC):
    
    def __init__(self, config=NetworkConfig):
        self.config = config
        self.running = False
    
    @abstractmethod
    async def start(self) -> None:
        raise SIPError("Transport start method not implemented")
    
    @abstractmethod
    async def stop(self) -> None:
        raise SIPError("Transport stop method not implemented")
    
    @abstractmethod
    async def send(self, data: bytes) -> None:
        raise SIPError("Transport send method not implemented")
    
    @abstractmethod
    async def set_receive_callback(self, callback) -> None:
        raise SIPError("Transport set_receive_callback method not implemented")
    

class AsyncTransport(TransportBase):
    def __init__(self, config: NetworkConfig):
        super().__init__(config)
        self.transport = None
        self.protocol = None
        self.server = None
        self.connections: Dict[tuple, StreamWriter] = {}
        self.receive_callback = None
        self.ssl_context = (self._create_ssl_context()
            if config.transport == TransportProtocol.TLS else None)
    
    class UDPProtocol(asyncio.DatagramProtocol):
        def __init__(self, receive_callback: Callable):
            self.receive_callback = receive_callback

        def datagram_received(self, data: bytes, addr: tuple):
            if not self.receive_callback:
                return
            asyncio.create_task(self.receive_callback(data.decode(), addr))
    
    def _create_ssl_context(self):
        try:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            if self.config.tls_cert and self.config.tls_key:
                context.load_cert_chain(
                    self.config.tls_cert,
                    self.config.tls_key)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context
        except Exception as e:
            raise TransportError(f"Failed to create SSL context:", e)

    async def start(self):
        try:
            match self.config.transport:
                case TransportProtocol.UDP:
                    loop = asyncio.get_running_loop()
                    self.transport, self.protocol = await loop.create_datagram_endpoint(
                        lambda: self.UDPProtocol(self.receive_callback),
                        local_addr=(self.config.local_ip, self.config.local_port)
                    )
                case TransportProtocol.TCP | TransportProtocol.TLS:
                    ssl_context = (self.ssl_context if 
                        self.config.transport == TransportProtocol.TLS else None)
                    self.server = await asyncio.start_server(
                        self._handle_connection,
                        self.config.local_ip,
                        self.config.local_port,
                        ssl=ssl_context
                    )
                case _:
                    raise TransportError(f"Unsupported transport protocol: {self.config.transport}")
            if self.config.transport in (TransportProtocol.TCP, TransportProtocol.TLS):
                asyncio.create_task(self.server.serve_forever())
            self.running = True
            logger.info(f"{self.config.transport} transport started on {self.config.local_ip}:{self.config.local_port}")
        except Exception as e:
            raise TransportError(f"Failed to start UDP transport: {e}")
    
    async def stop(self):        
        try:
            if (self.config.transport == TransportProtocol.UDP and self.transport):
                self.transport.close()
                return
            if self.server:
                self.server.close()
                await self.server.wait_closed()
            for writer in self.connections.values():
                writer.close()
                await writer.wait_closed()
        except Exception as e:
            raise TransportError(f"Failed to stop transport: {e}")
        else:
            self.running = False
            logger.info(f"{self.config.transport} transport stopped")

    async def send(self, message: str, address: Tuple[str, int]):
        try:
            if not self.transport:
                raise TransportError("Transport not initialized")

            match self.config.transport:
                case TransportProtocol.UDP:
                    self.transport.sendto(message.encode(), address)
                case TransportProtocol.TCP | TransportProtocol.TLS:
                    if address not in self.connections:
                        ssl_context = (self.ssl_context if self.config.transport == TransportProtocol.TLS else None)
                        reader, writer = await asyncio.open_connection(
                            *address, 
                            ssl=ssl_context
                        )
                        self.connections[address] = writer
                case _:
                    raise TransportError(f"Unsupported transport protocol: {self.config.transport}")
            
            if self.config.transport in (TransportProtocol.TCP, TransportProtocol.TLS):
                writer = self.connections[address]
                writer.write(message.encode())
                await writer.drain()
            logger.debug(f"Sent message to {address}: {message}")
        except Exception as e:
            raise TransportError(f"Failed to send UDP message: {e}")

    async def set_receive_callback(self, callback: Callable):
        self.receive_callback = callback
        logger.debug("Receive callback set")

    async def _handle_connection(self, reader: StreamReader, writer: StreamWriter):
        addr = writer.get_extra_info('peername')
        self.connections[addr] = writer
        try:
            while self.running:
                data = await reader.read(8192)
                if not data:
                    break
                if self.receive_callback:
                    await self.receive_callback(data.decode(), addr)
        except Exception as e:
            logger.error(f"Error handling {self.config.transport} connection: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            del self.connections[addr]


class TransportManager:    
    def __init__(self, config: NetworkConfig):
        self.config = config
        self.transport = AsyncTransport(config)

    async def start(self, receive_callback: Callable):
        await self.transport.set_receive_callback(receive_callback)
        await self.transport.start()

    async def stop(self):
        await self.transport.stop()

    async def send_message(self, message: str, address: tuple):
        await self.transport.send(message, address)    


###############
# SIP Message #
###############

class Headers:
    _headers: List[HeaderField] = []

    def __str__(self):
        return '\r\n'.join([str(h) for h in self._headers])
    
    def add(self, header: HeaderField):
        self._headers.append(header)
    
    def remove(self, name: str):
        self._headers = [h for h in self._headers if h.name != name]
    
    def get(self, name: str) -> Optional[HeaderField]:
        for header in self._headers:
            if header.name == name:
                return header
        return None


class Body:
    _sdp: List[SDPField] = []

    def __str__(self):
        return '\r\n'.join([str(s) for s in self._sdp])
    
    def add(self, sdp: SDPField):
        self._sdp.append(sdp)
    
    def remove(self, name: str):
        self._sdp = [s for s in self._sdp if s.name != name]
    
    def get(self, name: str) -> Optional[SDPField]:
        for sdp in self._sdp:
            if sdp.name == name:
                return sdp
        return None


@dataclass
class SDPMediaFormat:
    """Formato de mídia SDP"""
    payload_type: int
    encoding_name: str
    clock_rate: int
    channels: Optional[int] = None
    parameters: Dict[str, str] = field(default_factory=dict)

    def __str__(self) -> str:
        fmt = f"{self.encoding_name}/{self.clock_rate}"
        if self.channels and self.channels > 1:
            fmt += f"/{self.channels}"
        return fmt

@dataclass
class SDPMediaDescription:
    """Descrição de mídia SDP"""
    type: str
    port: int
    protocol: str
    formats: List[SDPMediaFormat]
    attributes: List[str] = field(default_factory=list)
    bandwidth: Dict[str, int] = field(default_factory=dict)
    connection: Optional[str] = None

class SDPManager:
    """Gerenciador de SDP"""

    def __init__(self, config: MediaConfig):
        self.config = config
        self.logger = logger

    def create_offer(self, local_ip: str, media_port: int) -> str:
        """Cria oferta SDP"""
        try:
            session_id = int(time.time())
            sdp_lines = [
                "v=0",
                f"o=- {session_id} {session_id} IN IP4 {local_ip}",
                "s=SIP Call",
                f"c=IN IP4 {local_ip}",
                "t=0 0"
            ]

            # Adiciona descrição de mídia de áudio
            audio_formats = []
            for codec in self.config.supported_codecs['audio']:
                if codec == 'PCMU':
                    audio_formats.append(SDPMediaFormat(0, 'PCMU', 8000, 1))
                elif codec == 'PCMA':
                    audio_formats.append(SDPMediaFormat(8, 'PCMA', 8000, 1))
                elif codec == 'telephone-event':
                    audio_formats.append(SDPMediaFormat(101, 'telephone-event', 8000))

            media_desc = self._create_media_description(
                'audio', media_port, audio_formats
            )
            sdp_lines.extend(self._format_media_description(media_desc))

            return "\r\n".join(sdp_lines) + "\r\n"

        except Exception as e:
            self.logger.error(f"Error creating SDP offer: {e}")
            raise SDPError(f"Failed to create SDP offer: {e}")

    def parse_sdp(self, sdp: str) -> Dict[str, Any]:
        """Parse de SDP"""
        try:
            result = {
                'version': 0,
                'origin': {},
                'session_name': '',
                'connection': {},
                'time': [],
                'media': []
            }

            lines = sdp.strip().split("\r\n")
            current_media = None

            for line in lines:
                type_, value = line[0], line[2:]

                if type_ == 'v':
                    result['version'] = int(value)
                elif type_ == 'o':
                    parts = value.split()
                    result['origin'] = {
                        'username': parts[0],
                        'session_id': parts[1],
                        'session_version': parts[2],
                        'network_type': parts[3],
                        'address_type': parts[4],
                        'address': parts[5]
                    }
                elif type_ == 'c':
                    parts = value.split()
                    result['connection'] = {
                        'network_type': parts[0],
                        'address_type': parts[1],
                        'address': parts[2]
                    }
                elif type_ == 'm':
                    parts = value.split()
                    current_media = {
                        'type': parts[0],
                        'port': int(parts[1]),
                        'protocol': parts[2],
                        'formats': parts[3:],
                        'attributes': []
                    }
                    result['media'].append(current_media)
                elif type_ == 'a' and current_media:
                    current_media['attributes'].append(value)

            return result

        except Exception as e:
            self.logger.error(f"Error parsing SDP: {e}")
            raise SDPError(f"Failed to parse SDP: {e}")

    def _create_media_description(self, media_type: str, port: int, 
                                formats: List[SDPMediaFormat]) -> SDPMediaDescription:
        """Cria descrição de mídia"""
        media_desc = SDPMediaDescription(
            type=media_type,
            port=port,
            protocol="RTP/AVP",
            formats=formats
        )

        # Adiciona atributos comuns
        media_desc.attributes.append("sendrecv")
        media_desc.attributes.append(f"ptime:{self.config.ptime}")
        media_desc.attributes.append(f"maxptime:{self.config.maxptime}")

        # Adiciona rtpmap para cada formato
        for fmt in formats:
            media_desc.attributes.append(
                f"rtpmap:{fmt.payload_type} {fmt}"
            )
            if fmt.parameters:
                params = " ".join(
                    f"{k}={v}" if v else k
                    for k, v in fmt.parameters.items()
                )
                media_desc.attributes.append(
                    f"fmtp:{fmt.payload_type} {params}"
                )

        return media_desc

    def _format_media_description(self, media_desc: SDPMediaDescription) -> List[str]:
        """Formata descrição de mídia em linhas SDP"""
        lines = []
        
        # Linha de mídia
        formats_str = " ".join(str(fmt.payload_type) for fmt in media_desc.formats)
        lines.append(
            f"m={media_desc.type} {media_desc.port} {media_desc.protocol} {formats_str}"
        )

        # Conexão específica se diferente da global
        if media_desc.connection:
            lines.append(f"c={media_desc.connection}")

        # Bandwidth
        for bw_type, value in media_desc.bandwidth.items():
            lines.append(f"b={bw_type}:{value}")

        # Atributos
        for attr in media_desc.attributes:
            lines.append(f"a={attr}")

        return lines

class DTMFEvent:
    """Evento DTMF"""
    
    DTMF_EVENTS = {
        '0': 0, '1': 1, '2': 2, '3': 3, '4': 4,
        '5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
        '*': 10, '#': 11, 'A': 12, 'B': 13, 'C': 14, 'D': 15
    }

    def __init__(self, digit: str, duration: int = 160, volume: int = 10):
        if digit.upper() not in self.DTMF_EVENTS:
            raise ValueError(f"Invalid DTMF digit: {digit}")
            
        self.digit = digit.upper()
        self.event_id = self.DTMF_EVENTS[self.digit]
        self.duration = min(duration, 16000)  # RFC limitation
        self.volume = max(0, min(volume, 63))  # RFC limitation
        self.timestamp = int(time.time() * 1000)
        self.end = False

class DTMFManager:
    """Gerenciador de DTMF"""

    def __init__(self, mode: str = "rfc2833"):
        self.mode = mode
        self.callbacks: Dict[str, Set[Callable]] = {
            'on_dtmf_sent': set(),
            'on_dtmf_received': set(),
            'on_error': set()
        }
        self.logger = logger

    async def send_dtmf(self, digit: str, duration: int = 160) -> None:
        """Envia DTMF"""
        try:
            event = DTMFEvent(digit, duration)
            
            if self.mode == "rfc2833":
                await self._send_rfc2833(event)
            elif self.mode == "info":
                await self._send_info(event)
            
            await self._trigger_callbacks('on_dtmf_sent', event)
            
        except Exception as e:
            self.logger.error(f"Error sending DTMF: {e}")
            await self._trigger_callbacks('on_error', e)

    async def _send_rfc2833(self, event: DTMFEvent) -> None:
        """Envia DTMF via RFC 2833"""
        try:
            # Implementação do envio RFC 2833
            # Este é um placeholder - a implementação real depende do RTP
            pass
        except Exception as e:
            raise DTMFError(f"Failed to send RFC2833 DTMF: {e}")

    async def _send_info(self, event: DTMFEvent) -> None:
        """Envia DTMF via SIP INFO"""
        try:
            # Implementação do envio INFO
            # Este é um placeholder - a implementação real depende do SIP
            pass
        except Exception as e:
            raise DTMFError(f"Failed to send INFO DTMF: {e}")

    def add_callback(self, event: str, callback: Callable) -> None:
        """Adiciona callback para evento"""
        if event in self.callbacks:
            self.callbacks[event].add(callback)

    async def _trigger_callbacks(self, event: str, *args, **kwargs) -> None:
        """Dispara callbacks para um evento"""
        if event in self.callbacks:
            for callback in self.callbacks[event]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(*args, **kwargs)
                    else:
                        callback(*args, **kwargs)
                except Exception as e:
                    self.logger.error(f"Error in DTMF callback: {e}")


class SIPMessage:
    def __init__(self, 
            raw: Optional[str] = None,
            method: Optional[SIPMethod] = None,
            status_code: Optional[SIPStatusCode] = None,
            uri: Optional[Uri] = None,
            headers: Optional[Headers] = None,
            body: Optional[Body] = None
            ):
        self.raw = raw
        self.method = method
        self.status_code = status_code
        self.uri = uri
        self.headers = headers or Headers()
        self.body = body or Body()

    @property
    def is_request(self) -> bool:
        return self.method is not None

    @property
    def is_response(self) -> bool:
        return self.status_code is not None

    @property
    def summary(self) -> str:
        return ''
    
    @staticmethod
    def build_request(
        cls,
        method: SIPMethod,
        uri: Uri,
        headers: Headers,
        body: Body
    ) -> 'SIPMessage':
        
        return cls(method=method, uri=uri, headers=headers, body=body)
    
    
    @staticmethod
    def build_response(
        cls,
        status_code: SIPStatusCode,
        headers: Headers,
        body: Body
    ) -> 'SIPMessage':
        
        return cls(status_code=status_code, headers=headers, body=body)

    @staticmethod
    def parse_message(raw: str) -> 'SIPMessage':
    
        return SIPMessage(raw=raw)


class SIPTransaction:
    def __init__(self, method: SIPMethod, message: SIPMessage, branch: str):
        self.method = method
        self.branch = branch
        self.state = TransactionState.TRYING
        self.request: Optional[SIPMessage] = None
        self.responses: List[SIPMessage] = []
        self.created_at = datetime.now()
        self.completed_at: Optional[datetime] = None
        self.retries = 0
        self.max_retries = 3
        self.timeout = 32
        self.callbacks: Dict[str, Set[Callable]] = {
            'on_trying': set(),
            'on_proceeding': set(),
            'on_completed': set(),
            'on_terminated': set(),
            'on_timeout': set(),
            'on_error': set()
        }

    async def add_response(self, response: SIPMessage) -> None:
        try:
            self.responses.append(response)
            #TODO: Update state based on response status code
            await self._update_state(TransactionState.PROCEEDING)
                
        except Exception as e:
            logger.error(f"Error adding response: {e}")
            await self._trigger_callbacks('on_error', e)

    async def _update_state(self, new_state: TransactionState) -> None:
        """Atualiza estado da transação"""
        if new_state != self.state:
            old_state = self.state
            self.state = new_state
            logger.debug(
                f"Transaction {self.branch} state changed: {old_state} -> {new_state}"
            )
            
            # Trigger callbacks baseado no novo estado
            if new_state == TransactionState.TRYING:
                await self._trigger_callbacks('on_trying')
            elif new_state == TransactionState.PROCEEDING:
                await self._trigger_callbacks('on_proceeding')
            elif new_state == TransactionState.COMPLETED:
                await self._trigger_callbacks('on_completed')
            elif new_state == TransactionState.TERMINATED:
                await self._trigger_callbacks('on_terminated')

    def add_callback(self, event: str, callback: Callable) -> None:
        """Adiciona callback para evento"""
        if event in self.callbacks:
            self.callbacks[event].add(callback)

    async def _trigger_callbacks(self, event: str, *args, **kwargs) -> None:
        """Dispara callbacks para um evento"""
        if event in self.callbacks:
            for callback in self.callbacks[event]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(*args, **kwargs)
                    else:
                        callback(*args, **kwargs)
                except Exception as e:
                    logger.error(f"Error in transaction callback: {e}")


class SIPDialog:
    def __init__(self, call_id: str, local_tag: str, remote_tag: Optional[str] = None):
        self.call_id = call_id
        self.local_tag = local_tag
        self.remote_tag = remote_tag
        self.local_seq = random.randint(1, 65535)
        self.remote_seq = 0
        self.state = DialogState.INIT
        self.local_uri: Optional[str] = None
        self.remote_uri: Optional[str] = None
        self.remote_target: Optional[str] = None
        self.secure = False
        self.created_at = datetime.now()
        self.transactions: Dict[str, SIPTransaction] = {}
        self.callbacks: Dict[str, Set[Callable]] = {
            'on_state_changed': set(),
            'on_terminated': set(),
            'on_error': set()
        }

    async def update_state(self, new_state: DialogState) -> None:
        """Atualiza estado do diálogo"""
        if new_state != self.state:
            old_state = self.state
            self.state = new_state
            logger.debug(
                f"Dialog {self.call_id} state changed: {old_state} -> {new_state}"
            )
            await self._trigger_callbacks('on_state_changed', old_state, new_state)

    def add_transaction(self, transaction: SIPTransaction) -> None:
        """Adiciona transação ao diálogo"""
        self.transactions[transaction.branch] = transaction

    def get_transaction(self, branch: str) -> Optional[SIPTransaction]:
        """Recupera transação pelo branch"""
        return self.transactions.get(branch)

    def add_callback(self, event: str, callback: Callable) -> None:
        """Adiciona callback para evento"""
        if event in self.callbacks:
            self.callbacks[event].add(callback)

    async def _trigger_callbacks(self, event: str, *args, **kwargs) -> None:
        """Dispara callbacks para um evento"""
        if event in self.callbacks:
            for callback in self.callbacks[event]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(*args, **kwargs)
                    else:
                        callback(*args, **kwargs)
                except Exception as e:
                    logger.error(f"Error in dialog callback: {e}")


class DialogManager:
    """Gerenciador de diálogos SIP"""

    def __init__(self):
        self.dialogs: Dict[str, SIPDialog] = {}

    def create_dialog(self, call_id: str, local_tag: str, 
                     remote_tag: Optional[str] = None) -> SIPDialog:
        """Cria novo diálogo"""
        dialog = SIPDialog(call_id, local_tag, remote_tag)
        self.dialogs[call_id] = dialog
        return dialog

    def get_dialog(self, call_id: str) -> Optional[SIPDialog]:
        """Recupera diálogo pelo Call-ID"""
        return self.dialogs.get(call_id)

    async def terminate_dialog(self, call_id: str) -> None:
        """Termina um diálogo"""
        dialog = self.dialogs.get(call_id)
        if dialog:
            await dialog.update_state(DialogState.TERMINATED)
            await dialog._trigger_callbacks('on_terminated')
            del self.dialogs[call_id]

    def find_dialog(self, message: SIPMessage) -> Optional[SIPDialog]:
        """Encontra diálogo correspondente a uma mensagem"""
        call_id = message.headers.get('Call-ID')
        if not call_id:
            return None
            
        dialog = self.dialogs.get(call_id)
        if dialog:
            # Verifica tags
            from_tag = self._extract_tag(message.headers.get('From', ''))
            to_tag = self._extract_tag(message.headers.get('To', ''))
            
            if dialog.local_tag == from_tag and dialog.remote_tag == to_tag:
                return dialog
                
        return None

    @staticmethod
    def _extract_tag(header: str) -> Optional[str]:
        """Extrai tag de um header"""
        match = re.search(r'tag=([^;>\s]+)', header)
        return match.group(1) if match else None

class EventManager:
    """Gerenciador de eventos"""

    def __init__(self):
        self.handlers: Dict[str, Set[Callable]] = {
            # Eventos SIP
            'on_register_success': set(),
            'on_register_failure': set(),
            'on_invite_received': set(),
            'on_invite_success': set(),
            'on_invite_failure': set(),
            'on_bye_received': set(),
            'on_bye_success': set(),
            'on_cancel_received': set(),
            'on_message_received': set(),
            'on_message_success': set(),
            'on_info_received': set(),
            'on_info_success': set(),
            
            # Eventos de diálogo
            'on_dialog_established': set(),
            'on_dialog_terminated': set(),
            
            # Eventos de mídia
            'on_media_established': set(),
            'on_media_terminated': set(),
            'on_dtmf_received': set(),
            'on_dtmf_sent': set(),
            
            # Eventos de erro
            'on_transport_error': set(),
            'on_media_error': set(),
            'on_general_error': set()
        }
        self.logger = logger

    def add_handler(self, event: str, handler: Callable) -> None:
        """Adiciona handler para evento"""
        if event in self.handlers:
            self.handlers[event].add(handler)
        else:
            raise ValueError(f"Unknown event type: {event}")

    def remove_handler(self, event: str, handler: Callable) -> None:
        """Remove handler de evento"""
        if event in self.handlers and handler in self.handlers[event]:
            self.handlers[event].remove(handler)

    async def trigger_event(self, event: str, *args, **kwargs) -> None:
        """Dispara evento"""
        if event in self.handlers:
            for handler in self.handlers[event]:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(*args, **kwargs)
                    else:
                        handler(*args, **kwargs)
                except Exception as e:
                    self.logger.error(f"Error in event handler {event}: {e}")
                    await self.trigger_event('on_general_error', e)
                    
                    
class AsyncSIPManager:
    """Gerenciador principal SIP assíncrono"""

    def __init__(self, config: SIPConfig, auth: Optional[AuthCredentials] = None):
        self.config = config
        self.auth = auth
        self.transport_manager = TransportManager(config.network)
        self.dialog_manager = DialogManager()
        self.sdp_manager = SDPManager(config.media)
        self.dtmf_manager = DTMFManager(config.media.dtmf_mode)
        self.event_manager = EventManager()
        self.running = False
        self.registered = False
        self.logger = logger

    async def start(self) -> None:
        """Inicia o gerenciador SIP"""
        try:
            self.running = True
            await self.transport_manager.start(self._handle_incoming_message)
            await self._start_keep_alive()
            self.logger.info("SIP Manager started successfully")
        except Exception as e:
            self.logger.error(f"Failed to start SIP Manager: {e}")
            await self.stop()
            raise

    async def stop(self) -> None:
        """Para o gerenciador SIP"""
        try:
            self.running = False
            await self.transport_manager.stop()
            # Termina todos os diálogos ativos
            for dialog_id in list(self.dialog_manager.dialogs.keys()):
                await self.dialog_manager.terminate_dialog(dialog_id)
            self.logger.info("SIP Manager stopped")
        except Exception as e:
            self.logger.error(f"Error stopping SIP Manager: {e}")
            raise

    async def register(self, force: bool = False) -> None:
        """Realiza registro SIP"""
        try:
            if not self.auth:
                raise AuthenticationError("Authentication required for registration")

            transaction = SIPTransaction(
                method=SIPMethod.REGISTER,
                branch=generate_branch()
            )

            headers = {
                "Via": f"SIP/2.0/{self.config.network.transport.value} "
                      f"{self.config.network.local_ip}:{self.config.network.local_port};"
                      f"branch={transaction.branch}",
                "From": f"<sip:{self.auth.username}@{self.config.network.remote_ip}>"
                       f";tag={generate_tag()}",
                "To": f"<sip:{self.auth.username}@{self.config.network.remote_ip}>",
                "Call-ID": generate_call_id(),
                "CSeq": "1 REGISTER",
                "Contact": f"<sip:{self.auth.username}@{self.config.network.local_ip}:"
                         f"{self.config.network.local_port}>",
                "Expires": str(self.config.registration_interval),
                "Max-Forwards": "70",
                "User-Agent": self.config.user_agent
            }

            request = SIPMessage.build_request(
                method=SIPMethod.REGISTER,
                uri=f"sip:{self.config.network.remote_ip}",
                headers=headers
            )

            # Configura callbacks da transação
            transaction.add_callback('on_completed', self._handle_register_response)
            transaction.add_callback('on_error', self._handle_register_error)

            await self._send_request(request, transaction)
            self.logger.info("Sent REGISTER request")

        except Exception as e:
            self.logger.error(f"Registration error: {e}")
            await self.event_manager.trigger_event('on_register_failure', str(e))
            raise

    async def invite(self, to_uri: str) -> str:
        """Inicia uma chamada"""
        try:
            call_id = generate_call_id()
            dialog = self.dialog_manager.create_dialog(
                call_id=call_id,
                local_tag=generate_tag()
            )

            transaction = SIPTransaction(
                method=SIPMethod.INVITE,
                branch=generate_branch()
            )

            # Cria oferta SDP
            media_port = self._allocate_media_port()
            sdp_offer = self.sdp_manager.create_offer(
                self.config.network.local_ip,
                media_port
            )

            headers = {
                "Via": f"SIP/2.0/{self.config.network.transport.value} "
                      f"{self.config.network.local_ip}:{self.config.network.local_port};"
                      f"branch={transaction.branch}",
                "From": f"<sip:{self.auth.username}@{self.config.network.remote_ip}>"
                       f";tag={dialog.local_tag}",
                "To": f"<{to_uri}>",
                "Call-ID": call_id,
                "CSeq": f"{dialog.local_seq} INVITE",
                "Contact": f"<sip:{self.auth.username}@{self.config.network.local_ip}:"
                         f"{self.config.network.local_port}>",
                "Content-Type": "application/sdp"
            }

            request = SIPMessage.build_request(
                method=SIPMethod.INVITE,
                uri=to_uri,
                headers=headers,
                body=sdp_offer
            )

            # Configura callbacks
            transaction.add_callback('on_proceeding', self._handle_invite_proceeding)
            transaction.add_callback('on_completed', self._handle_invite_completed)
            transaction.add_callback('on_error', self._handle_invite_error)

            dialog.add_transaction(transaction)
            await self._send_request(request, transaction)
            
            self.logger.info(f"Sent INVITE request for dialog {call_id}")
            return call_id

        except Exception as e:
            self.logger.error(f"Error sending INVITE: {e}")
            await self.event_manager.trigger_event('on_invite_failure', str(e))
            raise

    async def send_dtmf(self, dialog_id: str, digit: str) -> None:
        """Envia DTMF"""
        try:
            dialog = self.dialog_manager.get_dialog(dialog_id)
            if not dialog:
                raise DialogError(f"No dialog found with ID: {dialog_id}")

            await self.dtmf_manager.send_dtmf(digit)
            
        except Exception as e:
            self.logger.error(f"Error sending DTMF: {e}")
            await self.event_manager.trigger_event('on_general_error', str(e))
            raise

    async def terminate_dialog(self, dialog_id: str) -> None:
        """Termina um diálogo"""
        try:
            dialog = self.dialog_manager.get_dialog(dialog_id)
            if not dialog:
                raise DialogError(f"No dialog found with ID: {dialog_id}")

            # Envia BYE
            transaction = SIPTransaction(
                method=SIPMethod.BYE,
                branch=generate_branch()
            )

            headers = {
                "Via": f"SIP/2.0/{self.config.network.transport.value} "
                      f"{self.config.network.local_ip}:{self.config.network.local_port};"
                      f"branch={transaction.branch}",
                "From": f"<sip:{self.auth.username}@{self.config.network.remote_ip}>"
                       f";tag={dialog.local_tag}",
                "To": f"<{dialog.remote_uri}>;tag={dialog.remote_tag}",
                "Call-ID": dialog.call_id,
                "CSeq": f"{dialog.local_seq} BYE"
            }

            request = SIPMessage.build_request(
                method=SIPMethod.BYE,
                uri=dialog.remote_target,
                headers=headers
            )

            transaction.add_callback('on_completed', self._handle_bye_response)
            dialog.add_transaction(transaction)
            await self._send_request(request, transaction)

        except Exception as e:
            self.logger.error(f"Error terminating dialog: {e}")
            await self.event_manager.trigger_event('on_general_error', str(e))
            raise

    async def _handle_incoming_message(self, message: str, addr: tuple) -> None:
        """Manipula mensagens recebidas"""
        try:
            parsed_message = SIPMessage.parse_message(message)
            
            if parsed_message.is_request:
                await self._handle_request(parsed_message, addr)
            else:
                await self._handle_response(parsed_message, addr)
                
        except Exception as e:
            self.logger.error(f"Error handling incoming message: {e}")
            await self.event_manager.trigger_event('on_general_error', str(e))

    async def _handle_request(self, message: SIPMessage, addr: tuple) -> None:
        """Manipula requisições recebidas"""
        try:
            method = message.method
            if method == SIPMethod.INVITE:
                await self._handle_incoming_invite(message, addr)
            elif method == SIPMethod.BYE:
                await self._handle_incoming_bye(message, addr)
            elif method == SIPMethod.INFO:
                await self._handle_incoming_info(message, addr)
            else:
                # Método não suportado
                await self._send_response(
                    message, 405, "Method Not Allowed", addr
                )
                
        except Exception as e:
            self.logger.error(f"Error handling request: {e}")
            await self._send_response(
                message, 500, "Internal Server Error", addr
            )

    # Implementação dos handlers de resposta
    async def _handle_register_response(self, transaction: SIPTransaction) -> None:
        """Manipula resposta de REGISTER"""
        response = transaction.responses[-1]
        if 200 <= response.status_code < 300:
            self.registered = True
            await self.event_manager.trigger_event('on_register_success')
        else:
            await self.event_manager.trigger_event(
                'on_register_failure',
                response.status_code
            )

    async def _handle_invite_proceeding(self, transaction: SIPTransaction) -> None:
        """Manipula resposta provisória de INVITE"""
        response = transaction.responses[-1]
        await self.event_manager.trigger_event(
            'on_invite_progress',
            response.status_code
        )

    async def _handle_invite_completed(self, transaction: SIPTransaction) -> None:
        """Manipula resposta final de INVITE"""
        response = transaction.responses[-1]
        if 200 <= response.status_code < 300:
            # Processa SDP da resposta
            if response.body:
                sdp = self.sdp_manager.parse_sdp(response.body)
                # Configura mídia com base no SDP
                # (implementação depende do RTP)
            
            await self.event_manager.trigger_event('on_invite_success')
        else:
            await self.event_manager.trigger_event(
                'on_invite_failure',
                response.status_code
            )

    # Métodos auxiliares
    def _allocate_media_port(self) -> int:
        """Aloca porta para mídia"""
        # Implementação simplificada - deve ser melhorada
        return self.config.media.rtp_port_range[0]

    async def _start_keep_alive(self) -> None:
        """Inicia keep-alive"""
        while self.running:
            try:
                if self.registered:
                    # Envia OPTIONS como keep-alive
                    await self._send_options()
                await asyncio.sleep(self.config.keep_alive_interval)
            except Exception as e:
                self.logger.error(f"Keep-alive error: {e}")
                await asyncio.sleep(1)

class SIPClient:
    """Cliente SIP base"""

    def __init__(self, config: SIPConfig, credentials: AuthCredentials):
        self.config = config
        self.credentials = credentials
        self.sip_manager = AsyncSIPManager(config, credentials)
        self._setup_handlers()

    def _setup_handlers(self) -> None:
        """Configura handlers de eventos padrão"""
        self.sip_manager.event_manager.add_handler(
            'on_register_success',
            self.on_registered
        )
        self.sip_manager.event_manager.add_handler(
            'on_invite_received',
            self.on_invite_received
        )
        self.sip_manager.event_manager.add_handler(
            'on_invite_success',
            self.on_call_established
        )
        self.sip_manager.event_manager.add_handler(
            'on_dialog_terminated',
            self.on_call_terminated
        )
        self.sip_manager.event_manager.add_handler(
            'on_dtmf_received',
            self.on_dtmf_received
        )

    async def start(self) -> None:
        """Inicia o cliente"""
        try:
            await self.sip_manager.start()
            await self.sip_manager.register()
            self.logger.info("SIP Client started")
        except Exception as e:
            self.logger.error(f"Error starting client: {e}")
            raise

    async def stop(self) -> None:
        """Para o cliente"""
        await self.sip_manager.stop()
        self.logger.info("SIP Client stopped")

    async def make_call(self, to_uri: str) -> str:
        """Inicia uma chamada"""
        return await self.sip_manager.invite(to_uri)

    async def end_call(self, call_id: str) -> None:
        """Termina uma chamada"""
        await self.sip_manager.terminate_dialog(call_id)

    async def send_dtmf(self, call_id: str, digit: str) -> None:
        """Envia DTMF"""
        await self.sip_manager.send_dtmf(call_id, digit)

    # Callbacks que podem ser sobrescritos
    async def on_registered(self) -> None:
        """Chamado quando registrado com sucesso"""
        self.logger.info("Successfully registered")

    async def on_invite_received(self, dialog_id: str, remote_uri: str) -> None:
        """Chamado quando recebe INVITE"""
        self.logger.info(f"Received call from {remote_uri}")

    async def on_call_established(self, dialog_id: str) -> None:
        """Chamado quando chamada é estabelecida"""
        self.logger.info(f"Call established: {dialog_id}")

    async def on_call_terminated(self, dialog_id: str) -> None:
        """Chamado quando chamada é terminada"""
        self.logger.info(f"Call terminated: {dialog_id}")

    async def on_dtmf_received(self, dialog_id: str, digit: str) -> None:
        """Chamado quando recebe DTMF"""
        self.logger.info(f"Received DTMF {digit} in call {dialog_id}")


