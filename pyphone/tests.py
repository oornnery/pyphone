import asyncio
import logging
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type

import click
import structlog
import yaml
from prometheus_client import Counter, Gauge, Histogram
from pydantic import BaseModel, validator
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import Progress
from rich.prompt import Prompt
from rich.table import Table


# pyphone/logging/advanced.py
def setup_logging(log_level: str = "INFO", 
                 log_file: str = None,
                 enable_rich: bool = True):
    """Configura logging avançado com structlog e rich."""
    
    # Configurar processadores structlog
    processors = [
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]
    
    if enable_rich:
        processors.append(structlog.dev.ConsoleRenderer())
    else:
        processors.append(structlog.processors.JSONRenderer())

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configurar logging padrão
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(message)s",
        handlers=[
            RichHandler(rich_tracebacks=True) if enable_rich else logging.StreamHandler()
        ] + ([logging.FileHandler(log_file)] if log_file else [])
    )

class LoggedOperation:
    """Decorator para logging de operações."""
    
    def __init__(self, operation_name: str):
        self.operation_name = operation_name
        self.logger = structlog.get_logger()

    def __call__(self, func):
        async def wrapper(*args, **kwargs):
            start_time = datetime.now()
            
            self.logger.info(
                f"{self.operation_name}_started",
                args=args,
                kwargs=kwargs
            )
            
            try:
                result = await func(*args, **kwargs)
                duration = (datetime.now() - start_time).total_seconds()
                
                self.logger.info(
                    f"{self.operation_name}_completed",
                    duration=duration
                )
                
                return result
                
            except Exception as e:
                self.logger.error(
                    f"{self.operation_name}_failed",
                    error=str(e),
                    duration=(datetime.now() - start_time).total_seconds()
                )
                raise
                
        return wrapper


logger = structlog.get_logger()

# pyphone/core/config.py

class SIPConfig(BaseModel):
    username: str
    password: str
    domain: str
    port: int = 5060
    transport: str = "udp"
    
    @validator('transport')
    def validate_transport(cls, v):
        if v not in ['udp', 'tcp', 'tls']:
            raise ValueError('Invalid transport protocol')
        return v

class MediaConfig(BaseModel):
    rtp_start_port: int = 10000
    rtp_end_port: int = 20000
    codecs: list = ['PCMA', 'PCMU']

class Config:
    def __init__(self, config_file: Optional[str] = None):
        self._config = self._load_config(config_file)
        self.sip = SIPConfig(**self._config.get('sip', {}))
        self.media = MediaConfig(**self._config.get('media', {}))

    def _load_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        if not config_file:
            return {}
        
        path = Path(config_file)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {config_file}")
            
        with path.open() as f:
            return yaml.safe_load(f)

    def get(self, key: str, default: Any = None) -> Any:
        return self._config.get(key, default)

# pyphone/core/events.py

class EventType(Enum):
    # SIP Events
    SIP_REGISTER_SUCCESS = "sip_register_success"
    SIP_REGISTER_FAILED = "sip_register_failed"
    SIP_INVITE_RECEIVED = "sip_invite_received"
    SIP_INVITE_SENT = "sip_invite_sent"
    SIP_CALL_ESTABLISHED = "sip_call_established"
    SIP_CALL_ENDED = "sip_call_ended"
    
    # Media Events
    MEDIA_STARTED = "media_started"
    MEDIA_STOPPED = "media_stopped"
    DTMF_RECEIVED = "dtmf_received"
    
    # System Events
    ERROR = "error"
    WARNING = "warning"
    METRICS_UPDATED = "metrics_updated"

@dataclass
class Event:
    type: EventType
    data: Dict[str, Any]
    timestamp: float

class EventEmitter:
    def __init__(self):
        self._observers: Dict[EventType, List[Callable]] = {}
        self.logger = logger.bind(component="EventEmitter")

    def on(self, event_type: EventType, callback: Callable):
        if event_type not in self._observers:
            self._observers[event_type] = []
        self._observers[event_type].append(callback)
        self.logger.debug("registered_event_handler", 
                         event_type=event_type.value, 
                         handler=callback.__name__)

    async def emit(self, event: Event):
        self.logger.debug("emitting_event", 
                         event_type=event.type.value, 
                         data=event.data)
        
        if event.type in self._observers:
            for callback in self._observers[event.type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(event)
                    else:
                        await asyncio.get_running_loop().run_in_executor(
                            None, callback, event
                        )
                except Exception as e:
                    self.logger.error("event_handler_error",
                                    error=str(e),
                                    event_type=event.type.value,
                                    handler=callback.__name__)

# pyphone/core/exceptions.py

class PyPhoneError(Exception):
    def __init__(self, 
                 message: str, 
                 code: int, 
                 details: Optional[Dict] = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}

class SIPError(PyPhoneError):
    pass

class MediaError(PyPhoneError):
    pass

class ConfigError(PyPhoneError):
    pass

class SecurityError(PyPhoneError):
    pass

# pyphone/core/metrics.py

class MetricsCollector:
    def __init__(self):
        self.logger = logger.bind(component="MetricsCollector")
        
        # Call metrics
        self.calls_total = Counter('pyphone_calls_total', 
                                 'Total number of calls')
        self.call_duration = Histogram('pyphone_call_duration_seconds',
                                     'Call duration in seconds')
        self.active_calls = Gauge('pyphone_active_calls',
                                'Number of active calls')
        
        # SIP metrics
        self.sip_transactions = Counter('pyphone_sip_transactions_total',
                                      'Total SIP transactions',
                                      ['method'])
        self.sip_errors = Counter('pyphone_sip_errors_total',
                                'Total SIP errors',
                                ['type'])
        
        # Media metrics
        self.rtp_packets = Counter('pyphone_rtp_packets_total',
                                 'Total RTP packets',
                                 ['direction'])
        self.packet_loss = Gauge('pyphone_packet_loss_percent',
                               'Packet loss percentage')
        self.jitter = Gauge('pyphone_jitter_ms',
                          'Current jitter in milliseconds')

    def record_call_start(self):
        self.calls_total.inc()
        self.active_calls.inc()
        self.logger.info("call_started", 
                        active_calls=self.active_calls._value.get())

    def record_call_end(self, duration: float):
        self.active_calls.dec()
        self.call_duration.observe(duration)
        self.logger.info("call_ended", 
                        duration=duration,
                        active_calls=self.active_calls._value.get())

    def record_sip_transaction(self, method: str):
        self.sip_transactions.labels(method=method).inc()

    def record_media_stats(self, stats: Dict[str, Any]):
        self.packet_loss.set(stats.get('packet_loss', 0))
        self.jitter.set(stats.get('jitter', 0))
        self.logger.debug("media_stats_updated", **stats)

# pyphone/core/sip/stack.py

class SIPMethod(Enum):
    REGISTER = "REGISTER"
    INVITE = "INVITE"
    ACK = "ACK"
    BYE = "BYE"
    CANCEL = "CANCEL"
    OPTIONS = "OPTIONS"
    INFO = "INFO"

class SIPStatus(Enum):
    TRYING = (100, "Trying")
    RINGING = (180, "Ringing")
    OK = (200, "OK")
    UNAUTHORIZED = (401, "Unauthorized")
    NOT_FOUND = (404, "Not Found")
    
    def __init__(self, code: int, reason: str):
        self.code = code
        self.reason = reason

@dataclass
class SIPMessage:
    method: Optional[SIPMethod]
    status: Optional[SIPStatus]
    headers: Dict[str, str]
    body: Optional[str] = None
    
    @property
    def is_request(self) -> bool:
        return self.method is not None

class SIPDialog:
    def __init__(self, call_id: str, local_tag: str, remote_tag: Optional[str] = None):
        self.call_id = call_id
        self.local_tag = local_tag
        self.remote_tag = remote_tag
        self.local_seq = 0
        self.remote_seq = 0
        self.state = "INITIAL"

class SIPStack:
    def __init__(self, config: dict, events: EventEmitter):
        self.config = config
        self.events = events
        self.logger = logger.bind(component="SIPStack")
        self.dialogs: Dict[str, SIPDialog] = {}
        self.transactions: Dict[str, asyncio.Task] = {}
        
    async def start(self):
        """Inicializa o SIP Stack e prepara para processamento de mensagens."""
        self.logger.info("sip_stack_starting")
        try:
            # Inicializar transport
            await self._init_transport()
            # Iniciar processamento de mensagens
            self._message_processor = asyncio.create_task(self._process_messages())
            self.logger.info("sip_stack_started")
        except Exception as e:
            self.logger.error("sip_stack_start_failed", error=str(e))
            raise SIPError("Failed to start SIP stack", 500, {"error": str(e)})

    async def send_register(self) -> None:
        """Envia requisição REGISTER para o servidor SIP."""
        message = self._create_register_message()
        await self._send_message(message)
        self.logger.info("register_sent")

    async def send_invite(self, target: str) -> None:
        """Inicia uma chamada SIP para o alvo especificado."""
        dialog = self._create_dialog()
        message = self._create_invite_message(target, dialog)
        await self._send_message(message)
        self.logger.info("invite_sent", target=target)

    async def _process_messages(self):
        """Processa mensagens SIP recebidas."""
        while True:
            try:
                message = await self._receive_message()
                await self._handle_message(message)
            except Exception as e:
                self.logger.error("message_processing_error", error=str(e))

    async def _handle_message(self, message: SIPMessage):
        """Processa uma mensagem SIP recebida."""
        if message.is_request:
            await self._handle_request(message)
        else:
            await self._handle_response(message)

    def _create_dialog(self) -> SIPDialog:
        """Cria um novo diálogo SIP."""
        call_id = self._generate_call_id()
        local_tag = self._generate_tag()
        return SIPDialog(call_id, local_tag)


# pyphone/core/media/rtp.py

class RTPProtocol:
    pass

@dataclass
class RTPPacket:
    version: int = 2
    padding: bool = False
    extension: bool = False
    csrc_count: int = 0
    marker: bool = False
    payload_type: int = 0
    sequence_number: int = 0
    timestamp: int = 0
    ssrc: int = 0
    payload: bytes = b""

class RTPSession:
    def __init__(self, local_ip: str, local_port: int, events: EventEmitter):
        self.local_ip = local_ip
        self.local_port = local_port
        self.events = events
        self.logger = logger.bind(component="RTPSession")
        self.sequence_number = 0
        self.timestamp = 0
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._protocol: Optional[asyncio.DatagramProtocol] = None
        self.stats = {
            'packets_sent': 0,
            'packets_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'packet_loss': 0.0,
            'jitter': 0.0
        }

    async def start(self):
        """Inicia a sessão RTP."""
        try:
            loop = asyncio.get_running_loop()
            self._transport, self._protocol = await loop.create_datagram_endpoint(
                lambda: RTPProtocol(self),
                local_addr=(self.local_ip, self.local_port)
            )
            self.logger.info("rtp_session_started", 
                           local_ip=self.local_ip, 
                           local_port=self.local_port)
        except Exception as e:
            self.logger.error("rtp_session_start_failed", error=str(e))
            raise MediaError("Failed to start RTP session", 500, {"error": str(e)})

    async def send_packet(self, payload: bytes, pt: int, marker: bool = False):
        """Envia um pacote RTP."""
        if not self._transport:
            raise MediaError("RTP transport not initialized", 500)

        packet = self._create_packet(payload, pt, marker)
        packed_data = self._pack_packet(packet)
        self._transport.sendto(packed_data)
        
        self.stats['packets_sent'] += 1
        self.stats['bytes_sent'] += len(packed_data)

    def _create_packet(self, payload: bytes, pt: int, marker: bool) -> RTPPacket:
        """Cria um pacote RTP."""
        packet = RTPPacket(
            marker=marker,
            payload_type=pt,
            sequence_number=self.sequence_number,
            timestamp=self.timestamp,
            ssrc=self.ssrc,
            payload=payload
        )
        self.sequence_number = (self.sequence_number + 1) & 0xFFFF
        self.timestamp = (self.timestamp + len(payload)) & 0xFFFFFFFF
        return packet

    def _pack_packet(self, packet: RTPPacket) -> bytes:
        """Empacota um pacote RTP em bytes."""
        header = struct.pack(
            "!BBHII",
            (packet.version << 6) | (packet.padding << 5) | 
            (packet.extension << 4) | packet.csrc_count,
            (packet.marker << 7) | packet.payload_type,
            packet.sequence_number,
            packet.timestamp,
            packet.ssrc
        )
        return header + packet.payload

    def update_stats(self, packet: RTPPacket):
        """Atualiza estatísticas da sessão RTP."""
        self.stats['packets_received'] += 1
        self.stats['bytes_received'] += len(packet.payload)
        # Calcular jitter e perda de pacotes
        self._calculate_metrics(packet)
        
        # Emitir evento com métricas atualizadas
        self.events.emit(Event(
            type=EventType.METRICS_UPDATED,
            data=self.stats,
            timestamp=asyncio.get_event_loop().time()
        ))

@dataclass
class Call:
    def __init__(self, id: str, remote_uri: str):
        self.id = id
        self.remote_uri = remote_uri
        self.state = "INITIAL"
        self.start_time_at = datetime.now()

# pyphone/pyphone.py

class PyPhone:
    def __init__(self, config_file: Optional[str] = None):
        self.config = Config(config_file)
        self.events = EventEmitter()
        self.logger = logger.bind(component="PyPhone")
        self.metrics = MetricsCollector()
        
        # Inicializar componentes principais
        self.sip_stack = SIPStack(self.config.sip, self.events)
        self.rtp_session = RTPSession(
            self.config.get('local_ip', '0.0.0.0'),
            self.config.media.rtp_start_port,
            self.events
        )
        self._registered = False
        # Registrar handlers de eventos
        self._setup_event_handlers()

    async def start(self):
        """Inicia todos os componentes do PyPhone."""
        try:
            self.logger.info("pyphone_starting")
            await self.sip_stack.start()
            await self.rtp_session.start()
            self.logger.info("pyphone_started")
        except Exception as e:
            self.logger.error("pyphone_start_failed", error=str(e))
            raise PyPhoneError("Failed to start PyPhone", 500, {"error": str(e)})

    async def register(self):
        """Registra o cliente no servidor SIP."""
        try:
            await self.sip_stack.send_register()
        except Exception as e:
            self.logger.error("register_failed", error=str(e))
            raise

    async def call(self, target: str):
        """Inicia uma chamada para o alvo especificado."""
        try:
            self.logger.info("call_initiating", target=target)
            self.metrics.record_call_start()
            await self.sip_stack.send_invite(target)
        except Exception as e:
            self.logger.error("call_failed", target=target, error=str(e))
            raise

    async def hangup(self):
        """Encerra a chamada atual."""
        try:
            self.logger.info("call_ending")
            await self.sip_stack.send_bye()
            self.metrics.record_call_end(
                asyncio.get_event_loop().time() - self._call_start_time
            )
        except Exception as e:
            self.logger.error("hangup_failed", error=str(e))
            raise

    def _setup_event_handlers(self):
        """Configura os handlers de eventos."""
        self.events.on(EventType.SIP_REGISTER_SUCCESS, self._handle_register_success)
        self.events.on(EventType.SIP_CALL_ESTABLISHED, self._handle_call_established)
        self.events.on(EventType.METRICS_UPDATED, self._handle_metrics_update)

    async def _handle_register_success(self, event: Event):
        self.logger.info("registration_successful")

    async def _handle_call_established(self, event: Event):
        self.logger.info("call_established")
        self._call_start_time = asyncio.get_event_loop().time()

    async def _handle_metrics_update(self, event: Event):
        self.metrics.record_media_stats(event.data)

    @property
    def active_calls(self) -> int:
        return self.metrics.active_calls._value.get()
    
    @property
    def is_registered(self) -> bool:
        return self._registered

    def get_active_calls(self) -> List[Call]:
        return []

# pyphone/core/sip/processor.py

@dataclass
class SIPRequest:
    method: str
    uri: str
    version: str = "SIP/2.0"
    headers: Dict[str, str] = None
    body: Optional[str] = None

    def to_string(self) -> str:
        headers = self.headers or {}
        request_line = f"{self.method} {self.uri} {self.version}\r\n"
        header_lines = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
        return f"{request_line}{header_lines}\r\n\r\n{self.body or ''}"

@dataclass
class SIPResponse:
    status_code: int
    reason: str
    version: str = "SIP/2.0"
    headers: Dict[str, str] = None
    body: Optional[str] = None

    def to_string(self) -> str:
        headers = self.headers or {}
        status_line = f"{self.version} {self.status_code} {self.reason}\r\n"
        header_lines = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
        return f"{status_line}{header_lines}\r\n\r\n{self.body or ''}"

class SIPProcessor:
    def __init__(self):
        self.request_handlers: Dict[str, Callable] = {}
        self.response_handlers: Dict[int, Callable] = {}
        
    def register_request_handler(self, method: str, handler: Callable):
        self.request_handlers[method] = handler
        
    def register_response_handler(self, status_code: int, handler: Callable):
        self.response_handlers[status_code] = handler
        
    async def process_message(self, data: str) -> Optional[str]:
        """Processa uma mensagem SIP recebida."""
        try:
            lines = data.split("\r\n")
            first_line = lines[0]
            
            if first_line.startswith("SIP/2.0"):
                return await self._process_response(data)
            else:
                return await self._process_request(data)
                
        except Exception as e:
            raise SIPError(f"Error processing SIP message: {str(e)}", 500)

    async def _process_request(self, data: str) -> Optional[str]:
        """Processa uma requisição SIP."""
        request = self._parse_request(data)
        if request.method in self.request_handlers:
            response = await self.request_handlers[request.method](request)
            return response.to_string() if response else None
        raise SIPError(f"No handler for method: {request.method}", 501)

    async def _process_response(self, data: str) -> None:
        """Processa uma resposta SIP."""
        response = self._parse_response(data)
        if response.status_code in self.response_handlers:
            await self.response_handlers[response.status_code](response)

    def _parse_request(self, data: str) -> SIPRequest:
        """Converte dados brutos em um objeto SIPRequest."""
        lines = data.split("\r\n")
        request_line = lines[0]
        method, uri, version = request_line.split(" ")
        
        headers = {}
        body = None
        
        # Parse headers and body
        header_end = lines.index("")
        for line in lines[1:header_end]:
            name, value = line.split(": ", 1)
            headers[name] = value
            
        if header_end < len(lines) - 1:
            body = "\r\n".join(lines[header_end + 1:])
            
        return SIPRequest(method, uri, version, headers, body)

    def _parse_response(self, data: str) -> SIPResponse:
        """Converte dados brutos em um objeto SIPResponse."""
        lines = data.split("\r\n")
        status_line = lines[0]
        version, status_code, *reason_parts = status_line.split(" ")
        reason = " ".join(reason_parts)
        
        headers = {}
        body = None
        
        header_end = lines.index("")
        for line in lines[1:header_end]:
            name, value = line.split(": ", 1)
            headers[name] = value
            
        if header_end < len(lines) - 1:
            body = "\r\n".join(lines[header_end + 1:])
            
        return SIPResponse(int(status_code), reason, version, headers, body)

# pyphone/core/media/codecs/base.py

class Codec(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Nome do codec."""
        pass
    
    @property
    @abstractmethod
    def payload_type(self) -> int:
        """Tipo de payload RTP."""
        pass
    
    @property
    @abstractmethod
    def sampling_rate(self) -> int:
        """Taxa de amostragem em Hz."""
        pass
    
    @property
    @abstractmethod
    def channels(self) -> int:
        """Número de canais de áudio."""
        pass
    
    @abstractmethod
    def encode(self, data: bytes) -> bytes:
        """Codifica dados de áudio."""
        pass
    
    @abstractmethod
    def decode(self, data: bytes) -> bytes:
        """Decodifica dados de áudio."""
        pass

# pyphone/core/media/codecs/g711.py
class ALawCodec(Codec):
    @property
    def name(self) -> str:
        return "PCMA"
    
    @property
    def payload_type(self) -> int:
        return 8
    
    @property
    def sampling_rate(self) -> int:
        return 8000
    
    @property
    def channels(self) -> int:
        return 1
    
    def encode(self, data: bytes) -> bytes:
        # Implementação da codificação A-law
        # Este é um exemplo simplificado
        return data
    
    def decode(self, data: bytes) -> bytes:
        # Implementação da decodificação A-law
        # Este é um exemplo simplificado
        return data

class ULawCodec(Codec):
    @property
    def name(self) -> str:
        return "PCMU"
    
    @property
    def payload_type(self) -> int:
        return 0
    
    @property
    def sampling_rate(self) -> int:
        return 8000
    
    @property
    def channels(self) -> int:
        return 1
    
    def encode(self, data: bytes) -> bytes:
        # Implementação da codificação μ-law
        return data
    
    def decode(self, data: bytes) -> bytes:
        # Implementação da decodificação μ-law
        return data

# pyphone/core/media/codecs/manager.py

class CodecManager:
    def __init__(self):
        self._codecs: Dict[str, Type[Codec]] = {}
        self._register_default_codecs()
    
    def _register_default_codecs(self):
        """Registra os codecs padrão."""
        self.register_codec("PCMA", ALawCodec)
        self.register_codec("PCMU", ULawCodec)
    
    def register_codec(self, name: str, codec_class: Type[Codec]):
        """Registra um novo codec."""
        self._codecs[name] = codec_class
    
    def get_codec(self, name: str) -> Codec:
        """Retorna uma instância do codec especificado."""
        if name not in self._codecs:
            raise ValueError(f"Codec not found: {name}")
        return self._codecs[name]()
    
    def get_supported_codecs(self) -> List[str]:
        """Retorna lista de codecs suportados."""
        return list(self._codecs.keys())
    
    def negotiate_codec(self, remote_codecs: List[str]) -> Optional[str]:
        """Negocia o melhor codec com base nas preferências remotas."""
        for codec in remote_codecs:
            if codec in self._codecs:
                return codec
        return None


# pyphone/core/dtmf/handler.py

class DTMFEvent(Enum):
    DTMF_0 = "0"
    DTMF_1 = "1"
    DTMF_2 = "2"
    DTMF_3 = "3"
    DTMF_4 = "4"
    DTMF_5 = "5"
    DTMF_6 = "6"
    DTMF_7 = "7"
    DTMF_8 = "8"
    DTMF_9 = "9"
    DTMF_STAR = "*"
    DTMF_POUND = "#"

@dataclass
class DTMFTone:
    digit: str
    duration: int = 160  # milliseconds
    volume: int = 10     # dBm0

class DTMFHandler:
    def __init__(self):
        self.logger = logger.bind(component="DTMFHandler")
        self._observers: List[Callable[[DTMFEvent], None]] = []
        self._current_sequence: List[str] = []
        
    def add_observer(self, callback: Callable[[DTMFEvent], None]):
        """Adiciona um observador para eventos DTMF."""
        self._observers.append(callback)
        
    def remove_observer(self, callback: Callable[[DTMFEvent], None]):
        """Remove um observador."""
        if callback in self._observers:
            self._observers.remove(callback)

    async def handle_dtmf(self, digit: str):
        """Processa um dígito DTMF recebido."""
        try:
            event = DTMFEvent(digit)
            self._current_sequence.append(digit)
            self.logger.debug("dtmf_received", digit=digit)
            
            for observer in self._observers:
                if asyncio.iscoroutinefunction(observer):
                    await observer(event)
                else:
                    observer(event)
                    
        except ValueError as e:
            self.logger.error("invalid_dtmf", digit=digit, error=str(e))
            
    def get_current_sequence(self) -> str:
        """Retorna a sequência atual de dígitos DTMF."""
        return "".join(self._current_sequence)
        
    def clear_sequence(self):
        """Limpa a sequência atual de dígitos."""
        self._current_sequence.clear()

    async def send_dtmf(self, digit: str, duration: int = 160):
        """Envia um tom DTMF."""
        tone = DTMFTone(digit, duration)
        # Implementação do envio do tom DTMF
        self.logger.debug("dtmf_sent", digit=digit, duration=duration)

        
# pyphone/core/ivr/system.py

class IVRError(Exception):
    pass


class IVRState(ABC):
    @abstractmethod
    async def enter(self, context: Dict[str, Any]) -> None:
        """Executado quando o estado é iniciado."""
        pass
    
    @abstractmethod
    async def handle_dtmf(self, event: DTMFEvent, context: Dict[str, Any]) -> Optional['IVRState']:
        """Processa entrada DTMF e retorna próximo estado se houver transição."""
        pass
    
    @abstractmethod
    async def timeout(self, context: Dict[str, Any]) -> Optional['IVRState']:
        """Executado quando ocorre timeout de entrada."""
        pass

class IVRContext:
    def __init__(self):
        self.data: Dict[str, Any] = {}
        self.collected_input: str = ""
        self.attempts: int = 0
        self.current_prompt: Optional[str] = None

class IVRSystem:
    def __init__(self, initial_state: IVRState, timeout: int = 10):
        self.initial_state = initial_state
        self.timeout = timeout
        self.current_state: Optional[IVRState] = None
        self.context = IVRContext()
        self.logger = logger.bind(component="IVRSystem")
        self._timeout_task: Optional[asyncio.Task] = None
        
    async def start(self):
        """Inicia o sistema IVR."""
        try:
            self.current_state = self.initial_state
            await self._enter_state()
        except Exception as e:
            self.logger.error("ivr_start_failed", error=str(e))
            raise IVRError("Failed to start IVR", 500, {"error": str(e)})

    async def handle_dtmf(self, event: DTMFEvent):
        """Processa entrada DTMF."""
        if not self.current_state:
            return
            
        try:
            # Resetar timeout
            self._reset_timeout()
            
            # Processar entrada
            self.context.collected_input += event.value
            next_state = await self.current_state.handle_dtmf(event, self.context.data)
            
            if next_state and next_state != self.current_state:
                self.current_state = next_state
                await self._enter_state()
                
        except Exception as e:
            self.logger.error("dtmf_handling_failed", error=str(e))
            raise IVRError("Failed to handle DTMF", 500, {"error": str(e)})

    async def _enter_state(self):
        """Entra em um novo estado."""
        try:
            await self.current_state.enter(self.context.data)
            self._reset_timeout()
        except Exception as e:
            self.logger.error("state_transition_failed", error=str(e))
            raise

    def _reset_timeout(self):
        """Reseta o timer de timeout."""
        if self._timeout_task:
            self._timeout_task.cancel()
        self._timeout_task = asyncio.create_task(self._handle_timeout())

    async def _handle_timeout(self):
        """Gerencia timeout de entrada."""
        try:
            await asyncio.sleep(self.timeout)
            if self.current_state:
                next_state = await self.current_state.timeout(self.context.data)
                if next_state:
                    self.current_state = next_state
                    await self._enter_state()
        except asyncio.CancelledError:
            pass


# pyphone/cli/console.py

class PyPhoneConsole:
    def __init__(self, phone_instance):
        self.phone = phone_instance
        self.console = Console()
        self.layout = self._create_layout()
        self._call_active = False
        self._current_status = "IDLE"
        
    def _create_layout(self) -> Layout:
        layout = Layout()
        
        layout.split(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        layout["main"].split_row(
            Layout(name="status"),
            Layout(name="calls")
        )
        
        return layout
        
    def _generate_header(self) -> Panel:
        return Panel(
            f"PyPhone Console - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            style="bold white on blue"
        )
        
    def _generate_status_panel(self) -> Panel:
        status_table = Table(show_header=False)
        status_table.add_row("Status", self._current_status)
        status_table.add_row("Registration", "Registered" if self.phone.is_registered else "Not Registered")
        status_table.add_row("Active Calls", str(self.phone.active_calls))
        
        return Panel(status_table, title="System Status")
        
    def _generate_calls_panel(self) -> Panel:
        calls_table = Table()
        calls_table.add_column("ID")
        calls_table.add_column("Remote Party")
        calls_table.add_column("Duration")
        calls_table.add_column("Status")
        
        for call in self.phone.get_active_calls():
            calls_table.add_row(
                str(call.id),
                call.remote_uri,
                str(call.duration),
                call.state
            )
            
        return Panel(calls_table, title="Active Calls")
        
    async def update_display(self):
        with Live(self.layout, refresh_per_second=4) as live:
            while True:
                self.layout["header"].update(self._generate_header())
                self.layout["main"]["status"].update(self._generate_status_panel())
                self.layout["main"]["calls"].update(self._generate_calls_panel())
                await asyncio.sleep(0.25)
            live.update(self.layout)

    async def start(self):
        """Inicia a interface de console."""
        self.console.clear()
        await self._show_welcome()
        
        # Iniciar atualização da tela
        asyncio.create_task(self.update_display())
        
        while True:
            try:
                command = await self._get_command()
                await self._handle_command(command)
            except KeyboardInterrupt:
                await self._handle_exit()
                break
            except Exception as e:
                self.console.print(f"[red]Error: {str(e)}[/red]")

    async def _get_command(self) -> str:
        return await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: Prompt.ask("[bold blue]pyphone>[/bold blue]")
        )

    async def _handle_command(self, command: str):
        parts = command.split()
        if not parts:
            return
            
        cmd = parts[0].lower()
        args = parts[1:]
        
        if cmd == "call":
            if not args:
                self.console.print("[red]Error: Missing target number/URI[/red]")
                return
            await self._handle_call(args[0])
            
        elif cmd == "hangup":
            await self._handle_hangup()
            
        elif cmd == "status":
            await self._show_status()
            
        elif cmd == "register":
            await self._handle_register()
            
        elif cmd == "quit":
            await self._handle_exit()
            
        else:
            self.console.print(f"[red]Unknown command: {cmd}[/red]")

    async def _handle_call(self, target: str):
        with Progress() as progress:
            task = progress.add_task("[cyan]Initiating call...", total=100)
            
            try:
                await self.phone.call(target)
                self._call_active = True
                progress.update(task, completed=100)
                self.console.print(f"[green]Call established with {target}[/green]")
            except Exception as e:
                progress.update(task, completed=100)
                self.console.print(f"[red]Call failed: {str(e)}[/red]")

    async def _handle_hangup(self):
        if not self._call_active:
            self.console.print("[yellow]No active call to hang up[/yellow]")
            return
            
        try:
            await self.phone.hangup()
            self._call_active = False
            self.console.print("[green]Call ended[/green]")
        except Exception as e:
            self.console.print(f"[red]Error ending call: {str(e)}[/red]")

    async def _show_status(self):
        status_table = Table(title="PyPhone Status")
        status_table.add_column("Component")
        status_table.add_column("Status")
        status_table.add_column("Details")
        
        # Adicionar informações de status
        status = self.phone.get_status()
        for component, info in status.items():
            status_table.add_row(
                component,
                info.get("status", "Unknown"),
                info.get("details", "")
            )
            
        self.console.print(status_table)

    async def _handle_register(self):
        try:
            await self.phone.register()
            self.console.print("[green]Successfully registered[/green]")
        except Exception as e:
            self.console.print(f"[red]Registration failed: {str(e)}[/red]")

    async def _handle_exit(self):
        self.console.print("[yellow]Shutting down PyPhone...[/yellow]")
        await self.phone.stop()
        self.console.print("[green]Goodbye![/green]")

    async def _show_welcome(self):
        welcome_text = """
        [bold blue]PyPhone Console Interface[/bold blue]
        
        Available commands:
        - call <number/uri>: Make a call
        - hangup: End current call
        - status: Show system status
        - register: Register with SIP server
        - quit: Exit PyPhone
        
        Press Ctrl+C to exit
        """
        self.console.print(Panel(welcome_text, title="Welcome"))


# pyphone/cli/commands.py

@click.group()
def cli():
    """PyPhone - Python VoIP Client"""
    pass

@cli.command()
@click.option('--config', '-c', help='Path to config file')
def console(config):
    """Start PyPhone console interface"""
    console = Console()
    try:
        phone = PyPhone(config_file=config)
        phone_console = PyPhoneConsole(phone)
        asyncio.run(phone_console.start())
    except Exception as e:
        console.print(f"[red]Error starting PyPhone: {str(e)}[/red]")

@cli.command()
@click.argument('target')
@click.option('--config', '-c', help='Path to config file')
def call(target, config):
    """Make a call to specified target"""
    console = Console()
    try:
        phone = PyPhone(config_file=config)
        asyncio.run(phone.call(target))
    except Exception as e:
        console.print(f"[red]Error making call: {str(e)}[/red]")

@cli.command()
@click.option('--config', '-c', help='Path to config file')
def register(config):
    """Register with SIP server"""
    console = Console()
    try:
        phone = PyPhone(config_file=config)
        asyncio.run(phone.register())
        console.print("[green]Successfully registered[/green]")
    except Exception as e:
        console.print(f"[red]Registration failed: {str(e)}[/red]")


# examples/cli_example.py

async def main():
    # Configurar logging
    setup_logging(log_level="DEBUG", log_file="pyphone.log")
    
    # Criar instância do PyPhone
    phone = PyPhone("config.yaml")
    
    # Criar e iniciar console
    console = PyPhoneConsole(phone)
    await console.start()

if __name__ == "__main__":
    asyncio.run(main())