"""
RFC 4566: SDP (Session Description Protocol)
O SDP é usado para descrever sessões multimídia, incluindo detalhes como tipo de mídia (áudio, vídeo), formato, endereço IP e portas de transporte. Ele não é um protocolo de transporte, mas um formato utilizado em protocolos como SIP para negociar parâmetros de sessão. Exemplos incluem campos obrigatórios como v= (versão), o= (origem), s= (nome da sessão) e m= (descrição da mídia
"""

from uuid import uuid4
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Union, Dict
from abc import ABC

from rich.panel import Panel
from rich.pretty import Pretty
from rich.console import Console, ConsoleOptions, RenderResult
from pyphone.utils import log, console, EOL


__all__ = [
    'MediaType',
    'CodecType',
    'DtmfPayloadType',
    'MediaSessionType',
    'MediaProtocolType',
    'SDPField',
    'Owner',
    'Atribute',
    'ConnectionInformation',
    'MediaDescription',
    'SessionName',
    'MediaSession',
    'Ptime',
    'SDPConfig',
    'SDPBody'
]




class MediaType(Enum):
    AUDIO = 'audio'
    VIDEO = 'video'
    MESSAGE = 'message'

    def __str__(self) -> str:
        return str(self._value_)


class CodecType(Enum):
    PCMU = ('0', 'pcmu', '8000')
    PCMA = ('8', 'pcma', '8000')

    def __new__(self, code: str, description: str, rate: str):
        obj = object.__new__(self)
        obj.code = code
        obj.description = description
        obj.rate = rate
        obj._value_ = code
        return obj

    @classmethod
    def codecs(cls) -> List[str]:
        return [codec for codec in cls]

    def __str__(self) -> str:
        return f'{self.code} {self.description}/{self.rate}'


class DtmfPayloadType(Enum):
    RFC_2833 = ('101', 'telephone-event', '8000', '101 0-16')

    def __new__(self, code: str, description: str, rate: str, fmtp: str):
        obj = object.__new__(self)
        obj.code = code
        obj.description = description
        obj.rate = rate
        obj.fmtp = fmtp
        return obj

    def __str__(self) -> str:
        return f'{self.code} {self.description}/{self.rate}'



class MediaSessionType(Enum):
    SENDRECV = 'sendrecv'
    SENDONLY = 'sendonly'
    RECVONLY = 'recvonly'
    INACTIVE = 'inactive'

    def __str__(self) -> str:
        return str(self._value_)

    def __repr__(self) -> str:
        return self.__str__()

class MediaProtocolType(Enum):
    RTP_AVP = 'RTP/AVP'
    RTCP = 'RTCP'

    def __str__(self) -> str:
        return str(self._value_)


class SDPField(ABC):
    def __init__(self, key: str, value: str):
        self.key = key.lower()
        self.value = str(value)
        
    def __str__(self) -> str:
        return f'{self.key}={self.value}'


class Owner(SDPField):
    def __init__(
        self,
        username: str = '-',
        address: str = '0.0.0.0',
        address_type: str = 'IP4',
        network_type: str = 'IN',
        session_id: str = None,
        session_version: str = None,
    ):
        self.username = username
        self.session_id = session_id or \
            self._generate_session_id()
        self.session_version = session_version or \
            self._generate_session_id()
        self.network_type = network_type
        self.address_type = address_type
        self.address = address
        super().__init__(
            'o',
            f'{self.username} {self.session_id} {self.session_version} {self.network_type} {self.address_type} {self.address}'
            )

    def _generate_session_id(self) -> str:
        return uuid4().hex[:5]


class Atribute(SDPField):
    def __init__(self, key: str, value: str):
        self.key = key
        self.value = value
        super().__init__(self.key, self.value)


class ConnectionInformation(SDPField):
    def __init__(
        self,
        network_type: str = 'IN',
        address_type: str = 'IP4',
        address: str = '0.0.0.0',
    ):
        self.network_type = network_type
        self.address_type = address_type
        self.address = address
        super().__init__(
            'c',
            f'{self.network_type} {self.address_type} {self.address}'
        )


class MediaDescription(SDPField):
    def __init__(
        self,
        port: int = None,
        media_type: MediaType = MediaType.AUDIO,
        protocol: MediaProtocolType = MediaProtocolType.RTP_AVP,
        codecs: List[CodecType] = CodecType.codecs(),
        dtmf_payload: DtmfPayloadType = DtmfPayloadType.RFC_2833,
    ):
        self.media_type = media_type
        self.port = port or self._generate_port()
        self.protocol = protocol
        self.codecs = codecs
        self.dtmf_payload = dtmf_payload
        _codec = ' '.join([str(c.code) for c in self.codecs])
        super().__init__(
            'm',
            f'{self.media_type} {self.port} {self.protocol} {_codec} {self.dtmf_payload.code}'
        )
    
    def _generate_port(self) -> int:
        return random.randint(10000, 20000)


class SessionName(SDPField):
    def __init__(self, name: str = 'SDP Session'):
        self.name = name
        super().__init__('s', name)


class MediaSession(SDPField):
    def __init__(self, session_type: MediaSessionType = MediaSessionType.SENDRECV):
        self.session_type = session_type
        super().__init__('a', str(self.session_type))


class Ptime(SDPField):
    def __init__(self, ptime: int = 20):
        self.ptime = ptime
        super().__init__('a', f'ptime:{self.ptime}')


@dataclass
class SDPConfig:
    owner: Owner = field(default_factory=Owner)
    connection_information: ConnectionInformation = field(default_factory=ConnectionInformation)
    media_description: MediaDescription = field(default_factory=MediaDescription)
    session_name: SessionName = field(default_factory=SessionName)
    media_session_type: MediaSession = field(default_factory=MediaSession)
    ptime: Ptime = field(default_factory=Ptime)
    attributes: List[Atribute] = field(default_factory=list)
    extras_fields: List[SDPField] = field(default_factory=list)


class SDPBody:
    MULTI_SDP = ('t', 'r', 'a', 'm')
    COMPACT_SDP = {
        'v': 'version',
        'o': 'origin',
        's': 'session_name',
        'i': 'session_information',
        'u': 'uri',
        'e': 'email_address',
        'p': 'phone_number',
        'z': 'time_zone_adjustment',
        't': 'session_time',
        'r': 'repeat_time',
        'm': 'media_information',
        'c': 'connection_infomation',
        'b': 'bandwidth_information',
        'k': 'encryption_key',
        'a': 'media_attributes'
    }
    _sdp = {}
    def __init__(
        self,
        *fields: Union[List[SDPField], Dict[str, Union[SDPField, List[SDPField]]]],
        config: SDPConfig = None
        ):
        self.config = config
    
    
    def set_config(self, config: SDPConfig):
        self.config = config
        if self.config.owner:
            self['o'] = self.config.owner
        if self.config.connection_information:
            self['c'] = self.config.connection_information
        if self.config.media_description:
            self['m'] = self.config.media_description
        if self.config.session_name:
            self['s'] = self.config.session_name
        if self.config.media_session_type:
            self['a'] = self.config.media_session_type
        if self.config.ptime:
            self['a'] = self.config.ptime
        if self.config.attributes:
            for attribute in self.config.attributes:
                self['a'] = attribute
        if self.config.extras_fields:
            for field in self.config.extras_fields:
                self[field.key] = field
    
    def __getitem__(self, key):
        return self._sdp[key]
    
    def __setitem__(self, key, value):
        try:
            key.lower()
            if key in self.MULTI_SDP:
                if key not in self._sdp:
                    self._sdp[key] = []
                if isinstance(value, (list, tuple)):
                    self._sdp[key].extend(value)
                    return
                self._sdp[key].append(value)
                return
            self._sdp[key] = value
        except Exception:
            log.error(f"Invalid key {key}")
    
    def __delitem__(self, key):
        del self._sdp[key]
    
    def __len__(self):
        return len(self.__str__())

    def __contains__(self, item):
        return item in self._sdp
    
    def __str__(self):
        lines = []
        for _, value in self._sdp.items():
            if isinstance(value, (list, tuple)):
                lines.extend([x for x in value])
                continue
            lines.append(value)
        return ''.join([f'{line}{EOL}' for line in lines])
    
    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        yield Panel(Pretty(self.summary()), title='SDP (Session Description Protocol)', subtitle=f'{len(self)} bytes')
    
    def summary(self) -> str:
        return self.__str__()
    
    @staticmethod
    def from_string(cls, sdp: str) -> 'SDPBody':
        sdp_body = cls()
        for line in sdp.splitlines():
            key, value = line.split('=', 1)
            sdp_body[key] = value
        return sdp_body


if __name__ == '__main__':
    sdp_config = SDPConfig()
    sdp = SDPBody()
    sdp.set_config(sdp_config)
    console.print(sdp)