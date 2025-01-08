import re
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import List
from uuid import uuid4


# SDP Body RFC: 

class MediaType(Enum):
    AUDIO = 'audio'
    VIDEO = 'video'
    MESSAGE = 'message'

    def __repr__(self) -> str:
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

    def __repr__(self) -> str:
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

    def __repr__(self) -> str:
        return f'{self.code} {self.description}/{self.rate}'


class MediaSessionType(Enum):
    SENDRECV = 'sendrecv'
    SENDONLY = 'sendonly'
    RECVONLY = 'recvonly'
    INACTIVE = 'inactive'

    def __repr__(self) -> str:
        return str(self._value_)


class MediaProtocolType(Enum):
    RTP_AVP = 'RTP/AVP'
    RTCP = 'RTCP'

    def __repr__(self) -> str:
        return str(self._value_)


class Body(str):
    _SYNTAX = re.compile('^(?P<name>[a-z]+)=[\ \t]*(?P<value>.*)$')

    def __init__(self, name: str, value: str):
        self.name = name
        self.value = value
    
    def __str__(self):
        return f"{self.name}={self.value}"

    @classmethod
    def parser(cls, body: str) -> 'Body':
        _match = cls._SYNTAX.match(body)
        if not _match:
            raise ValueError(f"Invalid Body: {body}")
        return Body(
            name=_match.group('name'),
            value=_match.group('value')
        )


class Owner(Body):
    _SYNTAX = re.compile('^(?P<name>[a-z]+)=(?P<username>[a-zA-Z0-9\-\.\_]+)[\ \t]+(?P<session_id>[a-zA-Z0-9]+)[\ \t]+(?P<session_version>[a-zA-Z0-9]+)[\ \t]+(?P<network_type>[a-zA-Z0-9]+)[\ \t]+(?P<address_type>[a-zA-Z0-9]+)[\ \t]+(?P<address>[a-zA-Z0-9\.\:]+)$')
    
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

    @classmethod
    def parser(cls, owner: str) -> 'Owner':
        _match = cls._SYNTAX.match(owner)
        if not _match:
            raise ValueError(f"Invalid Owner: {owner}")
        return Owner(
            username=_match.group('username'),
            session_id=_match.group('session_id'),
            session_version=_match.group('session_version'),
            network_type=_match.group('network_type'),
            address_type=_match.group('address_type'),
            address=_match.group('address')
        )

class Atribute(Body):
    def __init__(self, key: str, value: str):
        self.key = key
        self.value = value
        super().__init__(self.key, self.value)


class ConnectionInformation(Body):
    _SYNTAX = re.compile('^(?P<name>[a-z]+)=(?P<network_type>[a-zA-Z0-9]+)[\ \t]+(?P<address_type>[a-zA-Z0-9]+)[\ \t]+(?P<address>[a-zA-Z0-9\.\:]+)$')
    
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

    @classmethod
    def parser(cls, connection: str) -> 'ConnectionInformation':
        _match = cls._SYNTAX.match(connection)
        if not _match:
            raise ValueError(f"Invalid Connection Information: {connection}")
        return ConnectionInformation(
            network_type=_match.group('network_type'),
            address_type=_match.group('address_type'),
            address=_match.group('address')
        )


class MediaDescription(Body):
    _SYNTAX = re.compile('^(?P<name>[a-z]+)=(?P<media_type>[a-zA-Z0-9]+)[\ \t]+(?P<port>[\d]+)[\ \t]+(?P<protocol>[a-zA-Z0-9]+)[\ \t]+(?P<codec>[a-zA-Z0-9\ \t]+)[\ \t]+(?P<dtmf_payload>[a-zA-Z0-9]+)$')
    
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

    @classmethod
    def parser(cls, media: str) -> 'MediaDescription':
        _match = cls._SYNTAX.match(media)
        if not _match:
            raise ValueError(f"Invalid Media Description: {media}")
        _codecs = [CodecType(code) for code in _match.group('codec').split(' ')]
        return MediaDescription(
            media_type=_match.group('media_type'),
            port=int(_match.group('port')),
            protocol=_match.group('protocol'),
            codecs=_codecs,
            dtmf_payload=_match.group('dtmf_payload')
        )

class SessionName(Body):
    def __init__(self, name: str = 'SDP Session'):
        self.name = name
        super().__init__('s', name)


class MediaSession(Body):
    def __init__(self, session_type: MediaSessionType = MediaSessionType.SENDRECV):
        self.session_type = session_type
        super().__init__('a', str(self.session_type))


class Ptime(Body):
    def __init__(self, ptime: int = 20):
        self.ptime = ptime
        super().__init__('a', f'ptime:{self.ptime}')


@dataclass
class BodyFactory:
    owner: Owner = field(default_factory=Owner)
    connection_information: ConnectionInformation = field(default_factory=ConnectionInformation)
    media_description: MediaDescription = field(default_factory=MediaDescription)
    session_name: SessionName = field(default_factory=SessionName)
    media_session_type: MediaSession = field(default_factory=MediaSession)
    ptime: Ptime = field(default_factory=Ptime)
    attributes: List[Atribute] = field(default_factory=list)
    extras_fields: List[Body] = field(default_factory=list)

    def from_string(self, body: str):
        lines = body.split('\r\n')
        attributes = []
        extras_fields = []
        for line in lines:
            name, value = line.split('=')
            match name:
                case 'o':
                    owner = Owner.parser(value)
                case 'c':
                    connection_information = ConnectionInformation.parser(value)
                case 'm':
                    media_description = MediaDescription.parser(value)
                case 's':
                    session_name = SessionName(value)
                case 'a':
                    match value:
                        case 'sendrecv' | 'sendonly' | 'recvonly' | 'inactive':
                            media_session_type = MediaSession(value)
                        case 'ptime':
                            ptime = Ptime(value)
                        case _:
                            attributes.append(Atribute(name, value))
                case _:
                    extras_fields.append(Body(name, value))
            
        return BodyFactory(
            owner=owner,
            connection_information=connection_information,
            media_description=media_description,
            session_name=session_name,
            media_session_type=media_session_type,
            ptime=ptime,
            attributes=attributes,
            extras_fields=extras_fields
        )
