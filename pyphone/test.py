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


from pyphone.utils import log

class SipMethod(Enum):
    INVITE = "INVITE"
    ACK = "ACK"
    BYE = "BYE"
    CANCEL = "CANCEL"
    REGISTER = "REGISTER"
    OPTIONS = "OPTIONS"
    INFO = "INFO"
    SUBSCRIBE = "SUBSCRIBE"
    NOTIFY = "NOTIFY"

    def __str__(self):
        return self.value
    
    @classmethod
    def methods(cls) -> List[str]:
        return [method for method in cls]
    
    @classmethod
    def from_string(cls, method: str) -> 'SipMethod':
        return cls(method.upper())


class SipStatusCode(Enum):
    TRYING = (100, "Trying")
    RINGING = (180, "Ringing")
    OK = (200, "OK")
    UNAUTHORIZED = (401, "Unauthorized")
    FORBIDDEN = (403, "Forbidden")
    NOT_FOUND = (404, "Not Found")
    REQUEST_TIMEOUT = (408, "Request Timeout")
    INTERNAL_SERVER_ERROR = (500, "Internal Server Error")
    BUSY_HERE = (486, "Busy Here")
    REQUEST_TERMINATED = (487, "Request Terminated")
    SERVER_TIMEOUT = (504, "Server Timeout")
    BUSY_EVERYWHERE = (600, "Busy Everywhere")
    DECLINE = (603, "Decline")
    NOT_ACCEPTABLE = (606, "Not Acceptable")

    def __new__(cls, value, phrase):
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.phrase = phrase
        return obj

    def __str__(self):
        return f"{self.value} {self.phrase}"

    @classmethod
    def from_string(cls, sip_status) -> 'SipStatusCode':
        if sip_status.isdigit():
            for status in cls:
                if status.value == int(sip_status):
                    return status
        else:
            for status in cls:
                if status.phrase == sip_status:
                    return status


class DialogState(Enum):
    INIT = "INIT"
    EARLY = "EARLY"
    CONFIRMED = "CONFIRMED"
    TERMINATED = "TERMINATED"

    def __str__(self):
        return self.value


@dataclass
class Uri:
    user: str
    host: str
    port: int = field(default=5060)
    scheme: str = field(default='sip')
    # password: str = field(default=None)
    parameters: dict = field(default_factory=dict)

    _SYNTAX = re.compile('^(?P<scheme>[a-zA-Z][a-zA-Z0-9\+\-\.]*):'# scheme
            + '(?:(?:(?P<user>[a-zA-Z0-9\-\_\.\!\~\*\'\(\)&=\+\$,;\?\/\%]+)' # user 
            # + '(?::(?P<password>[^:@;\?]+))?)@)?' # password
            + '(?:(?:(?P<host>[^;\?:]*)(?::(?P<port>[\d]+))?))' # host, port
            + '(?:;(?P<params>[^\?]*))?' # parameters
            )
    
    def __str__(self):
        uri = f"{self.scheme}:{self.user}@{self.host}"
        if self.port != 5060:
            uri += f":{self.port}"
        # if self.password:
        #     uri += f":{self.password}"
        if self.parameters:
            uri += f";{';'.join([f'{k}={v}' for k, v in self.parameters.items()])}"
        return uri

    @classmethod
    def parser(cls, uri: str) -> 'Uri':
        _match = cls._SYNTAX.match(uri)
        if not _match:
            raise ValueError(f"Invalid URI: {uri}")
        _params = {}
        if _match.group('params'):
            _params = dict([p.split('=') for p in _match.group('params').split(';')])
        return Uri(
            scheme=_match.group('scheme'),
            user=_match.group('user'),
            host=_match.group('host'),
            port=int(_match.group('port')) if _match.group('port') else 5060,
            # password=_match.group('password'),
            parameters=_params,
        )


class Address:
    uri: Uri
    display_name: str = None
    tag: str = None

    _SYNTAX = [
        re.compile('^(?P<display_name>[a-zA-Z0-9\-\.\_\+\~\ \t]*)<(?P<uri>[^>]+)>'),
        re.compile('^(?:"(?P<display_name>[a-zA-Z0-9\-\.\_\+\~\ \t]+)")[\ \t]*<(?P<uri>[^>]+)>'),
        re.compile('^[\ \t]*(?P<display_name>)(?P<uri>[^;]+)'),
        ]
    
    def __str__(self):
        address = f'"{self.display_name}" ' if self.display_name else ''
        address += f"<{self.uri}>"
        if self.tag:
            address += f";tag={self.tag}"
        return address
    
    @classmethod
    def parser(cls, address: str) -> 'Address':
        _match = cls._SYNTAX.match(address)
        if not _match:
            raise ValueError(f"Invalid Address: {address}")
        _uri = Uri().parser(_match.group('uri'))
        return Address(
            uri=_uri,
            display_name=_match.group('display_name'),
        )

class Field:
    def __init__(self, name: str, value: str, separator: str = ':'):
        self.name = name.strip()
        self.value = value.strip()
        self.separator = separator
    
    def __str__(self):
        return f"{self.name}{self.separator}{self.value}"
    
    @classmethod
    def parser(cls, field: str, separator: str = ':') -> 'Field':
        _name, _value = field.split(separator)
        return Field(
            name=_name,
            value=_value,
            separator=separator,
        )

    def generate_call_id(self) -> str:
        return str(uuid4())[0:8]

    def generate_tag(self) -> str:
        return str(uuid4())[0:6]

    def generate_branch(self) -> str:
        return f"z9hG4bK-{self.generate_tag()}"


class Via(Field):
    def __init__(
        self,
        host: str,
        port: int = 5060,
        branch: str = None,
        received: str = None,
        rport: int = None,
        protocol: str = 'SIP/2.0',
        transport: str = 'UDP'
    ):
        self.host = host
        self.port = port
        self.branch = branch or self.generate_branch()
        self.received = received
        self.rport = rport
        self.protocol = protocol
        self.transport = transport
        super().__init__('via', self._to_string())
    
    def _to_string(self):
        _host = (f"{self.host}:{self.port}" if self.port != 5060 else self.host)
        via = f"{self.protocol}/{self.transport} {_host};branch={self.branch}"
        if self.received:
            via += f";received={self.received}"
        if self.rport:
            via += f";rport={self.rport}"
        return via
    
    @classmethod
    def parser(cls, field: str) -> 'Via':
        _params = dict([p.split('=') for p in field.split(';')])
        _host, _port = _params.get('host').split(':')
        return Via(
            host=_host,
            port=int(_port),
            branch=_params.get('branch'),
            received=_params.get('received'),
            rport=int(_params.get('rport')),
            protocol=_params.get('protocol'),
            transport=_params.get('transport'),
        )


class From(Field):
    def __init__(
        self,
        address: Address,
        tag: str = None
    ):
        self.address = address
        self.tag = tag or self.generate_tag()
        super().__init__('From', self._to_string(), separator=':')
    
    def _to_string(self):
        _tag = f';tag={self.tag}' if self.tag else ''
        return f'{self.address}{_tag}'

    @classmethod
    def parser(cls, field: str) -> 'From':
        _tag = re.search(r';tag=(\w+)', field)
        if _tag:
            _tag = _tag.group(1)
            field = field.replace(f';tag={_tag}', '')
        return From(
            address=Address.parser(field),
            tag=_tag,
        )

class To(Field):
    def __init__(
        self,
        address: Address,
        tag: str = None
    ):
        self.address = address
        self.tag = tag or self.generate_tag()
        super().__init__('To', self._to_string(), separator=':')
    
    def _to_string(self):
        _tag = f';tag={self.tag}' if self.tag else ''
        return f'{self.address}{_tag}'

    @classmethod
    def parser(cls, field: str) -> 'To':
        _tag = re.search(r';tag=(\w+)', field)
        if _tag:
            _tag = _tag.group(1)
            field = field.replace(f';tag={_tag}', '')
        return From(
            address=Address.parser(field),
            tag=_tag,
        )


class Contact(Field):
    def __init__(
        self,
        address: Address,
        expires: str = None
    ):
        self.address = address
        self.expires = expires or self.generate_tag()
        super().__init__('Contact', self._to_string(), separator=':')
    
    def _to_string(self):
        _expires = f";expires={self.expires}" if self.expires else ''
        return f'{self.address}{_expires}'

    @classmethod
    def parser(cls, field: str) -> 'Contact':
        _expires = re.search(r';expires=(\d+)', field)
        if _expires:
            _expires = _expires.group(1)
            field = field.replace(f';expires={_expires}', '')
        return Contact(
            address=Address.parser(field),
            expires=_expires,
        )


class CallId(Field):
    def __init__(self, call_id: str = None):
        self.call_id = call_id or self.generate_call_id()
        super().__init__('Call-ID', self.call_id)

    @classmethod
    def parser(cls, field: str) -> 'CallId':
        _, _call_id = field.split(':')
        return CallId(_call_id)


class CSeq(Field):
    def __init__(self, method: str, seq: int):
        self.method = method
        self.seq = seq
        super().__init__('Cseq', self._to_string())
    
    def _to_string(self):
        return f"{self.seq} {self.method}"

    @classmethod
    def parser(cls, field: str) -> 'CSeq':
        _, _seq = field.split(':')
        _seq, _method = _seq.split(' ')
        return CSeq(_method, int(_seq))


class MaxForword(Field):
    def __init__(self, max_forword: int = 70):
        super().__init__('Max-Forwords', str(max_forword))

    @classmethod
    def parser(cls, field: str) -> 'MaxForword':
        _, _max_forword = field.split(':')
        return MaxForword(int(_max_forword))


class ContentType(Field):
    def __init__(self, content_type: str = 'application/sdp'):
        super().__init__('Content-Type', content_type)

    @classmethod
    def parser(cls, field: str) -> 'ContentType':
        _, _content_type = field.split(':')
        return ContentType(_content_type)


class ContentLength(Field):
    def __init__(self, content_length: int = 0):
        super().__init__('Content-Length', str(content_length))

    @classmethod
    def parser(cls, field: str) -> 'ContentLength':
        _, _content_length = field.split(':')
        return ContentLength(int(_content_length))


class Authorization(Field):
    def __init__(self, username: str, password: str, realm: str, nonce: str, uri: str, response: str):
        self.username = username
        self.password = password
        self.realm = realm
        self.nonce = nonce
        self.uri = uri
        self.response = response
        super().__init__('Authorization', self._to_string())
    
    def _to_string(self):
        return f"Digest username={self.username}, realm={self.realm}, nonce={self.nonce}, uri={self.uri}, response={self.response}"

    @classmethod
    def parser(cls, field: str) -> 'Authorization':
        _params = dict([p.split('=') for p in field.split(',')])
        return Authorization(
            username=_params.get('username'),
            password=_params.get('password'),
            realm=_params.get('realm'),
            nonce=_params.get('nonce'),
            uri=_params.get('uri'),
            response=_params.get('response'),
        )


@dataclass
class SipHeader:
    via: Via
    from_: From
    to: To
    call_id: CallId
    cseq: CSeq
    contact: Contact = None
    max_forword: MaxForword = field(default_factory=MaxForword)
    content_type: ContentType = field(default_factory=ContentType)
    content_length: ContentLength = field(default_factory=ContentLength)
    authorization: Authorization = None
    extras_fields: Dict[str, Field] = field(default_factory=dict)

    COMPACT_HEADERS_FIELDS = {
        'v': 'Via', 'f': 'From', 't': 'To', 'm': 'Contact',
        'i': 'Call-ID', 's': 'Subject', 'l': 'Content-Length',
        'c': 'Content-Type', 'k': 'Supported', 'o': 'Allow',
        'p': 'P-Associated-URI'
    }

    def __post_init__(self):
        if self.name.lower() in self.COMPACT_HEADERS_FIELDS:
            self.name = self.COMPACT_HEADERS_FIELDS[self.name.lower()]

    def __str__(self):
        _headers = ''
        _headers += f'{self.via}\r\n'
        _headers += f'{self.from_}\r\n'
        _headers += f'{self.to}\r\n'
        if self.contact:
            _headers += f'{self.contact}\r\n'
        _headers += f'{self.call_id}\r\n'
        _headers += f'{self.cseq}\r\n'
        _headers += f'{self.max_forword}\r\n'
        _headers += f'{self.content_type}\r\n'
        _headers += f'{self.content_length}\r\n'
        if self.authorization:
            _headers += f'{self.authorization}\r\n'
        if self.extras_fields:
            for field in self.extras_fields.values():
                _headers += f'{field}\r\n'
        return _headers
    
    @classmethod
    def parser(cls, headers: str) -> 'SipHeader':
        _headers = {}
        lines = headers.split('\r\n')
        for line in lines:
            name, value = line.split(':')
            match name.lower():
                case 'via':
                    _headers['via'] = Via.parser(value)
                case 'from':
                    _headers['from'] = From.parser(value)
                case 'to':
                    _headers['to'] = To.parser(value)
                case 'contact':
                    _headers['contact'] = Contact.parser(value)
                case 'call-id':
                    _headers['call_id'] = CallId.parser(value)
                case 'cseq':
                    _headers['cseq'] = CSeq.parser(value)
                case 'max-forword':
                    _headers['max_forword'] = MaxForword.parser(value)
                case 'content-type':
                    _headers['content_type'] = ContentType.parser(value)
                case 'content-length':
                    _headers['content_length'] = ContentLength.parser(value)
                case 'authorization':
                    _headers['authorization'] = Authorization.parser(value)
                case _:
                    _headers[name] = Field.parser(name, value)
        return SipHeader(**_headers)


class MediaType(Enum):
    AUDIO = "audio"
    VIDEO = "video"
    MESSAGE = "message"

    def __str__(self):
        return self.value

class MediaSessionType(Enum):
    SENDRECV = "sendrecv"
    SENDONLY = "sendonly"
    RECVONLY = "recvonly"
    INACTIVE = "inactive"

    def __str__(self):
        return self.value


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

class MediaProtocolType(Enum):
    RTP_AVP = 'RTP/AVP'
    RTCP = 'RTCP'

    def __str__(self) -> str:
        return self.value


class Owner(Field):
    def __init__(
        self,
        username: str = '-',
        address: str = '0.0.0.0',
        address_type: str = 'IP4',
        network_type: str = 'IN',
        session_id: str = None,
        session_version: str = None
    ):
        self.username = username
        self.address = address
        self.address_type = address_type
        self.network_type = network_type
        self.session_id = session_id or self.generate_call_id()
        self.session_version = session_version or self.generate_call_id()
        super().__init__(
            'o',
            f'{self.username} {self.session_id} {self.session_version} {self.network_type} {self.address_type} {self.address}',
            separator='='
            )
    
    @classmethod
    def parser(cls, field: str) -> 'Owner':
        _, field = field.split('=', maxsplit=1)
        _username, _session_id, _session_version, _network_type, _address_type, _address = field.split(' ')
        return Owner(
            username=_username,
            address=_address,
            address_type=_address_type,
            network_type=_network_type,
            session_id=_session_id,
            session_version=_session_version,
        )


class ConnectionInformation(Field):
    def __init__(
        self,
        network_type: str = 'IN',
        address_type: str = 'IP4',
        address: str = '0.0.0.0'
    ):
        self.network_type = network_type
        self.address_type = address_type
        self.address = address
        super().__init__(
            'c',
            f'{self.network_type} {self.address_type} {self.address}',
            separator='='
            )
    
    @classmethod
    def parser(cls, field: str) -> 'ConnectionInformation':
        _, field = field.split('=', maxsplit=1)
        _network_type, _address_type, _address = field.split(' ')
        return ConnectionInformation(
            network_type=_network_type,
            address_type=_address_type,
            address=_address,
        )


class MediaDescription(Field):
    PORT_RANGE = (10000, 20000)
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
            f'{self.media_type} {self.port} {self.protocol} {_codec} {self.dtmf_payload.code}',
            separator='='
        )
    
    def _generate_port(self) -> int:
        return random.randint(*self.PORT_RANGE)

    @classmethod
    def parser(cls, field: str) -> 'MediaDescription':
        _, field = field.split('=', maxsplit=1)
        _media_type, _port, _protocol, *_codes = field.split(' ')
        _dtmf_payload = _codes[-1]
        _codecs = [CodecType(c) for c in _codes[:-1]]
        return MediaDescription(
            media_type=MediaType(_media_type),
            port=int(_port),
            protocol=MediaProtocolType(_protocol),
            codecs=_codecs,
            dtmf_payload=DtmfPayloadType(_dtmf_payload),
        )


class SessionName(Field):
    def __init__(self, name: str = 'SDP Session'):
        self.name = name or self.generate_call_id()
        super().__init__('s', self.name, separator='=')

    @classmethod
    def parser(cls, field: str) -> 'SessionName':
        _, _name = field.split('=', maxsplit=1)
        return SessionName(_name)


class MediaSession(Field):
    def __init__(self, version: str = '0'):
        self.version = version
        super().__init__('v', self.version, separator='=')

    @classmethod
    def parser(cls, field: str) -> 'MediaSession':
        _, _version = field.split('=', maxsplit=1)
        return MediaSession(_version)


class Time(Field):
    def __init__(self, start: int = 0, stop: int = 0):
        self.start = start
        self.stop = stop
        super().__init__('t', f'{self.start} {self.stop}', separator='=')

    @classmethod
    def parser(cls, field: str) -> 'Time':
        _, field = field.split('=', maxsplit=1)
        _start, _stop = field.split(' ')
        return Time(int(_start), int(_stop))


class Attribute(Field):
    def __init__(self, attribute: str):
        self.attribute = attribute
        super().__init__('a', self.attribute, separator='=')

    @classmethod
    def parser(cls, field: str) -> 'Attribute':
        _, _value = field.split('=', maxsplit=1)
        return Attribute(_value)


class AttrPtime(Attribute):
    def __init__(self, ptime: int = 20):
        self.ptime = ptime
        super().__init(f'ptime:{self.ptime}')

    @classmethod
    def parser(cls, field: str) -> 'AttrPtime':
        _, _value = field.split('=', maxsplit=1)
        return AttrPtime(int(_value))

class AttrMediaSession(Attribute):
    def __init__(self, session_type: MediaSessionType):
        self.session_type = session_type
        super().__init__(str(self.session_type))

    @classmethod
    def parser(cls, field: str) -> 'AttrMediaSession':
        _, _value = field.split('=', maxsplit=1)
        return AttrMediaSession(MediaSessionType(_value))


class AttrRtpMap(Attribute):
    def __init__(self, payload_type: str, encoding_name: str, clock_rate: str, channels: str = None):
        self.payload_type = payload_type
        self.encoding_name = encoding_name
        self.clock_rate = clock_rate
        self.channels = channels
        super().__init(f'rtpmap:{self.payload_type} {self.encoding_name}/{self.clock_rate}/{self.channels}' if self.channels else f'rtpmap:{self.payload_type} {self.encoding_name}/{self.clock_rate}')

    @classmethod
    def parser(cls, field: str) -> 'AttrRtpMap':
        _, _value = field.split('=', maxsplit=1)
        _payload_type, _encoding_name, _clock_rate, *_channels = _value.split(' ')
        _channels = _channels[0] if _channels else None
        return AttrRtpMap(_payload_type, _encoding_name, _clock_rate, _channels)


class AttrFmtp(Attribute):
    def __init__(self, payload_type: str, config: str):
        self.payload_type = payload_type
        self.config = config
        super().__init(f'fmtp:{self.payload_type} {self.config}')

    @classmethod
    def parser(cls, field: str) -> 'AttrFmtp':
        _, _value = field.split('=', maxsplit=1)
        _payload_type, _config = _value.split(' ')
        return AttrFmtp(_payload_type, _config)


@dataclass
class SdpMedia:
    '''
    v=0\r\n
    o=- 20211 20211 IN IP4 local.domain.com\r\n
    s=SDP data\r\n
    c=IN IP4 local.domain.com\r\n
    t=0 0\r\n
    m=audio 11808 RTP/AVP 9 0 8 18 101\r\n
    a=rtpmap:9 G722/8000\r\n
    a=rtpmap:0 PCMU/8000\r\n
    a=rtpmap:8 PCMA/8000\r\n
    a=rtpmap:18 G729/8000\r\n
    a=fmtp:18 annexb=no\r\n
    a=ptime:20\r\n
    a=sendrecv\r\n
    a=rtpmap:101 telephone-event/8000\r\n
    a=fmtp:101 0-15\r\n
    '''
    owner: Owner = field(default_factory=Owner)
    connection_information: ConnectionInformation = field(default_factory=ConnectionInformation)
    session_name: SessionName = field(default_factory=SessionName)
    media_description: MediaDescription = field(default_factory=MediaDescription)
    media_session: AttrMediaSession = field(default_factory=AttrMediaSession)
    ptime: AttrPtime = field(default_factory=AttrPtime)
    rtp_map: List[AttrRtpMap] = field(default_factory=list)
    fmtp: List[AttrFmtp] = field(default_factory=list)
    attrs: List[Attribute] = field(default_factory=list)
    extras_fields: Dict[str, Field] = field(default_factory=dict)

    def __str__(self):
        _sdp = ''
        _sdp += f'{self.owner}\r\n'
        _sdp += f'{self.connection_information}\r\n'
        _sdp += f'{self.session_name}\r\n'
        _sdp += f'{self.media_description}\r\n'
        if self.rtp_map:
            for rtp_map in self.rtp_map:
                _sdp += f'{rtp_map}\r\n'
        if self.fmtp:
            for fmtp in self.fmtp:
                _sdp += f'{fmtp}\r\n'
        if self.ptime:
            _sdp += f'{self.ptime}\r\n'
        if self.media_session:
            _sdp += f'{self.media_session}\r\n'
        if self.attrs:
            for attr in self.attrs:
                _sdp += f'{attr}\r\n'
        return _sdp
    
    @classmethod
    def parser(cls, media: str) -> 'SdpMedia':
        lines = media.split('\r\n')
        _media = {}
        for line in lines:
            name, value = line.split('=', maxsplit=1)
            match name:
                case 'o':
                    _media['owner'] = Owner.parser(value)
                case 'c':
                    _media['connection_information'] = ConnectionInformation.parser(value)
                case 'm':
                    _media['media_description'] = MediaDescription.parser(value)
                case 's':
                    _media['session_name'] = SessionName.parser(value)
                case 'a':
                    if 'rtpmap' in value:
                        _media['rtp_map'].append(AttrRtpMap.parser(value))
                    elif 'fmtp' in value:
                        _media['fmtp'].append(AttrFmtp.parser(value))
                    elif 'ptime' in value:
                        _media['ptime'] = AttrPtime.parser(value)
                    elif 'sendrecv' in value:
                        _media['media_session'] = AttrMediaSession.parser(value)
                    else:
                        _media['attrs'].append(Attribute.parser(value))
        return SdpMedia(**_media)
            


class SipMessage(ABC):
    def __init__(
        self,
        method: SipMethod = None,
        status_code: SipStatusCode = None,
        headers: SipHeader = None,
        body: SdpMedia = None):
        self.headers = headers or defaultdict(list)
        self.body = body or defaultdict(list)
    
    @property
    def is_request(self) -> bool:
        return self.method is not None
    
    @property
    def is_response(self) -> bool:
        return self.status_code is not None
    
    def add_header(self, header: Field):
        self.headers[header.name].append(header)
    
    def get_header(self, name: str) -> Field:
        return self.headers.get(name)

    def add_body(self, body: Field):
        self.body[body.name].append(body)
    
    def get_body(self, name: str) -> Field:
        return self.body.get(name)

    def to_bytes(self):
        return str(self).encode()
    
    @abstractmethod
    def parser(cls, message: bytes) -> 'SipMessage':
        headers, body = message.split(b'\r\n\r\n')
        _headers = SipHeader.parser(headers)
        if body:
            _body = SdpMedia.parser(body)
        return SipMessage(headers=_headers, body=_body)
    
    @abstractmethod
    def __str__(self):
        if self.is_request:
            _message = f'{self.method} {self.uri} SIP/2.0\r\n'
        elif self.is_response:
            _message = f'SIP/2.0 {self.status_code}\r\n'
        _message += f'{self.headers}'
        if self.body:
            _message += f'\r\n{self.body}'
        return _message

class SipDialog:
    def __init__(self, call_id: str, local_tag: str, remote_tag: str):
        self.call_id = call_id
        self.local_tag = local_tag
        self.remote_tag = remote_tag
        self.state = DialogState.INIT
        self.local_seq = 0
        self.remote_seq = 0
    
    def update_state(self, state: DialogState):
        log.info(f"Dialog {self.call_id} state updated: {self.state} -> {state}")
        self.state = state
    
    def update_local_seq(self, seq: int):
        log.info(f"Dialog {self.call_id} local seq updated: {self.local_seq} -> {seq}")
        self.local_seq = seq
    
    def update_remote_seq(self, seq: int):
        log.info(f"Dialog {self.call_id} remote seq updated: {self.remote_seq} -> {seq}")
        self.remote_seq = seq


class SipTransaction:
    def __init__(self, request: SipMessage):
        self.request = request
        self.response = None
        self.state = None
        self.timer = asyncio.create_task(self.transaction_timer())
        self.retransmit = 0
    
    async def transaction_timer(self):
        await asyncio.sleep(32)  # RFC 3261 recommends 32 seconds
        if self.state != "COMPLETED":
            logging.warning(f"Transaction {self.request.get_header('CSeq')} timed out")
            self.state = "TERMINATED"
    
    def retransmit_request(self):
        pass
    
    def receive_response(self, response: SipMessage):
        self.response = response
        if response.status_code in [SipStatusCode.TRYING, SipStatusCode.RINGING]:
            self.state = "COMPLETED"
            if self.timer:
                self.timer.cancel()
        elif response.status_code in [SipStatusCode.OK]:
            self.state = "TERMINATED"
            if self.timer:
                self.timer.cancel()
        else:
            self.retransmit += 1
            if self.retransmit == 7:
                self.state = "TERMINATED"
                if self.timer:
                    self.timer.cancel()
            else:
                self.retransmit_request()


class SipRegister(SipTransaction):
    pass

class SipCall(SipTransaction):
    pass


class SipSubscribe(SipTransaction):
    pass


class SipMessage(SipTransaction):
    pass


class SipKeepAlive(SipTransaction):
    pass

class SocketInterface(ABC):
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        self.sock = None
        self._running = False
    
    def _connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.ip, self.port))
        self._running = True
    
    def _disconnect(self):
        self._running = False
        self.sock.close()
    
    async def _send(self, data: bytes):
        if not self.sock:
            self._connect()
        await asyncio.get_event_loop().sock_sendto(self.sock, data, (self.ip, self.port))
    
    async def _receive(self):
        while self._running:
            data, addr = await asyncio.get_event_loop().sock_recv(self.sock, 4096)
            yield data, addr


class SipHandler(SocketInterface):
    def __init__(self, ip: str, port: int, callback: callable):
        super().__init__(ip, port)
        self.callback = callback
        self._receive_task = None
    
    async def send(self, message: SipMessage):
        await self._send(message.to_bytes())
    
    async def receive(self):
        for data, addr in self._receive():
            message = SipMessage.parser(data)
            self.callback(message, addr)

    async def start(self):
        self._connect()
        self._receive_task = await asyncio.create_task(self.receive())
    
    async def close(self):
        self._disconnect()
        await self._receive_task.cancel()


class RtpHandler(SocketInterface):
    def __init__(self, ip: str, port: int, callback: callable):
        super().__init__(ip, port)
        self.callback = callback
        self._receive_task = None
    
    async def send(self, data: bytes):
        await self._send(data)
    
    async def receive(self):
        for data, addr in self._receive():
            self.callback(data, addr)

    async def start(self):
        self._connect()
        self._receive_task = await asyncio.create_task(self.receive())
    
    async def close(self):
        self._disconnect()
        await self._receive_task.cancel()


class DtmfHandler(SocketInterface):
    def __init__(self, ip, port, callback):
        super().__init__(ip, port)
        self.callback = callback
        self._receive_task = None
    
    async def send(self, digit: str):
        await self._send(digit.encode())
    
    async def receive(self):
        for data, addr in self._receive():
            self.callback(data, addr)
    
    async def start(self):
        self._connect()
        self._receive_task = await asyncio.create_task(self.receive())
    
    async def close(self):
        self._disconnect()
        await self._receive_task.cancel()


@dataclass
class UserAgentConfig:
    username: str
    server: str
    port: int = field(default=5060)
    login: str = field(default=None)
    password: str = field(default=None)
    realm: str = field(default=None)
    proxy: str = field(default=None)
    user_agent: str = field(default="PyPhone")
    time_out: int = field(default=30)
    expires: int = field(default=30)


class SipClient:
    transactions: dict[str, SipTransaction] = {}
    dialogs: dict[str, SipDialog] = {}
    cseq = 0
    
    def __init__(
        self,
        local_ip: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        ua_cfg: UserAgentConfig,
        event_loop = None
    ):
        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.ua_cfg = ua_cfg

        self.event_loop = event_loop or asyncio.get_event_loop()
        self.sock: SipHandler = SipHandler(local_ip, local_port, self.on_received_message)
        self.rtp: RtpHandler = None
        self.dtmf: DtmfHandler = None
        self._receive_message_task = None
    
    async def start(self):
        await self.sock.start()

    async def close(self):
        await self.sock.close()
        await self._receive_message_task.cancel()
    
    async def send_message(self, message: SipMessage):
        log.info(f"Sending SIP message: {message}")
        await self.sock.send(message)

    async def on_received_message(self, message: SipMessage, addr: Tuple[str, int]):
        match message:
            case message.is_request():
                log.info(f"Received SIP request: {message}")
            case message.is_response():
                log.info(f"Received SIP response: {message}")
            case _:
                log.error(f"Invalid SIP message: {message}")
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
