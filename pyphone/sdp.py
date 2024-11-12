from enum import Enum
from uuid import uuid4
from typing import Union, Any, List
from abc import ABC


from pyphone.utils import EOL

class MediaType(Enum):
    """Supported media types in SDP"""
    AUDIO = 'audio'
    VIDEO = 'video'
    APPLICATION = 'application'
    MESSAGE = 'message'
    TEXT = 'text'

    def __str__(self) -> str:
        return self._value_


class CodecType(Enum):
    PCMU = ('0', 'pcmu', '8000')
    PCMA = ('8', 'pcma', '8000')

    def __new__(self, code: str, description: str, rate: str):
        obj = object.__new__(self)
        obj._value_ = code
        obj.description = description
        obj.rate = rate
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
        obj._value_ = code
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


class MediaProtocolType(Enum):
    RTP = 'RTP/AVP'
    RTCP = 'RTCP'

    def __str__(self) -> str:
        return self._value_

# SDP Classes
# TODO: Melhorar isso
class AbstractSdp:
    def __init__(self, key: str, value: str):
        self.key = key
        self.value = value

    def __str__(self) -> str:
        return f'{self.key}={self.value}{EOL}'


class Owner(AbstractSdp):
    def __init__(
        self,
        username: str = '-',
        session_id: str = None,
        session_version: str = None,
        network_type: str = 'IN',
        address_type: str = 'IP4',
        address: str = '0.0.0.0',
    ):
        self.username = username
        self.session_id = session_id or self._generate_session_id()
        self.session_version = session_version or self._generate_session_id()
        self.network_type = network_type
        self.address_type = address_type
        self.address = address
        super().__init__(
            'o',
            f'{self.username} {self.session_id} {self.session_version} {self.network_type} {self.address_type} {self.address}'
            )

    def _generate_session_id(self) -> str:
        return uuid4().hex[:5]


class Attribute(AbstractSdp):
    def __init__(self, value: str, name: str = None):
        self.name = name
        self.value = value
        _name = f'{self.name}:' if self.name else ''
        super().__init__('a', f'{self.name}{self.value}')


class ConectionInformation(AbstractSdp):
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


class MediaDescription(AbstractSdp):
    def __init__(
        self,
        port: int,
        media_type: MediaType = MediaType.AUDIO,
        protocol: MediaProtocolType = MediaProtocolType.RTP,
        codecs: List[CodecType] = [CodecType.PCMU, CodecType.PCMA],
        dtmf_payload: DtmfPayloadType = DtmfPayloadType.RFC_2833,
    ):
        self.media_type = media_type
        self.port = port
        self.protocol = protocol
        self.codecs = codecs
        self.dtmf_payload = dtmf_payload
        _codec = ' '.join([str(c.code) for c in self.codecs])
        super().__init__(
            'm',
            f'{self.media_type} {self.port} {self.protocol} {_codec} {self.dtmf_payload.code}'
        )


class Sdp:
    MULTI_SDP = ('t', 'r', 'a')
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
    def __init__(
        self,
        owner: Owner,
        connection_information: ConectionInformation,
        media_description: MediaDescription,
        media_session_type: MediaSessionType = MediaSessionType.SENDRECV,
        ptime: int = 20,
        session_name: str = 'SDP Session',
        extras_fields: List[AbstractSdp] = None
        ):
        self._sdp = {}
        self.owner = owner
        self.connection_information = connection_information
        self.session_name = session_name
        self.media_description = media_description
        self.media_session_type = media_session_type
        self.ptime = ptime
        self.attributes = extras_fields or []
        
        # TODO: Implementar kwargs
        if self.owner:
            self._sdp['o'] = self.owner
        if self.connection_information:
            self._sdp['c'] = self.connection_information
        if self.media_description:
            self._sdp['m'] = self.media_description
            for c in self.media_description.codecs:
                self.attributes.append(Attribute(name='fmtp', value=c))
            self.attributes.append(Attribute(name='rtpmap', value=self.media_description.dtmf_payload))
            self.attributes.append(Attribute(name='fmtp', value=self.media_description.dtmf_payload.fmtp))
        if self.session_name:
            self._sdp['s'] = self.session_name
        if self.ptime:
            self.attributes.append(Attribute(name='ptime', value=ptime))
        if self.media_session_type:
            self.attributes.append(Attribute(value=media_session_type))
        if self.attributes:
            self._sdp['a'] = self.attributes
    
    def __setitem__(self, key: str, value: AbstractSdp) -> Union[str, List[str], None]:
        if key in self.MULTI_SDP:
            if key not in self._sdp:
                self._sdp[key] = []
            if isinstance(value, (list, tuple)):
                self._sdp[key].extend(value)
            else:
                self._sdp[key].append(value)
        else:
            self._sdp[key] = value
        return self._sdp[key]

    def __getitem__(self, key: str) -> Union[str, List[str], None]:
        return self._sdp.get(key, None)

    def __delitem__(self, key: str) -> None:
        del self._sdp[key]
    
    def __contains__(self, key: str) -> bool:
        return key in self._sdp
    
    def add(self, value: Any) -> Union[str, List[str], None]:
        self[value.key] = value
        return self[value.key]
    
    def get(self, key: str) -> Union[str, List[str], None]:
        return self[key]

    def __str__(self) -> str:
        lines = []
        for _, value in self._sdp.items():
            if isinstance(value, (list, tuple)):
                for item in value:
                    lines.append(item)
            else:
                lines.append(value)
        return ''.join([f'{line}{EOL}' for line in lines])
    
    @staticmethod
    def from_string(cls, string: str) -> 'Sdp':
        s = cls()
        lines = [line.strip() for line in string.splitlines() if line.strip()]
        for line in lines:
            if '=' not in line:
                continue
            k, v = line.split('=', 1)
            s[k.strip()] = v.strip()
        return s
