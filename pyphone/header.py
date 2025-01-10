from dataclasses import dataclass, field
from typing import Dict
import re
from uuid import uuid4

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
        pass
    
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