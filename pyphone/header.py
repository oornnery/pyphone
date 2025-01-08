import re
from dataclasses import dataclass, field
from typing import List
from uuid import uuid4


def generate_call_id() -> str:
    return str(uuid4())[0:8]

def generate_tag() -> str:
    return str(uuid4())[0:6]

def generate_branch() -> str:
    return f"z9hG4bK-{generate_tag()}"


# SIP Header RFC:
@dataclass
class Uri:
    user: str
    host: str
    port: int = field(default=5060)
    scheme: str = field(default='sip')
    password: str = field(default=None)
    parameters: dict = field(default_factory=dict)
    
    _SYNTAX = re.compile('^(?P<scheme>[a-zA-Z][a-zA-Z0-9\+\-\.]*):'# scheme
            + '(?:(?:(?P<user>[a-zA-Z0-9\-\_\.\!\~\*\'\(\)&=\+\$,;\?\/\%]+)' # user 
            + '(?::(?P<password>[^:@;\?]+))?)@)?' # password
            + '(?:(?:(?P<host>[^;\?:]*)(?::(?P<port>[\d]+))?))' # host, port
            + '(?:;(?P<params>[^\?]*))?' # parameters
            )
    def __str__(self):
        uri = f"{self.scheme}:{self.user}@{self.host}"
        if self.port != 5060:
            uri += f":{self.port}"
        if self.password:
            uri += f":{self.password}"
        if self.parameters:
            uri += f";{';'.join([f'{k}={v}' for k, v in self.parameters.items()])}"
        return uri
    
    def __repr__(self):
        return self.__str__()
    
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
            password=_match.group('password'),
            parameters=_params,
        )


@dataclass
class Address:
    uri: Uri
    display_name: str = None
    
    _SYNTAX = [
        re.compile('^(?P<display_name>[a-zA-Z0-9\-\.\_\+\~\ \t]*)<(?P<uri>[^>]+)>'),
        re.compile('^(?:"(?P<display_name>[a-zA-Z0-9\-\.\_\+\~\ \t]+)")[\ \t]*<(?P<uri>[^>]+)>'),
        re.compile('^[\ \t]*(?P<display_name>)(?P<uri>[^;]+)'),
        ]
    
    def __str__(self):
        address = f'"{self.display_name}" ' if self.display_name else ''
        address += f"<{self.uri}>"
        return address
    
    def __repr__(self):
        return self.__str__()
    
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


class Header(str):
    _SYNTAX = re.compile('^(?P<name>[a-zA-Z0-9\-\.\_]+):[\ \t]*(?P<value>.*)$')
    COMPACT_HEADERS_FIELDS = {
        'v': 'via', 'f': 'from', 't': 'to', 'm': 'contact',
        'i': 'call-id', 's': 'subject', 'l': 'content-length',
        'c': 'content-type', 'k': 'supported', 'o': 'allow',
        'p': 'p-associated-uri'
    }
    
    def __init__(self, name: str, value: str):
        self.name = self.COMPACT_HEADERS_FIELDS[name] if name in self.COMPACT_HEADERS_FIELDS else \
            name.strip()
        self.value = value.strip()

    def __str__(self):
        return f"{self.name}: {self.value}"
    
    def __repr__(self):
        return f"{self.name}: {self.value}"
    
    @classmethod
    def parser(cls, header: str) -> 'Header':
        _match = cls._SYNTAX.match(header)
        if not _match:
            raise ValueError(f"Invalid Header: {header}")
        return Header(
            name=_match.group('name'),
            value=_match.group('value')
        )


class Via(Header):
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
        self.branch = branch or generate_branch()
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


class From(Header):
    def __init__(
        self,
        address: Address,
        tag: str = None
    ):
        self.address = address
        self.tag = tag or generate_tag()
        super().__init__('from', self._to_string())
    
    def _to_string(self):
        _tag = f';tag={self.tag}' if self.tag else ''
        return f'{self.address}{_tag}'

class To(Header):
    def __init__(
        self,
        address: Address,
        tag: str = None
    ):
        self.address = address
        self.tag = tag or generate_tag()
        super().__init__('to', self._to_string())
    
    def _to_string(self):
        _tag = f';tag={self.tag}' if self.tag else ''
        return f'{self.address}{_tag}'


class Contact(Header):
    def __init__(
        self,
        address: Address,
        expires: int = None
    ):
        self.address = address
        self.expires = expires
        super().__init__('contact', self._to_string())
    
    def _to_string(self):
        _expires = f";expires={self.expires}" if self.expires else ''
        return f'{self.address}{_expires}'


class CallId(Header):
    def __init__(self, call_id: str = None):
        self.call_id = call_id or generate_call_id()
        super().__init__('call-id', self.call_id)


class CSeq(Header):
    def __init__(self, method: str, seq: int):
        self.method = method
        self.seq = seq
        super().__init__('cseq', self._to_string())
    
    def _to_string(self):
        return f"{self.seq} {self.method}"


class MaxForword(Header):
    def __init__(self, max_forword: int = 70):
        super().__init__('max-forword', str(max_forword))


@dataclass
class HeaderFactory:
    via: Via = None
    from_: From = None
    to: To = None
    contact: Contact = None
    call_id: CallId = None
    cseq: CSeq = None
    extras_header: List[Header] = field(default_factory=list)

    def __repr__(self):
        pass

    @classmethod
    def from_to_string(cls, headers: str) -> 'HeaderFactory':
        extras_header = []
        lines = headers.split('\r\n')
        
        for line in lines:
            name, value = line.split(':')
            match name.lower():
                case 'via':
                    via = Via.parser(value)
                case 'from':
                    from_ = From.parser(value)
                case 'to':
                    to = To.parser(value)
                case 'contact':
                    contact = Contact.parser(value)
                case 'call-id':
                    call_id = CallId.parser(value)
                case 'cseq':
                    cseq = CSeq.parser(value)
                case _:
                    extras_header.append(Header(name, value))
        return HeaderFactory(
            via=via,
            from_=from_,
            to=to,
            contact=contact,
            call_id=call_id,
            cseq=cseq,
            extras_header=extras_header
        )
        
        