from typing import Union, Dict, List, AnyStr, Literal
from dataclasses import dataclass, field
from rich.panel import Panel
import re

from pyphone.core.utils import (
    cl,
    ProtocolType,
    SipMethod,
    SIP_VERSION,
    SIP_SCHEME,
    EOL,
    parser_uri_to_str
    )

__all__ = [
    'Header',
    'Via',
    'MaxForwards',
    'From',
    'To',
    'Contact',
    'CallId',
    'CSeq',
    'UserAgent',
    'Expires',
    'Allow',
    'ContentType',
    'ContentLength',
    'ProtocolType',
    'SipMethod',
]

# TODO: Refactor classes and group some objects.



@dataclass
class Via:
    """
    https://datatracker.ietf.org/doc/html/rfc3261#page-179
    parameters such as "maddr","ttl", "received", and "branch"
    Via: SIP/2.0/UDP erlang.bell-telephone.com:5060;branch=z9hG4bK87asdks7
    Via: SIP/2.0/UDP 192.0.2.1:5060 ;received=192.0.2.207;branch=z9hG4bK77asjd
    Via: SIP / 2.0 / UDP first.example.com: 4000;ttl=16;maddr=224.2.0.1 ;branch=z9hG4bKa7c6a8dlze.1
    """
    address: AnyStr
    port: int
    scheme: AnyStr = field(default=SIP_SCHEME)
    version: AnyStr = field(default=SIP_VERSION)
    protocol: ProtocolType = field(default=ProtocolType.UDP)
    params: Dict[Literal['maddr', 'ttl', 'received', 'branch'], str] = None

    def __str__(self) -> str:
        _uri = parser_uri_to_str(address=self.address, port=self.port, params=self.params)
        return f'Via: {self.scheme.upper()}/{self.version}/{self.protocol} {_uri}'

    @staticmethod
    def parser(message: str) -> 'Via':
        _syntax = re.compile(r'''
        Via:\s
        (?P<scheme>\w+)/(?P<version>\d+\.\d+)/(?P<protocol>\w+)
        \s
        (?P<address>[^:]+)
        (?::(?P<port>\d+))?
        (?P<params>;(?:[^;=]+(?:=(?:[^;\s]+))?))*
        ''', re.VERBOSE)
        
        print(_syntax.match(message).groupdict())
        
        

@dataclass
class MaxForwards:
    max_forwards: int = field(default=70)
    def __str__(self) -> str:
        return f'Max-Forwards: {self.max_forwards}'


@dataclass
class From:
    username: AnyStr
    address: AnyStr
    port: int = None
    display_info: AnyStr = None
    caller_id: AnyStr = None
    params: Dict[str, str] = None

    def __str__(self) -> str:
        display_info = f'"{self.display_info}" ' if self.display_info else ""
        _uri = parser_uri_to_str(address=self.address, user=self.username, port=self.port, params=self.params)
        return f'From: {display_info}<{_uri}>'


@dataclass
class To:
    username: AnyStr
    address: AnyStr
    port: int = None
    params: Dict[str, str] = None
    def __str__(self) -> str:
        _uri = parser_uri_to_str(address=self.address, user=self.username, port=self.port, params=self.params)
        return f'To: <{_uri}>'


@dataclass
class Contact:
    username: AnyStr
    address: AnyStr
    def __str__(self) -> str:
        _uri = parser_uri_to_str(address=self.address, user=self.username)
        return f'Contact: <{_uri}>'


@dataclass
class CallId:
    call_id: AnyStr
    def __str__(self) -> str:
        return f'Call-ID: {self.call_id}'


@dataclass
class CSeq:
    cseq: int
    method: SipMethod
    def __str__(self) -> str:
        return f'CSeq: {self.cseq} {self.method}'


@dataclass
class UserAgent:
    user_agent: AnyStr
    def __str__(self) -> str:
        return f'User-Agent: {self.user_agent}'


@dataclass
class Server:
    server: AnyStr
    def __str__(self) -> str:
        return f'Server: {self.server}'


@dataclass
class Expires:
    expires: int = field(default=30)
    def __str__(self) -> str:
        return f'Expires: {self.expires}'


@dataclass
class Allow:
    allowed_methods: List[SipMethod] = field(default_factory=lambda: [
        SipMethod.INVITE,
        SipMethod.ACK,
        SipMethod.BYE,
        SipMethod.CANCEL,
        SipMethod.REGISTER,
        SipMethod.OPTIONS
    ])
    def __str__(self) -> str:
        allow = ', '.join([str(a) for a in self.allowed_methods])
        return f'Allow: {allow}'


@dataclass
class ContentType:
    content_type: AnyStr = field(default='application/sdp')
    def __str__(self) -> str:
        return f'Content-Type: {self.content_type}'


@dataclass
class ContentLength:
    content_length: int = 0
    def __str__(self) -> str:
        return f'Content-Length: {self.content_length}'



class Header:
    def __init__(self, **kwargs):
        """
        Constructor for Header.

        :param via_uri: Union[Via, List[Via]] of Via header.
        :param from_uri: From header.
        :param to_uri: To header.
        :param contact_uri: Union[Contact, List[Contact]] of Contact header.
        :param call_id: CallId header.
        :param cseq: CSeq header.
        :param max_forwards: MaxForwards header.
        :param user_agent: UserAgent header.
        :param server: Server header.
        :param expires: Expires header.
        :param allow: Allow header.
        :param supported: Supported header (Not implemented yet).
        :param unsupported: Unsupported header (Not implemented yet).
        :param content_type: ContentType header.
        :param content_length: ContentLength header.
        :param route: List of Route header (Not implemented yet).
        :param record_route: List of RecordRoute header (Not implemented yet).
        :param proxy_authenticate: ProxyAuthenticate header (Not implemented yet).
        :param authorization: Authorization header (Not implemented yet).
        """
        self._via_uri: Union[Via, List[Via]] = kwargs.get('via_uri', [])
        self._from_uri: From = kwargs.get('from_uri', None)
        self._to_uri: To = kwargs.get('to_uri', None)
        self._contact_uri: Union[Contact, List[Contact]] = kwargs.get('contact_uri', [])
        self._call_id: CallId = kwargs.get('call_id', None)
        self._cseq: CSeq = kwargs.get('cseq', None)
        self._max_forwards: MaxForwards = kwargs.get('max_forwards', None)
        self._user_agent: UserAgent = kwargs.get('user_agent', None)
        self._server: Server = kwargs.get('server', None)
        self._expires: Expires = kwargs.get('expires', None)
        self._allow: Allow = kwargs.get('allow', None)
        self._content_type: ContentType = kwargs.get('content_type', None)
        self._content_length: ContentLength = kwargs.get('content_length', None)

    def __str__(self) -> str:
        h = []
        
        if isinstance(self._via_uri, list):
            h.extend([_ for _ in self._via_uri])
        else:
            h.append(self._via_uri)

        h.extend(
            [
                self._from_uri,
                self._to_uri,
            ]
        )
        if isinstance(self._contact_uri, list):
            h.extend([_ for _ in self._contact_uri])
        else:
            h.append(self._contact_uri)

        h.extend(
            [
                self._call_id,
                self._cseq,
                self._max_forwards,
                self._allow,
                self._content_type,
                self._content_length,
                self._user_agent,
                self._server,
                self._expires,
            ]
        )
            
        # TODO: Refactore to not allow multiple headers with the same name
        return f'{EOL}'.join([str(_) for _ in h if _])

    def __rich__(self) -> Panel:
        return Panel(self.__str__(), title="Headers", highlight=True, expand=False)

    def to_bytes(self) -> bytes:
        return str(self).encode()

    @property
    def via_uri(self) -> List[Via]:
        return self._via_uri

    @via_uri.setter
    def via_uri(self, via_uri: Via):
        if self._via_uri is None:
            self._via_uri = []
        if not isinstance(self._via_uri, list):
            self._via_uri = [self._via_uri]
        self._via_uri.append(via_uri)

    @property
    def from_uri(self) -> From:
        return self._from_uri

    @from_uri.setter
    def from_uri(self, from_uri: From):
        self._from_uri = from_uri

    @property
    def to_uri(self) -> To:
        return self._to_uri

    @to_uri.setter
    def to_uri(self, to_uri: To):
        self._to_uri = to_uri

    @property
    def contact_uri(self) -> Contact:
        return self._contact_uri

    @contact_uri.setter
    def contact_uri(self, contact_uri: Contact):
        if self._contact_uri is None:
            self._contact_uri = []
        if not isinstance(self._contact_uri, list):
            self._contact_uri = [self._contact_uri]
        self._contact_uri.append(contact_uri)

    
    @property
    def call_id(self) -> CallId:
        return self._call_id

    @call_id.setter
    def call_id(self, call_id: CallId):
        self._call_id = call_id

    @property
    def cseq(self) -> CSeq:
        return self._cseq

    @cseq.setter    
    def cseq(self, cseq: CSeq):
        self._cseq = cseq

    @property
    def max_forwards(self) -> MaxForwards:
        return self._max_forwards

    @max_forwards.setter
    def max_forwards(self, max_forwards: MaxForwards):
        self._max_forwards = max_forwards

    @property
    def user_agent(self) -> UserAgent:
        return self._user_agent

    @user_agent.setter
    def user_agent(self, user_agent: UserAgent):
        self._user_agent = user_agent

    @property
    def server(self) -> Server:
        return self._server

    @server.setter
    def server(self, server: Server):
        self._server = server

    @property
    def expires(self) -> Expires:
        return self._expires

    @expires.setter
    def expires(self, expires: Expires):
        self._expires = expires

    @property
    def allow(self) -> Allow:
        return self._allow

    @allow.setter    
    def allow(self, allow: Allow):
        self._allow = allow

    @property
    def content_type(self) -> ContentType:
        return self._content_type

    @content_type.setter    
    def content_type(self, content_type: ContentType):
        self._content_type = content_type

    @property
    def content_length(self) -> ContentLength:
        return self._content_length

    @content_length.setter
    def content_length(self, content_length: ContentLength):
        self._content_length = content_length



def test() -> Header:
    local_address = 'localhost'
    local_port = 10080
    public_address = '0.0.0.0'
    public_port = 10060
    domain = 'pabx.com'
    port = 5060
    username = 'root-1001'
    display_info = 'root'
    password = 'password'  # noqa: F841
    call_id = '12345678'
    cseq = 1
    max_forwards = 70
    user_agent = 'Pyphone/0.0.1'
    tag = '12345678'
    expires = 3600
    branch = 'z9hG4bK-dcba-12345678'
    method = SipMethod.REGISTER
    allowed_methods = [SipMethod.INVITE, SipMethod.ACK, SipMethod.BYE, SipMethod.CANCEL, SipMethod.REGISTER, SipMethod.OPTIONS]
    content_type = 'application/sdp'
    content_length = 0


    h = Header()
    h.via_uri = Via(address=local_address, port=local_port, params={'branch': branch})
    h.via_uri = Via(address=public_address, port=public_port, params={'branch': branch})
    h.from_uri = From(username=username, address=domain, port=port, display_info=display_info, params={'tag': tag})
    h.to_uri = To(username=username, address=domain)
    h.contact_uri = Contact(username=username, address=local_address)
    h.call_id = CallId(call_id=call_id)
    h.cseq = CSeq(cseq=cseq, method=method)
    h.max_forwards = MaxForwards(max_forwards=max_forwards)
    h.user_agent = UserAgent(user_agent=user_agent)
    h.expires = Expires(expires=expires)
    h.allow = Allow(allowed_methods=allowed_methods)
    h.content_type = ContentType(content_type=content_type)
    h.content_length = ContentLength(content_length=content_length)
    #TODO: auth
    
    cl.print(h)
    cl.print(h.to_bytes())
    
    
    
if __name__ == '__main__':
    pass
    test()