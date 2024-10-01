from typing import Dict, List, AnyStr
from dataclasses import dataclass, field
from rich.panel import Panel

from pyphone.core.utils import ProtocolType, SipMethod, SIP_VERSION, EOL, cl

__all__ = [
    'Header',
    'Uri',
    'Attr',
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
class Uri:
    username: AnyStr = field(default='')
    address: AnyStr = field(default='')
    port: int = field(default=0)

    def __str__(self) -> str:
        username = (f"sip:{self.username}@" if self.username else '')
        port = (f":{self.port}" if self.port else '')
        return f"{username}{self.address}{port}"


@dataclass
class Attr:
    attr: Dict[str, str] = None
    def __str__(self) -> str:
        if not self.attr:
            return ''
        return ''.join([f';{k}={v}' for k, v in self.attr.items()])


@dataclass
class Via:
    """
    https://datatracker.ietf.org/doc/html/rfc3261#page-179
    """
    via_uri: Uri
    protocol: ProtocolType = ProtocolType.UDP
    attr: Attr = None
    def __str__(self) -> str:
        attr = self.attr if self.attr else ''
        return f'Via: {SIP_VERSION}/{self.protocol} {self.via_uri}{attr}'


@dataclass
class MaxForwards:
    max_forwards: int = field(default=70)
    def __str__(self) -> str:
        return f'Max-Forwards: {self.max_forwards}'


@dataclass
class From:
    from_uri: Uri
    display_info: AnyStr = None
    caller_id: AnyStr = None
    attr: Attr = None

    def __str__(self) -> str:
        display_info = f'"{self.display_info}" ' if self.display_info else ""
        attr = self.attr if self.attr else ''
        return f'From: {display_info}<{self.from_uri}{attr}>'


@dataclass
class To:
    to_uri: Uri
    attr: Attr = None
    def __str__(self) -> str:
        attr = self.attr if self.attr else ''
        return f'To: <{self.to_uri}{attr}>'


@dataclass
class Contact:
    contact_uri: Uri
    def __str__(self) -> str:
        return f'Contact: <{self.contact_uri}>'


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


#TODO: Refactor and add to export
@dataclass
class Supported:
    supported: List[AnyStr]
    def __str__(self) -> str:
        supported = ', '.join([_ for _ in self.supported])
        return f'Supported: {supported}'


#TODO: Refactor and add to export
@dataclass
class Unsupported:
    """
    https://datatracker.ietf.org/doc/html/rfc3261#page-177
    """
    unsupported: List[AnyStr]
    def __str__(self) -> str:
        unsupported = ', '.join([_ for _ in self.unsupported])
        return f'Unsupported: {unsupported}'


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

#TODO: Refactor and add to export
@dataclass
class Route:
    """
    https://datatracker.ietf.org/doc/html/rfc3261#page-177
    """
    uri: Uri
    def __str__(self) -> str:
        return f'Route: <{self.uri};lr>'

#TODO: Refactor and add to export
@dataclass
class RecordRoute:
    """
    https://datatracker.ietf.org/doc/html/rfc3261#page-175
    """
    uri: Uri
    def __str__(self) -> str:
        return f'Record-Route: <{self.uri}>;lr'

#TODO: Refactor and add to export
class Authentication:
    # TODO: refatore this
    def __init__(self, uri: Uri, realm: str, domain: str, nonce: str, response: str, authorization: str = 'Digest', algorithm: str = 'MD5'):
        self.uri = uri
        self.realm = realm
        self.nonce = nonce
        self.response = response
        self.authorization = authorization

    def __str__(self) -> str:
        return f'Authorization: {self.authorization}'


class Header:
    def __init__(self):
        self._via_uri: List[Via] = []
        self._from_uri: From = None
        self._to_uri: To = None
        self._contact_uri: List[Contact] = []
        self._call_id: CallId = None
        self._cseq: CSeq = None
        self._max_forwards: MaxForwards = None
        self._user_agent: UserAgent = None
        self._expires: Expires = None
        self._allow: Allow = None
        self._supported: Supported = None
        self._unsupported: Unsupported = None
        self._content_type: ContentType = None
        self._content_length: ContentLength = None
        self._route: List[Route] = []
        self._record_route: List[RecordRoute] = []

    def __str__(self) -> str:
        headers = [
            *[_ for _ in self._via_uri],
            self._from_uri,
            self._to_uri,
            *[_ for _ in self._contact_uri],
            self._call_id,
            self._cseq,
            self._max_forwards,
            self._allow,
            self._content_type,
            self._content_length,
            self._user_agent,
            self._expires,
            self._supported,
            self._unsupported,
            *[_ for _ in self._record_route if self._record_route],
            *[_ for _ in self._route if self._route],
        ]
        # TODO: Refactore to not allow multiple headers with the same name
        return f'{EOL}'.join([str(_) for _ in headers if _])

    def __rich__(self) -> Panel:
        return Panel(self.__str__(), title="Headers", highlight=True, expand=False)

    def to_bytes(self) -> bytes:
        return str(self).encode()

    @property
    def via_uri(self) -> List[Via]:
        return self._via_uri

    @via_uri.setter
    def via_uri(self, via_uri: Via):
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
    def supported(self) -> Supported:
        return self._supported

    @supported.setter    
    def supported(self, supported: Supported):
        self._supported = supported

    @property
    def unsupported(self) -> Unsupported:
        return self._unsupported

    @unsupported.setter    
    def unsupported(self, unsupported: Unsupported):
        self._unsupported = unsupported

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

    @property
    def route(self) -> List[Route]:
        return self._route

    @route.setter    
    def route(self, route: Route):
        self._route.append(route)

    @property
    def record_route(self) -> List[RecordRoute]:
        return self._record_route

    @record_route.setter    
    def record_route(self, record_route: RecordRoute):
        self._record_route.append(record_route)



def test() -> Header:
    local_address = 'localhost'
    local_port = 10080
    public_address = '0.0.0.0'
    public_port = 10060
    domain = 'pabx.com'
    port = 5060
    protocol = ProtocolType.UDP
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
    via_uri = Uri(address=local_address, port=local_port)
    via_uri = Uri(address=public_address, port=public_port)
    from_uri = Uri(username=username, address=domain, port=port)
    to_uri = Uri(username=username, address=domain)
    contact_uri = Uri(username=username, address=local_address)
    method = SipMethod.REGISTER
    allowed_methods = [SipMethod.INVITE, SipMethod.ACK, SipMethod.BYE, SipMethod.CANCEL, SipMethod.REGISTER, SipMethod.OPTIONS]
    content_type = 'application/sdp'
    content_length = 0


    h = Header()
    h.via_uri = Via(via_uri=via_uri, protocol=protocol, attr=Attr({'branch': branch}))
    h.from_uri = From(from_uri=from_uri, display_info=display_info, attr=Attr({'tag': tag}))
    h.to_uri = To(to_uri=to_uri, attr=Attr({}))
    h.contact_uri = Contact(contact_uri=contact_uri)
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