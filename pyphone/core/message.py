from typing import List, Optional, Dict
from enum import Enum
from dataclasses import field, dataclass


class SIPMethod(Enum):
    INVITE = "INVITE"
    ACK = "ACK"
    BYE = "BYE"
    CANCEL = "CANCEL"
    REGISTER = "REGISTER"
    OPTIONS = "OPTIONS"
    SUBSCRIBE = "SUBSCRIBE"
    NOTIFY = "NOTIFY"
    UPDATE = "UPDATE"

class SIPStatusCode(Enum):
    TRYING = (100, "Trying")
    RINGING = 180
    CALL_IS_BEING_FORWARDED = 181
    QUEUED = 182
    SESSION_PROGRESS = 183
    EARLY_DIALOG_TERMINATED = 199

    OK = 200
    ACCEPTED = 202
    NO_NOTIFICATION = 204

    MULTIPLE_CHOICES = 300
    MOVED_PERMANENTLY = 301
    MOVED_TEMPORARILY = 302
    USE_PROXY = 305
    ALTERNATIVE_SERVICE = 380

    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    PAYMENT_REQUIRED = 402
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    NOT_ACCEPTABLE = 406
    PROXY_AUTHENTICATION_REQUIRED = 407
    REQUEST_TIMEOUT = 408
    CONFLICT = 409
    GONE = 410
    LENGTH_REQUIRED = 411
    CONDITIONAL_REQUEST_FAILED = 412
    REQUEST_ENTITY_TOO_LARGE = 413
    REQUEST_URI_TOO_LONG = 414
    UNSUPPORTED_MEDIA_TYPE = 415
    UNSUPPORTED_URI_SCHEME = 416
    UNKNOWN_RESOURCE_PRIORITY = 417
    BAD_EXTENSION = 420
    EXTENSION_REQUIRED = 421
    SESSION_INTERVAL_TOO_SMALL = 422
    INTERVAL_TOO_BRIEF = 423
    BAD_LOCATION_INFORMATION = 424
    USE_IDENTITY_HEADER = 428
    PROVIDE_REFERRER_IDENTITY = 429
    FLOW_FAILED = 430
    ANONYMITY_DISALLOWED = 433
    BAD_IDENTITY_INFO = 436
    UNSUPPORTED_CERTIFICATE = 437
    INVALID_IDENTITY_HEADER = 438
    FIRST_HOP_LACKS_OUTBOUND_SUPPORT = 439
    MAX_BREADTH_EXCEEDED = 440
    BAD_INFO_PACKAGE = 469
    CONSENT_NEEDED = 470
    TEMPORARILY_UNAVAILABLE = 480
    CALL_TRANSACTION_DOES_NOT_EXIST = 481
    LOOP_DETECTED = 482
    TOO_MANY_HOPS = 483
    ADDRESS_INCOMPLETE = 484
    AMBIGUOUS = 485
    BUSY_HERE = 486
    REQUEST_TERMINATED = 487
    NOT_ACCEPTABLE_HERE = 488
    BAD_EVENT = 491
    REQUEST_PENDING = 493
    UNDECIPHERABLE = 494
    SECURITY_AGREEMENT_REQUIRED = 494

    SERVER_INTERNAL_ERROR = 500
    NOT_IMPLEMENTED = 501
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    SERVER_TIMEOUT = 504
    VERSION_NOT_SUPPORTED = 505
    MESSAGE_TOO_LARGE = 513
    PUSH_NOTIFICATION_SERVICE_NOT_SUPPORTED = 555
    PRECONDITION_FAILURE = 580
    
    BUSY_EVERYWHERE = 600
    DECLINE = 603
    DOES_NOT_EXIST_ANYWHERE = 604
    UNWANTED = 607


@dataclass
class Via:
    address: str
    port: str
    transport: Optional[str] = field(default='UDP')
    #TODO: add tags for via (branch, rport, received, ...)
    def __str__(self) -> str:
        return f'Via: SIP/2.0/{self.transport} {self.address}:{self.port}\r\n'

    @staticmethod
    def parser(message: str) -> 'Via':
        address = ''
        port = ''
        transport = ''
        return Via(address=address, port=port, transport=transport)


@dataclass
class From:
    user: str
    address: str
    port: str
    display_info: Optional[str] = None
    tags: Optional[Dict[str, str]] = None

    def __str__(self) -> str:
        r = 'From: '
        if self.display_info:
            r += f'"{self.display_info}" '
        r += f'<{self.user}@{self.address}:{self.port}>'
        if self.tags:
            r += ''.join([f'{k}={v}' for k, v in self.tags.items()])
        r += '\r\n'
        return r

    @staticmethod
    def parser(message: str) -> 'From':
        address = ''
        port = ''
        transport = ''
        return From(address=address, port=port, transport=transport)


@dataclass
class To:
    user: str
    address: str

    def __str__(self) -> str:
        return f'To: <{self.user}@{self.address}>\r\n'

    @staticmethod
    def parser(message: str) -> 'To':
        address = ''
        user = ''
        return To(user=user, address=address)


@dataclass
class Contact:
    user: str
    address: str

    def __str__(self) -> str:
        return f'Contact: <{self.user}@{self.address}>\r\n'

    @staticmethod
    def parser(message: str) -> 'Contact':
        address = ''
        user=''
        return Contact(address=address, user=user)


@dataclass
class CallId:
    call_id: str

    def __str__(self) -> str:
        return f'Call-ID: {self.call_id}\r\n'

    @staticmethod
    def parser(message: str) -> 'CallId':
        call_id = ''
        return CallId(call_id=call_id)


@dataclass
class Suported:
    supported: str

    def __str__(self) -> str:
        return f'Supported: {self.supported}\r\n'

    @staticmethod
    def parser(message: str) -> 'Suported':
        supported = ''
        return Suported(supported=supported)


@dataclass
class SessionExpires:
    session_expires: str

    def __str__(self) -> str:
        return f'Session-Expires: {self.session_expires}\r\n'

    @staticmethod
    def parser(message: str) -> 'SessionExpires':
        session_expires = ''
        return SessionExpires(session_expires=session_expires)


@dataclass
class CSeq:
    cseq: str
    method: SIPMethod

    def __str__(self) -> str:
        return f'CSeq: {self.cseq} {self.method}\r\n'

    @staticmethod
    def parser(message: str) -> 'CSeq':
        cseq = ''
        method = ''
        return CSeq(cseq=cseq, method=method)


@dataclass
class MaxForwards:
    max_forwards: str

    def __str__(self) -> str:
        return f'Max-Forwards: {self.max_forwards}\r\n'

    @staticmethod
    def parser(message: str) -> 'MaxForwards':
        max_forwards = ''
        return MaxForwards(max_forwards=max_forwards)


@dataclass
class Allow:
    allowed_methods: List[SIPMethod]

    def __str__(self) -> str:
        allow = ', '.join([a.value for a in self.allowed_methods])
        return f'Allow: {allow}\r\n'

    @staticmethod
    def parser(message: str) -> 'Allow':
        allowed_methods = ''
        return Allow(allowed_methods=allowed_methods)


@dataclass
class StatusLine:
    status_code: SIPStatusCode
    # TODO: Refactor reason phrase
    reason_phrase: SIPStatusCode = None

    def __str__(self) -> str:
        return f"SIP/2.0 {self.status_code.value} {self.status_code.name.capitalize()}\r\n"

    @staticmethod
    def parser(message: str) -> 'StatusLine':
        status_code = ''
        reason_phrase = ''
        return StatusLine(status_code=status_code, reason_phrase=reason_phrase)


@dataclass
class ContentType:
    content_type: str

    def __str__(self) -> str:
        return f"Content-Type: {self.content_type}\r\n"

    @staticmethod
    def parser(message: str) -> 'ContentType':
        content_type = ''
        return ContentType(content_type=content_type)


@dataclass
class ContentLength:
    content_length: str

    def __str__(self) -> str:
        return f"Content-Length: {self.content_length}\r\n"

    @staticmethod
    def parser(message: str) -> 'ContentLength':
        content_length = ''
        return ContentLength(content_length=content_length)


@dataclass
class RecordRoute:
    record_route: str

    def __str__(self) -> str:
        return f"Record-Route: {self.record_route}\r\n"

    @staticmethod
    def parser(message: str) -> 'RecordRoute':
        record_route = ''
        return RecordRoute(record_route=record_route)


@dataclass
class Route:
    route: str

    def __str__(self) -> str:
        return f"Route: {self.route}\r\n"

    @staticmethod
    def parser(message: str) -> 'Route':
        route = ''
        return Route(route=route)


@dataclass
class UserAgent:
    user_agent: str

    def __str__(self) -> str:
        return f"User-Agent: {self.user_agent}\r\n"

    @staticmethod
    def parser(message: str) -> 'UserAgent':
        user_agent = ''
        return UserAgent(user_agent=user_agent)


@dataclass
class Supported:
    supported: str

    def __str__(self) -> str:
        return f"Supported: {self.supported}\r\n"

    @staticmethod
    def parser(message: str) -> 'Supported':
        supported = ''
        return Supported(supported=supported)


@dataclass
class ProxyAuthenticate:
    proxy_authenticate: str

    def __str__(self) -> str:
        return f"Proxy-Authenticate: {self.proxy_authenticate}\r\n"

    @staticmethod
    def parser(message: str) -> 'ProxyAuthenticate':
        proxy_authenticate = ''
        return ProxyAuthenticate(proxy_authenticate=proxy_authenticate)


@dataclass
class Authorization:
    authorization: str

    def __str__(self) -> str:
        return f"Authorization: {self.authorization}\r\n"

    @staticmethod
    def parser(message: str) -> 'Authorization':
        authorization = ''
        return Authorization(authorization=authorization)


@dataclass
class Uri:
    user: str
    address: str
    def __str__(self) -> str:
        return f"sip:{self.user}@{self.address}"

    @staticmethod
    def parser(message: str) -> 'Uri':
        user = ''
        address = ''
        return Uri(user=user, address=address)


@dataclass
class RequestLine:
    method: SIPMethod
    request_uri: Uri

    def __str__(self) -> str:
        #TODO: Refactor to include attr
        return f"{self.method.value} {self.request_uri} SIP/2.0\r\n"

    @staticmethod
    def parser(message: str) -> 'RequestLine':
        method = ''
        request_uri = ''
        return RequestLine(method=method, request_uri=request_uri)


@dataclass
class Server:
    server: str

    def __str__(self) -> str:
        return f'Server: {self.server}\r\n'

    @staticmethod
    def parser(message: str) -> 'Server':
        return Server(server=message)


@dataclass
class SIPHeader:
    via: List[Via]
    from_: From
    to: To
    call_id: CallId
    cseq: CSeq
    contact: Optional[Contact] = None
    user_agent: Optional[UserAgent] = None
    server: Optional[Server] = None
    content_type: Optional[ContentType] = None
    content_length: Optional[ContentLength] = None
    max_forwards: Optional[MaxForwards] = None
    session_expires: Optional[SessionExpires] = None
    supported: Optional[Suported] = None
    proxy_authenticate: Optional[ProxyAuthenticate] = None
    authorization: Optional[Authorization] = None
    record_route: List[RecordRoute] = None
    route: List[Route] = None
    allow: Optional[Allow] = None

    def __str__(self) -> str:
        headers = [str(via) for via in self.via]
        headers.extend([str(self.from_), str(self.to), str(self.call_id), str(self.cseq)])
        
        if self.contact:
            headers.append(str(self.contact))
        if self.user_agent:
            headers.append(str(self.user_agent))
        if self.content_type:
            headers.append(str(self.content_type))
        if self.content_length:
            headers.append(str(self.content_length))
        if self.max_forwards:
            headers.append(str(self.max_forwards))
        if self.proxy_authenticate:
            headers.append(str(self.proxy_authenticate))
        if self.authorization:
            headers.append(str(self.authorization))
        if self.session_expires:
            headers.append(str(self.session_expires))
        if self.supported:
            headers.append(str(self.supported))
        if self.server:
            headers.append(str(self.server))  # Converte o objeto Server em string.
        if self.allow:
            headers.append(str(self.allow))
        if self.record_route:
            headers.extend([str(record_route) for record_route in self.record_route])
        if self.route:
            headers.extend([str(route) for route in self.route])

        return "".join(headers)


@dataclass
class SDPVersion:
    version: str

    def __str__(self) -> str:
        return f'v={self.version}\r\n'

    @staticmethod
    def parser(message: str) -> 'SDPVersion':
        version = ''
        return SDPVersion(version=version)


@dataclass
class SDPOrigin:
    origin: str

    def __str__(self) -> str:
        return f"o={self.origin}\r\n"

    @staticmethod
    def parser(message: str) -> 'SDPOrigin':
        origin = ''
        return SDPOrigin(origin=origin)


@dataclass
class SDPSession:
    session: str

    def __str__(self) -> str:
        return f"s={self.session}\r\n"

    @staticmethod
    def parser(message: str) -> 'SDPSession':
        session = ''
        return SDPSession(session=session)


@dataclass
class SDPContact:
    contact: str

    def __str__(self) -> str:
        return f"c={self.contact}\r\n"

    @staticmethod
    def parser(message: str) -> 'SDPContact':
        contact = ''
        return SDPContact(contact=contact)


@dataclass
class SDPContent:
    content: str

    def __str__(self) -> str:
        return f"t={self.content}\r\n"

    @staticmethod
    def parser(message: str) -> 'SDPContent':
        content = ''
        return SDPContent(content=content)


@dataclass
class SDPTimer:
    timer: str

    def __str__(self) -> str:
        return f"m={self.timer}\r\n"

    @staticmethod
    def parser(message: str) -> 'SDPTimer':
        timer = ''
        return SDPTimer(timer=timer)


@dataclass
class SDPAttribute:
    """
    Example: a=rtpmap:8 PCMA/8000 a=ptime:20 a=rtpmap:0 PCMU/8000 a=ptime:20
    """
    attr: str

    def __str__(self) -> str:
        return f"a={self.attr}\r\n"

    @staticmethod
    def parser(message: str) -> 'SDPAttribute':
        attr = ''
        return SDPAttribute(attr=attr)


@dataclass
class SIPBody:
    version: SDPVersion = None # v=0
    origin: Optional[SDPOrigin] = None # o=huawei 39 1 IN IP4 177.22.82.3
    session: Optional[SDPSession] = None # s=-
    contact: Optional[SDPContact] = None # c=IN IP4 177.22.82.3
    content: Optional[SDPContent] = None # t=0 0
    timer: Optional[SDPTimer] = None # m=audio 53534 RTP/AVP 8 0 18 9
    attr: List[SDPAttribute] = None # 

    def __str__(self) -> str:
        body = [str(self.version)]
        if self.origin:
            body.append(str(self.origin))  # Converte para string
        if self.session:
            body.append(str(self.session))  # Converte para string
        if self.contact:
            body.append(str(self.contact))  # Converte para string
        if self.content:
            body.append(str(self.content))  # Converte para string
        if self.timer:
            body.append(str(self.timer))  # Converte para string
        if self.attr:
            body.extend([str(attr) for attr in self.attr])  # Converte cada atributo para string

        return "".join(body)


class SIPRequest:
    def __init__(self, request_line: RequestLine, header: SIPHeader, body: Optional[SIPBody] = None) -> None:
        self.request_line = request_line
        self.header = header
        self.body = body
        
        if body:
            self.header.content_length = ContentLength(str(self.calculate_content_length()))
            print(self.header.content_length)

    def calculate_content_length(self) -> int:
        if self.body:
            return len(str(self.body))
        return 0

    def __str__(self) -> str:
        return f"{str(self.request_line)}{str(self.header)}\r\n{str(self.body)}"


class SIPResponse:
    def __init__(self, status_line: StatusLine, header: SIPHeader) -> None:
        self.status_line = status_line
        self.header = header

    @classmethod
    def parser(cls, message: str) -> 'SIPResponse':
        status_line = message
        header = SIPHeader()
        return cls(header=header, status_line=status_line)

    def __str__(self) -> str:
        return f"{self.status_line}{self.header}"


if __name__ == '__main__':
    from rich import print as p

    def test():
        header = SIPHeader(
            via=[Via(address='89.0.142.86', port='5060', transport='UDP')],
            from_=From(user='XXXXXX', address='89.0.142.86', port='5060'),
            to=To(user='CCCCCCCC', address='89.0.142.86', port='5060'),
            call_id=CallId('1234567890'),
            cseq=CSeq(1, 'REGISTER'),
            server=Server('89.0.142.86'),
        )
        p(header)
        body = SIPBody(
            version=SDPVersion(version='0'),
        )
        p(body)
        req = SIPRequest(
            request_line=RequestLine(
                method=SIPMethod.REGISTER,
                request_uri=Uri(user='CCCCCCCC', address='89.0.142.86')
                ),
            header=header,
            body=body
        )
        p(req)
        
        res = SIPResponse(
            status_line=StatusLine(status_code=SIPStatusCode.OK),
            header=header
        )
        p(res)

    test()