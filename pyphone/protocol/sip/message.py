import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Union, Literal

CRLF = "\r\n"

class SIPMethod(Enum):
    INVITE = "INVITE"
    ACK = "ACK"
    BYE = "BYE"
    CANCEL = "CANCEL"
    REGISTER = "REGISTER"
    OPTIONS = "OPTIONS"


class SIPStatus(Enum):
    TRYING = (100, "Trying")
    RINGING = (180, "Ringing")
    OK = (200, "OK")
    BAD_REQUEST = (400, "Bad Request")
    UNAUTHORIZED = (401, "Unauthorized")
    FORBIDDEN = (403, "Forbidden")
    NOT_FOUND = (404, "Not Found")
    PROXY_AUTH_REQUIRED = (407, "Proxy Authentication Required")
    REQUEST_TIMEOUT = (408, "Request Timeout")
    TEMP_UNAVAILABLE = (480, "Temporarily Unavailable")
    CALL_TR_DOEST_EXIST = (481, "Call/Transaction Does Not Exist")
    BUSY_HERE = (486, "Busy Here")
    REQUEST_TERMINATED = (487, "Request Terminated")
    NOT_ACCEPTABLE = (488, "Not Acceptable Here")
    SERVER_INTERNAL_ERROR = (500, "Server Internal Error")
    SERVICE_UNAVAILABLE = (503, "Service Unavailable")
    SERVER_TIMEOUT = (504, "Server Timeout")
    BUSY_EVERYWHERE = (600, "Busy Everywhere")
    
    def __new__(cls, value, reason):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.reason = reason
        return obj

@dataclass
class Address:
    host: str
    port: int
    params: dict = field(default_factory=dict)

    def __str__(self):
        addr = f"{self.host}:{self.port}"
        if self.params:
            addr += f"{';'.join([f"{k}={v}" for k, v in self.params.items()])}"
        return addr

@dataclass
class Uri:
    address: Address
    username: str = None
    scheme: Literal["sip", "sips"] = "sip"
    bracket: bool = True
    
    def __str__(self):
        uri = str(self.address)
        if self.username:
            uri += f"{self.username}@{uri}"
            uri += f":{self.port}"
        if self.scheme in "sip,sips":
            uri = f"{self.scheme}:{uri}"
            if self.bracket:
                uri = f"<{uri}>"
        return uri



HEADERS = [
    "Via", "From", "To", "Call-ID", "CSeq", "Contact", "Max-Forwards",
    "Content-Length", "Content-Type", "WWW-Authenticate", "Authorization",
    "Proxy-Authenticate", "Proxy-Authorization", "Route", "Record-Route",
    "Expires"
]


@dataclass
class Header:
    name: str
    value: str

    def __str__(self):
        return f"{self.name}: {self.value}{CRLF}"


@dataclass
class Via:
    address: Address
    branch: str = None
    rport: str = None
    received: str = None
    transport: Literal["UDP", "TCP"] = "UDP"
    scheme: Literal["SIP"] = "SIP"
    version: Literal["2.0"] = "2.0"

    def __str__(self):
        if not self.branch:
            self.branch = "z9hG4bK{}".format(hash(self))
        return f"Via: {self.scheme}/{self.version}/{self.transport} {self.address};branch={self.branch}{CRLF}"


@dataclass
class From:
    uri: Uri
    display_name: str = None
    tag: str = None
    params: dict = field(default_factory=dict)

    def __str__(self):
        d_name = f'"{self.display_name}" ' if self.display_name else ''
        tag = f";tag={self.tag}" if self.tag else ''
        params = f"{';'.join([f"{k}={v}" for k, v in self.params.items()])}" if self.params else ''
        return f"From: {d_name}{self.uri}{params}{tag}{CRLF}"


@dataclass
class To:
    uri: Uri
    display_name: str = None
    tag: str = None
    params: dict = field(default_factory=dict)

    def __str__(self):
        d_name = f'"{self.display_name}" ' if self.display_name else ''
        tag = f";tag={self.tag}" if self.tag else ''
        params = f"{';'.join([f"{k}={v}" for k, v in self.params.items()])}" if self.params else ''
        return f"To: {d_name}{self.uri}{params}{tag}{CRLF}"


@dataclass
class CallID:
    id: str

    def __str__(self):
        if not self.id:
            self.id = hash(self)
        return f"Call-ID: {self.id}{CRLF}"


@dataclass
class CSeq:
    id: int
    method: SIPMethod

    def __str__(self):
        return f"CSeq: {self.id} {self.method}{CRLF}"


@dataclass
class Headers:
    via_uri: Union[List[Via], Via]
    from_uri: From
    to_uri: To
    call_id: CallID = field(default_factory=CallID)
    cseq: CSeq = field(default_factory=CSeq)
    extra_headers: List[Header] = field(default_factory=list)
    
    def __str__(self):
        ...

class SIPMessage:
    def __init__(self, headers: Headers, body: str = None):
        self.headers = headers
        self.body = body
        
    @property
    def branch(self):
        return re.search(r'branch=([^;]+)', self.headers.via_uri[-1]).group(1)
    
    @property
    def from_tag(self):
        return re.search(r'tag=([^;]+)', self.headers.from_uri).group(1)
    
    @property
    def to_tag(self):
        return re.search(r'tag=([^;]+)', self.headers.to_uri).group(1)
    
    @property
    def call_id(self):
        return self.headers.call_id
    
    @property
    def cseq_id(self):
        return self.headers.cseq.split()[0]
    
    @property
    def cseq_method(self):
        return self.headers.cseq.split()[1]
    
    @property
    def is_request(self):
        return isinstance(self, SIPRequest)


class SIPRequest(SIPMessage):
    def __init__(self, method: str, uri: str, address: Address, headers: Headers = None, body: str = None):
        super().__init__(headers, body)
        self.method = method
        self.uri = uri
        self.address = address
        
        if not headers:
            headers = Headers()
        if not headers.via_uri:
            uri = Uri(host=self.address.host, port=self.address.port, branch='')
            headers.via_uri.append(f"SIP/2.0/UDP {uri}")
        if not headers.from_uri:
            uri = Uri(host=self.address.host, port=self.address.port, bracket=True)
            headers.from_uri = str(uri)
        if not headers.to_uri:
            uri = Uri(host=self.address.host, port=self.address.port, bracket=True, tag='')
            headers.to_uri = str(uri)
        self.headers
        

    def __str__(self):
        body = f"{CRLF}{self.body}" if self.body else CRLF
        return f"{self.method} {self.uri} SIP/2.0{CRLF}{self.headers}{body}"

    @classmethod
    def request(cls, method: SIPMethod, uri: Uri, headers: Headers, body: str = None):
        return cls(method, uri, headers, body)


class SIPResponse(SIPMessage):
    def __init__(self, status: int, reason: str, headers: Headers = None, body: str = None):
        super().__init__(headers, body)
        self.status = status
        self.reason = reason

    def __str__(self):
        body = f"{CRLF}{self.body}" if self.body else CRLF
        return f"SIP/2.0 {self.status} {self.reason}{CRLF}{self.headers}{body}"
    