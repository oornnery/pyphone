from dataclasses import dataclass
from typing import List
from enum import Enum
import re

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
class Uri:
    username: str
    host: str
    port: int = 5060
    branch: str = None
    tag: str = None
    display_name: str = None
    scheme: str = "sip"
    bracket: bool = False
    
    def __str__(self):
        uri = ''
        if self.username:
            uri += f"{self.username}@{uri}"
        if self.host:
            uri += f"{self.host}"
        if self.port:
            uri += f":{self.port}"
        if self.scheme in "sip,sips":
            uri = f"{self.scheme}:{uri}"
            if self.branch:
                uri += f";branch={self.branch}"
            if self.bracket:
                uri = f"<{uri}>"
                if self.tag:
                    uri += f";tag={self.tag}"
        if self.display_name:
            uri = f'"{self.display_name}" {uri}'
        return uri

    @classmethod
    def parse(cls, raw: str):
        uri_pattern = re.compile(r'(?:"([^"]+)"\s+)?<?(sip|sips):([^@]+)@([^:]+)(?::(\d+))?(?:;branch=([^;]+))?(?:;tag=([^;]+))?>?')
        match = uri_pattern.match(raw)
        if not match:
            raise ValueError(f"Invalid URI: {raw}")
        display_name, scheme, username, host, port, branch, tag = match.groups()
        return cls(username, host, int(port), branch, tag, display_name, scheme, "<" in raw)
    
@dataclass
class SIPHeader:
    name: str
    value: str

    def __str__(self):
        return f"{self.name}: {self.value}{CRLF}"

    def items(self):
        return self.name, self.value
    
    @classmethod
    def parse(cls, raw: str):
        name, value = re.split(r':\s*', raw, 1)
        return cls(name, value.strip())

class ViaHeader(SIPHeader):
    def __init__(self, value: str):
        super().__init__("Via", value)

class FromHeader(SIPHeader):
    def __init__(self, value: str):
        super().__init__("From", value)

class ToHeader(SIPHeader):
    def __init__(self, value: str):
        super().__init__("To", value)

class CallIDHeader(SIPHeader):
    def __init__(self, value: str):
        super().__init__("Call-ID", value)

class CSeqHeader(SIPHeader):
    def __init__(self, value: str):
        super().__init__("CSeq", value)

class ContactHeader(SIPHeader):
    def __init__(self, value: str):
        super().__init__("Contact", value)

class MaxForwardsHeader(SIPHeader):
    def __init__(self, value: str):
        super().__init__("Max-Forwards", value)

class ContentLengthHeader(SIPHeader):
    def __init__(self, value: str):
        super().__init__("Content-Length", value)

class ContentTypeHeader(SIPHeader):
    def __init__(self, value: str):
        super().__init__("Content-Type", value)
        
class WWWAuthenticateHeader(SIPHeader):
    def __init__(self, value: str):
        super().__init__("WWW-Authenticate", value)

class AuthorizationHeader(SIPHeader):
    def __init__(self, value: str):
        super().__init__("Authorization", value)

class ProxyAuthenticateHeader(SIPHeader):
    def __init__(self, value: str):
        super().__init__("Proxy-Authenticate", value)

class ProxyAuthorizationHeader(SIPHeader):
    def __init__(self, value: str):
        super().__init__("Proxy-Authorization", value)

class RouteHeader(SIPHeader):
    def __init__(self, value: str):
        super().__init__("Route", value)

class RecordRouteHeader(SIPHeader):
    def __init__(self, value: str):
        super().__init__("Record-Route", value)

class ExpiresHeader(SIPHeader):
    def __init__(self, value: str):
        super().__init__("Expires", value)


class Message:
    def __init__(self, headers: dict, body: str):
        self.headers = headers
        self.body = body
    
    @property
    def uri(self):
        return self.headers["Via"].uri
    
    @property
    def branch(self):
        return self.headers["Via"].branch
    
    @property
    def from_tag(self):
        return self.headers["From"].tag
    
    @property
    def to_tag(self):
        return self.headers["To"].tag
    
    @property
    def call_id(self):
        return self.headers["Call-ID"]
    
    @property
    def cseq(self):
        return self.headers["CSeq"]
    
    @property
    def is_request(self):
        return isinstance(self, SIPRequest)
    
    def __str__(self):
        return f"{self.__class__.__name__}({self.call_id}, {self.branch})"


class SIPRequest(Message):
    def __init__(self, method: SIPMethod, uri: str, headers: List[SIPHeader] = None, body: str = None):
        super().__init__(headers, body)
        method = method
        uri = uri

    def __str__(self):
        headers = ''.join([f"{k}: {v}{CRLF}" for k, v in (x for x in self.headers).items()])
        body = f"{CRLF}{self.body}" if self.body else CRLF
        return f"{self.method} {self.uri} SIP/2.0{CRLF}{headers}{body}"

class SIPResponse(Message):
    def __init__(self, status: SIPStatus, headers: List[SIPHeader] = None, body: str = None):
        super().__init__(headers, body)
        status = status

    def __str__(self):
        headers = ''.join([f"{k}: {v}{CRLF}" for k, v in self.headers.items()])
        body = f"{CRLF}{self.body}" if self.body else CRLF
        return f"SIP/2.0 {self.status} {self.status.reason}{CRLF}{headers}{body}"