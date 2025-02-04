import logging
import re
import socket
import uuid
from dataclasses import dataclass, field

from rich.console import Console
from rich.logging import RichHandler


# Set up logging
console = Console()
logging.basicConfig(
    level="NOTSET",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, console=console)]
)

log = logging.getLogger("rich")

# Constants
EOL = r'\r\n'
SIP_SCHEME = 'SIP'
SIP_VERSION = '2.0'
SIP_BRANCH = 'z9hG4bK'
SIP_MAX_FORWARDS = 70
SIP_CONTENT = "application"
SIP_CONTENT_TYPE = "sdp"

COMPACT_HEADERS = {
    "v": "via",
    "f": "from",
    "t": "to",
    "m": "contact",
    "i": "call-id",
    "e": "contact-encoding",
    "l": "content-length",
    "c": "content-type",
    "s": "subject",
    "k": "supported",
}

HEADERS = {
    "via": "Via",
    "from": "From",
    "to": "To",
    "contact": "Contact",
    "call-id": "Call-ID",
    "cseq": "CSeq",
    "max-forwards": "Max-Forwards",
    "content-length": "Content-Length",
    "content-type": "Content-Type",
    "authorization": "Authorization",
    "www-authenticate": "WWW-Authenticate",
    "proxy-authenticate": "Proxy-Authenticate",
}

MULTI_HEADERS = {'via', 'contact', 'record-route', 'route', 'path'}

SDP_HEADERS = {
    "version": "v",
    "origin": "o",
    "session_name": "s",
    "connection_info": "c",
    "bandwidth_info": "b",
    "time_description": "t",
    "media_description": "m",
    "attribute": "a",
    "email_address": "e",
    "phone_number": "p",
    "uri": "u",
    "repeat_time": "r",
    "time_zone": "z",
}

# Regex Patterns
REQUEST_LINE_PATTERN = r'(?P<method>\w+)\s+(?P<uri>.+)\s+(?P<scheme>SIP)/(?P<version>\d+\.\d+)'
STATUS_LINE_PATTERN = r'^(?P<scheme>SIP)/(?P<version>\d+\.\d+)\s+(?P<status_code>\d+)\s+(?P<reason>.+)'
URI_PATTERN = r'(?:\"(?P<display_info>[^\"]+)\"\s+)?<sip:(?:\+)?(?P<user>[^@]+)@(?P<host>[^:;>]+)(?::(?P<port>\d+))?(?:;(?P<params>[^>]+))?>(?:;tag=(?P<tag>[^>\s]+))?'
ADDRESS_PATTERN = r'^(?P<scheme>SIP)/(?P<version>\d+\.\d+)/(?P<protocol>\w+)\s+(?P<address>[\d\.]+):(?P<port>\d+);branch=(?P<branch>[\w\.]+)'
HEADER_PATTERN = r'(?P<name>[\w-]+):\s+(?P<value>.+)'
BODY_PATTERN = r'(?P<name>\w+)\s*=\s*(?P<value>.+)'


# Exceptions
class SipException(Exception): ...

# Utils
def generate_branch(len: int = 8):
    """Generate a random branch ID."""
    return f"{SIP_BRANCH}-{uuid.uuid4().hex[:len]}"

def generate_call_id(host: str = None):
    """Generate a random call ID."""
    host = host or socket.gethostbyname(socket.gethostname())
    return f"{uuid.uuid4().hex}@{host}"

def generate_tag(len: int = 6):
    """Generate a random tag."""
    return f"{uuid.uuid4().hex[:len]}"

def parser_request_line(line: str):
    """Parse a SIP request line."""
    ...

def parser_status_line(line: str):
    """Parse a SIP status line."""
    ...

def parse_uri(uri: str):
    """Parse a SIP URI."""
    ...
    
def parser_address(address: str):
    """Parse a SIP address."""
    ...

def parse_header(header: str):
    """Parser a SIP header normal or compact."""
    ...
    
def parse_body(body: str):
    """Parser a SIP body."""
    ...


# Structs
@dataclass
class RequestLine:
    method: str
    uri: str

    def __str__(self):
        return f"{self.method} {self.uri} SIP/2.0\r\n"


@dataclass
class StatusLine:
    status_code: str
    reason: str

    def __str__(self):
        return f"SIP/2.0 {self.status_code} {self.reason}\r\n"


@dataclass
class Uri:
    user: str
    host: str
    port: int = None
    display_info: str = None
    params: dict = field(default_factory=dict)

    def __str__(self):
        _display_info = f'"{self.display_info}" ' if self.display_info else ''
        _params = ''.join([f";{k}={v}" for k, v in self.params.items()])
        return f"{_display_info}<sip:{self.user}@{self.host}:{self.port}{_params}>\r\n"


@dataclass
class Via:
    address: str
    port: int
    branch: str = field(default_factory=generate_branch)
    transport: str = 'UDP'
    params: dict = field(default_factory=dict)
    
    def __str__(self):
        _params = ''.join([f";{k}={v}" for k, v in self.params.items()])
        return f"Via: SIP/2.0/{self.transport} {self.address}:{self.port};branch={self.branch};{_params}\r\n"


@dataclass
class From:
    uri: Uri
    tag: str = None
    params: dict = field(default_factory=dict)
    
    def __str__(self):
        _tag = f";tag={self.tag}" if self.tag else ''
        _params = ''.join([f";{k}={v}" for k, v in self.params.items()])
        return f"From: {self.uri}{_tag}{_params}\r\n"



@dataclass
class Authorization:
    scheme: str
    params: dict = field(default_factory=dict)

    def __str__(self):
        _params = ''.join([f";{k}={v}" for k, v in self.params.items()])
        return f"{self.scheme} {self.params}\r\n"


@dataclass
class Header:
    via_uri: list[dict] = field(default_factory=list[dict])
    from_uri: dict = field(default_factory=dict)
    to_uri: dict = field(default_factory=dict)
    call_id: dict = field(default_factory=dict)
    cseq: dict = field(default_factory=dict)
    contact: list[dict] = field(default_factory=list[dict])
    content_type: dict = field(default_factory=dict)
    max_forwards: dict = field(default_factory=dict)
    user_agent: dict = field(default_factory=dict)
    content_length: dict = field(default_factory=dict)
    extra_fields: list[dict] = field(default_factory=list[dict])

    def __str__(self):
        h = [
            *[i for i in self.via_uri],
            self.from_uri,
            self.to_uri,
            self.call_id,
            self.cseq,
            *[i for i in self.contact],
            self.content_type,
            self.max_forwards,
            self.user_agent,
            *[i for i in self.extra_fields],
            self.content_length,
        ]
        return "".join([f"{k}: {v}\r\n" for k, v in h if v])

    @classmethod
    def from_string(cls, data: str):
        pattern = (
            r'(?P<name>Via):(?P<value>.*)(:?\r\n)?',
            r'(?P<from_uri>(From):(.*)\r\n)',
            r'(?P<to_uri>(To):(.*)\r\n)',
            r'(?P<cseq>(CSeq):(.*)\r\n)',
            r'(?P<contact_uri>(Contact):(.*)\r\n)',
        )
        headers = {}
        for l in data.splitlines():
            if not l:
                continue
            if ':' in l:
                k, v = l.split(':', 1)
                headers[k] = v.strip()
        return cls(**headers)
    

@dataclass
class Body:
    origin: dict = field(default_factory=dict)
    session_name: dict = field(default_factory=dict)
    connection_info: dict = field(default_factory=dict)
    bandwidth_info: dict = field(default_factory=dict)
    time_description: dict = field(default_factory=dict)
    media_description: dict = field(default_factory=dict)
    attribute: list[dict] = field(default_factory=list[dict])
    version: str = field(default_factory=str)
    
    def __str__(self):
        h = [
            self.origin,
            self.session_name,
            self.connection_info,
            self.bandwidth_info,
            self.time_description,
            self.media_description,
            *[i for i in self.attribute],
        ]
        return "".join([f"{k}: {v}\r\n" for k, v in h if v])
    
    
class Message:
    # Constants
    REQUEST_LINE_PATTERN = (
        r'(?P<method>\S+)\s+'
        r'(?P<uri>[^\s]+)\s+'
        r'(?P<scheme>\S+)'
        r'(?:/(?P<version>\d+(\.\d+)?))?'
    )
    RESPONSE_LINE_PATTERN = (
        r'(?P<scheme>\w+)'
        r'/(?P<version>\d+(\.\d+)?)'
        r'\s+(?P<status_code>\d+)'
        r'\s+(?P<reason>.+)'
    )
    URI_PATTERN = (
        r'(?:.*?<)?(sip:(?P<user>[^@]+)@(?P<host>[^:;>]+)(?::(?P<port>\d+))?(?:;(?P<params>[^>]+))?)(?:>)?' # URIs
    )
    PARAMS_PATTERN = r'(?:.*?)?(?P<name>\w+)=?(?P<value>[^;]*)'
    ADDRESS_PATTERN = (
        r'(?:\"(?P<display_info>.*)\"\s+)?'       # Display Info
        r'(?P<uri>(?:<sip:)?[^@].*[^:;>]+(?:>))?' # URI
        r'(?:;tag=(?P<tag>[^;\s]+))?'             # Tag
        r'(?:;(?P<params>.*))?'                   # Params
    )
    VIA_PATTERN = (
        r'(?P<protocol>\S+)/(?P<version>\d+\.\d+)/(?P<transport>\S+)\s+'
        r'(?P<address>[\d\.]+):(?P<port>\d+);branch=(?P<branch>[\w\.]+)'
        r'(?:;(?P<params>.*))?'
    )
    AUTHORIZATION_PATTERN = (
        
    )
    HEADER_PATTERN = r'(?P<name>[A-Z][a-z]+):(?:\s)?+(?P<value>.+)'
    BODY_PATTERN = r'(?P<name>[a-z])=(?:\s)?+(?P<value>.+)'
    
    def __init__(self, message: str = None):
        self.message = message
        self.headers = {}
        self.body = {}
    
    def _parser_request_line(self, value: str):
        return re.compile(self.REQUEST_LINE_PATTERN).match(value).groupdict()
    
    def _parser_status_line(self, value: str):
        return re.compile(self.STATUS_LINE_PATTERN).match(value).groupdict()
    
    def _parser_params(self, value: str):
        return [{k: v} for k, v in re.compile(self.PARAMS_PATTERN).findall(value)]
    
    def _parser_uri(self, value: str):
        _ = re.compile(self.URI_PATTERN).match(value).groupdict()
        _['params'] = self._parser_params(_['params'])
        return _

    def _parser_via(self, value: str):
        _ = re.compile(self.VIA_PATTERN).match(value).groupdict()
        _['params'] = self._parser_params(_['params'])
        return _
    
    def _parser_address(self, value: str):
        _ = re.compile(self.ADDRESS_PATTERN).match(value).groupdict()
        _['uri'] = {'uri': _['uri'], **self._parser_uri(_['uri'])}
        _['params'] = self._parser_params(_['params'])
        return _

    def _parser_from(self, value: str):
        return {'field': f'From: {value}', **self._parser_address(value)}
    
    def _parser_www_authenticate(self, value: str):
        _ = re.compile(self.AUTHORIZATION_PATTERN).match(value).groupdict()
        return _
    
    def _parser_header(self, value: str):
        k, v = value.split(':', 1)
        match k.lower():
            case "via":
                return {k: self._parser_via(v)}
            case "from":
                return {k: self._parser_address(v)}
            case "to":
                return {k: self._parser_address(v)}
            case "contact":
                return {k: self._parser_address(v)}
            case "www-authenticate":
                return {k: self._parser_www_authenticate(v)}
            case _:
                return {k: v}
    
    def _parse_body(self, value: str):
        return value.split('=', 1)
    
    def from_string(self, data: str):
        first_line = ''
        header = {}
        body = re.findall(self.BODY_PATTERN, data)
        
        lines = data.splitlines()
        first_line = lines[0]
        log.info(first_line)
        for line in lines[1:]:
            if not line:
                continue
            h = re.compile(self.HEADER_PATTERN).match(line)
            if header:
                log.info(header.groupdict())
                
        
        
        
        print(header)
        print(body)
# Utility functions

if __name__ == "__main__":
    text = '''INVITE sip:43820060@siptrunkbr.net2phone.com SIP/2.0\r\n
Via: SIP/2.0/UDP 189.40.89.131:20268;rport;branch=z9hG4bKPj2b6100d935344ce7a278c15d8b876816\r\n
Max-Forwards: 70\r\n
From: "SIPTxTest" <sip:4312639212@siptrunkbr.net2phone.com>;tag=6ee7c8e4e6b04967b61843a77df71868\r\n
To: <sip:43820060@siptrunkbr.net2phone.com>\r\n
Contact: <sip:4312639212@189.40.89.131:20268;ob>\r\n
Call-ID: 02dc983505ed4e57b3394350c5a97878\r\n
CSeq: 17118 INVITE\r\n
Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n
Supported: replaces, 100rel, timer, norefersub\r\n
Session-Expires: 1800\r\n
Min-SE: 90\r\n
User-Agent: MicroSIP/3.21.5\r\n
Content-Type: application/sdp\r\n
Content-Length:   342\r\n
\r\n
v=0\r\n
o=- 3940497526 3940497526 IN IP4 189.40.89.131\r\n
s=pjmedia\r\n
b=AS:84\r\n
t=0 0\r\n
a=X-nat:0\r\n
m=audio 4006 RTP/AVP 0 8 101\r\n
c=IN IP4 189.40.89.131\r\n
b=TIAS:64000\r\n
a=rtcp:4007 IN IP4 189.40.89.131\r\n
a=sendrecv\r\n
a=rtpmap:0 PCMU/8000\r\n
a=rtpmap:8 PCMA/8000\r\n
a=rtpmap:101 telephone-event/8000\r\n
a=fmtp:101 0-16\r\n
a=ssrc:978471171 cname:63557ac616b56d19\r\n
'''
    
    m = Message()
    print(m.from_string(text))
    
    