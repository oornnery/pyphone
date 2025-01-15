import logging
import re

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
    HEADER_PATTERN = r'(?P<name>\w+):(?:\s)?+(?P<value>.+)'
    BODY_PATTERN = r'(?P<name>\w?)=(?:\s)?+(?P<value>.+)'
    
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
        header = re.findall(self.HEADER_PATTERN, data)
        body = re.findall(self.BODY_PATTERN, data)
        
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
    
    