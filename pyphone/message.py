import re
from typing import Union, List


from pyphone.header import (
    Header,
    HeaderFactory,
    Address,
    Uri,
    Via,
    From,
    To,
    Contact,
    CSeq,
    CallId,
    MaxForword
)
from pyphone.utils import (
    SIPMethod,
    SIPStatusCode
)
from pyphone.sdp import (
    Body,
    BodyFactory
)

from pyphone.user_agent import (
    UserAgentConfig
)


class Message:
    
    def __init__(
        self,
        firt_line: Union[SIPMethod, SIPStatusCode],
        headers: HeaderFactory,
        body: BodyFactory = None

    ):
        self.first_line = firt_line
        self.headers = headers
        self.body = body
    
    def is_request(self) -> bool:
        return isinstance(self.first_line, SIPMethod)
    
    def is_response(self) -> bool:
        return isinstance(self.first_line, SIPStatusCode)
    
    def __str__(self):
        return f"{self.first_line} {self.uri} SIP/2.0\r\n{str(self.headers)}\r\n{self.body}"
    
    @classmethod
    def parser(cls, message: str) -> 'Message':
        _lines = message.split('\r\n')
        _headers = HeaderFactory().from_string(message)
        _sdp = BodyFactory().from_string(message)
        if message.endswith('SIP/2.0'):
            _match = cls._SYNTAX_REQUEST.match(_lines[0])
            _uri = Uri().parser(_match.group('uri'))
            return Message(
                firt_line=_match.group('method'),
                uri=_uri,
                headers=_headers,
                sdp=_sdp
            )
        elif message.startswith('SIP/2.0'):
            _match = cls._SYNTAX_RESPONSE.match(_lines[0])
            return Message(
                firt_line=_match.group('status_code'),
                headers=_headers,
                sdp=_sdp
            )


class SIPRequest(Message):
    _SYNTAX = re.compile('^(?P<method>[A-Z]+)[\ \t]+(?P<uri>[^ \t]+)[\ \t]+SIP/2.0$')
    
    def __init__(
        self,
        method: SIPMethod,
        uri: Uri,
        headers: HeaderFactory,
        body: BodyFactory
    ):
        super().__init__(
            firt_line=method,
            headers=headers,
            body=body
        )

    @classmethod
    def parser(cls, message) -> 'SIPRequest':
        _lines = message.split('\r\n')
        _headers = HeaderFactory().from_string(message)
        _sdp = BodyFactory().from_string(message)
        _match = cls._SYNTAX.match(_lines[0])
        _uri = Uri().parser(_match.group('uri'))
        return SIPRequest(
            method=_match.group('method'),
            uri=_uri,
            headers=_headers,
            sdp=_sdp
        )

class SIPResponse(Message):
    _SYNTAX = re.compile('^SIP/2.0[\ \t]+(?P<status_code>[\d]+)[\ \t]+(?P<reason_phrase>[^\r\n]+)$')
    
    def __init__(
        self,
        status_code: SIPStatusCode,
        headers: HeaderFactory,
        body: BodyFactory
    ):
        super().__init__(
            firt_line=status_code,
            headers=headers,
            body=body
        )

    @classmethod
    def parser(cls, message) -> 'SIPResponse':
        _lines = message.split('\r\n')
        _headers = HeaderFactory().from_string(message)
        _sdp = BodyFactory().from_string(message)
        _match = cls._SYNTAX.match(_lines[0])
        return SIPResponse(
            status_code=_match.group('status_code'),
            headers=_headers,
            sdp=_sdp
        )


class MessageFactory:
    
    @staticmethod
    def from_string(message: str) -> Message:
        if message.startswith('SIP/2.0'):
            return SIPResponse.parser(message)
        else:
            return SIPRequest.parser(message)
    
    #TODO: Use config files to define the default headers
    @staticmethod
    def request(method: SIPMethod, to_uri: Uri, ua_cfg: UserAgentConfig, extra_header: List[Header], extra_body: List[Body]) -> SIPRequest:
        _header = HeaderFactory(
            via=Via(
                ua_cfg.server,
                ua_cfg.port,
            ),
            from_=From(
                address=Address(uri=Uri(ua_cfg.username, ua_cfg.server), display_name=ua_cfg.display_name)
            ),
            to=To(
                address=Address(uri=to_uri)
            ),
            contact=Contact(
                Address(uri=Uri(ua_cfg.username, ua_cfg.server), display_name=ua_cfg.display_name)
            ),
            cseq=CSeq(
                method=method,
                sequence=1
            ),
            call_id=CallId(),
            extras_header=[MaxForword(), *extra_header],
            )
        
        return SIPRequest(
            method=method,
            uri=Uri(ua_cfg.username, ua_cfg.server),
            headers=_header,
            body=None
        )
    @staticmethod
    def response(status_code: SIPStatusCode, headers: HeaderFactory, body: BodyFactory) -> SIPResponse:
        return SIPResponse(
            status_code=status_code,
            headers=headers,
            body=body
        )