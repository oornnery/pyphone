from __future__ import annotations

import threading
import datetime
from typing import List, ByteString
from uuid import uuid4

from utils import Method, StatusCode, EOL

from pyphone.header import Header, HeaderField, Via, From, To, CallId, CSeq
from pyphone.sdp import Sdp


# SIP Message Classes
class SIPMessage:
    _lock = threading.Lock()
    def __init__(self, first_line: str, header: Header, sdp: Sdp = None, scheme: str = 'SIP', version: str = '2.0'):
        self.first_line = first_line
        self.headers = header
        self.sdp = sdp
        self.scheme = scheme
        self.version = version
        self.created_at = datetime.now()
        # TODO: Implementar kwargs
    
    def to_bytes(self) -> ByteString:
        return str(self).encode()
    
    @classmethod
    def from_string(cls, string: str) -> 'SIPMessage':
        first_line, *_ = string.splitlines()
        if first_line.endswith('SIP/2.0'):
            method, uri, _ = first_line.split(' ', 3)
            header = Header.from_string(string)
            sdp = Sdp.from_string(string)
            method = Method[method]
            return Request(method=method, uri=uri, header=header, sdp=sdp)
        _, status_code, reason = first_line.split(' ', 3)
        header = Header.from_string(string)
        sdp = Sdp.from_string(string)
        status_code = StatusCode[status_code]
        return Response(status_code=status_code, reason=reason, header=header, sdp=sdp)
    
    @classmethod
    def from_bytes(cls, bytes: ByteString) -> 'SIPMessage':
        return cls.from_string(cls, bytes.decode())
    
    @staticmethod
    def generate_call_id() -> str:
        return str(uuid4().hex)

    def is_request(self) -> bool:
        return isinstance(self, Request)

    def is_response(self) -> bool:
        return isinstance(self, Response)

    def __str__(self) -> str:
        with self._lock:
            _sdp = f'{EOL}{self.sdp}' if self.sdp else ''
            return f'{self.first_line}{self.headers}{_sdp}'

        

class Request(SIPMessage):
    def __init__(
        self,
        method: Method,
        host: str,
        port: int,
        header: Header,
        sdp: Sdp = None,
        scheme: str = 'SIP', version: str = '2.0'
        ):
        self.method = method
        self.host = host
        self.port = port
        self.header = header
        self.sdp = sdp
        self.scheme = scheme
        self.version = version
        first_line = f'{self.method} {self.host}:{self.port} {self.scheme}/{self.version}{EOL}'
        super().__init__(first_line=first_line, header=header, sdp=sdp)
    
    def __copy__(self):
        return Request(
            method=self.method,
            host=self.host,
            port=self.port,
            header=self.header,
            sdp=self.sdp,
            scheme=self.scheme,
            version=self.version
        )

class Response(SIPMessage):
    DEFAULT_REASONS = {
        100: 'Trying',
        180: 'Ringing',
        181: 'Call Is Being Forwarded',
        182: 'Queued',
        183: 'Session Progress',
        199: 'Early Dialog Terminated',
        200: 'OK',
        202: 'Accepted',
        404: 'Not Found',
        405: 'Method Not Allowed',
        406: 'Not Acceptable',
        407: 'Proxy Authentication Required',
        408: 'Request Timeout',
        410: 'Gone',
        413: 'Request Entity Too Large',
        414: 'Request-URI Too Long',
        415: 'Unsupported Media Type',
        420: 'Bad Extension',
        421: 'Extension Required',
        480: 'Temporarily Unavailable',
        486: 'Busy Here',
        487: 'Request Terminated',
        500: 'Server Internal Error',
        501: 'Not Implemented',
        603: 'Decline',
        604: 'Does Not Exist Anywhere',
        606: 'Not Acceptable'
    }
    
    def __init__(
            self,
            status_code: StatusCode,
            header: Header,
            reason: str = None,
            sdp: Sdp = None,
            scheme: str = 'SIP', version: str = '2.0'
            ):
        
        self.status_code = status_code
        self.reason = reason
        self.header = header
        self.sdp = sdp
        self.scheme = scheme
        self.version = version
        first_line = f'{self.scheme}/{self.version} {self.status_code} {self.reason}{EOL}'
        super().__init__(first_line=first_line, header=self.header, sdp=self.sdp)

    def __copy__(self):
        return Response(
            status_code=self.status_code,
            header=self.header,
            reason=self.reason,
            sdp=self.sdp,
            scheme=self.scheme,
            version=self.version
        )


class MessageFactory:
    @classmethod
    def create_request(
        cls,
        method: Method,
        host: str,
        port: int,
        via_field: Via,
        from_field: From,
        to_field: To,
        call_id_field: CallId,
        cseq_field: CSeq,
        user_agent: str = None,
        allow: str = None,
        allow_events: str = None,
        sdp: Sdp = None,
        extra_headers_fields: List[HeaderField] = None
    ) -> Request:
            
        h = Header()
        # h.add(Via(host=user_agent.transport.local_address, port=user_agent.transport.local_port, branch=branch))
        # h.add(From(address=Address(host=user_agent.host, port=user_agent.port, user=user_agent.username, display_name=user_agent.display_name), tag=local_tag))
        # h.add(To(address=Address(host=user_agent.host, port=user_agent.port, user=destination or user_agent.username, display_name=user_agent.display_name), tag=remote_tag))
        h.add(via_field)
        h.add(from_field)
        h.add(to_field)
        h.add(call_id_field)
        h.add(cseq_field)
        if extra_headers_fields:
            for header in extra_headers_fields:
                h.add(header)
        if 'Max-Forwards' not in h:
            h.add(HeaderField(key='Max-Forwards', value=70))
        if user_agent:
            h.add(HeaderField(key='User-Agent', value=user_agent))
        if allow:
            h.add(HeaderField(key='Allow', value=allow))
        if allow_events:
            h.add(HeaderField(key='Allow-Events', value=allow_events))
        # TODO: Implementar corretamente o SDP
        if sdp:
            h.add(HeaderField(key='Content-Type', value='application/sdp'))
            h.add(HeaderField(key='Content-Length', value=len(sdp)))
        else:
            h.add(HeaderField(key='Content-Length', value=0))
        return Request(method=method, host=host, port=port, header=h, sdp=sdp)

    @classmethod
    def create_response(
            cls,
            original_request: Request,
            status_code: StatusCode,
            reason: str = None,
            sdp: Sdp = None,
            extra_headers_fields: List[HeaderField] = None
        ) -> Response:
        _h = original_request.headers
        h = Header()
        h.add(_h['Via'])
        h.add(_h['From'])
        h.add(_h['To'])
        h.add(_h['Call-ID'])
        h.add(_h['CSeq'])
        if sdp:
            h.add(HeaderField(key='Content-Type', value='application/sdp'))
            h.add(HeaderField(key='Content-Length', value=len(sdp)))
        else:
            h.add(HeaderField(key='Content-Length', value=0))
        if extra_headers_fields:
            for header in extra_headers_fields:
                h.add(header)
        return Response(status_code=status_code, reason=(reason or status_code.reason), header=h, sdp=sdp)

