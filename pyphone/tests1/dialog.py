from typing import Callable, List, Union
from uuid import uuid4
from dataclasses import dataclass
from rich.panel import Panel
from pyphone.core.utils import (
    SipMethod,
    SipStatusCode,
    SIP_VERSION,
    SIP_METHODS,
    SIP_MAX_FORWARDS,
    SIP_CONTENT_TYPE,
    SIP_SUPPORTED,
    SIP_UNSUPPORTED,
    EOL,
    cl,
    parser_uri_to_str
)
from pyphone.core.transport import Transport
from pyphone.core.user import User
from pyphone.core.header import Header
from pyphone.core.payload import Body

@dataclass
class SipRequest:
    method: SipMethod
    uri: str
    header: Header
    body: Body
    def __str__(self) -> str:
        return f"{self.method} {self.uri} SIP/2.0{EOL}{self.header}{EOL}{EOL}{self.body}"

    def __rich__(self):
        return Panel(self.__str__(), title="SIP Request", highlight=True, expand=False)

    def to_bytes(self) -> bytes:
        return str(self).encode()

@dataclass
class SipResponse:
    status_code: SipStatusCode
    uri: str
    header: Header
    def __str__(self) -> str:
        return f"{SIP_VERSION} {self.status_code}{EOL}{self.header}"

    def __rich__(self):
        return Panel(self.__str__(), title="SIP Response", highlight=True, expand=False)

    def to_bytes(self) -> bytes:
        return str(self).encode()



class Dialog:
    def __init__(self):
        self.transport: Transport = Transport()
        self.user: User = User()
        self._cseq = -1
        self._call_id = None
        self._branch = None
        self._tag = None
        self._via_uri = None
        self._from_uri = None

        self.stack: List[Union[SipRequest, SipResponse]] = []


    # @property
    # def cseq(self):
    #     self._cseq += 1
    #     return self._cseq
    
    # @property
    # def branch(self):
    #     if not self._branch:
    #         self._branch = f'z9hG4bK-{uuid4().hex}'
    #     return self._branch

    # @property
    # def tag(self):
    #     return f'{uuid4().hex}'[0:8]

    # @property
    # def via_uri(self) -> Uri:
    #     if not self._via_uri:
    #         self._via_uri = Uri(address=self.transport.public_address, port=self.transport.public_port)
    #     return self._via_uri
    
    # @property
    # def from_uri(self) -> Uri:
    #     if not self._from_uri:
    #         self._from_uri = Uri(username=self.user.username, address=self.public_address, port=self.user.port)
    #     return self._from_uri

    # @property
    # def contact_uri(self) -> Uri:
    #     if not self._contact_uri:
    #         self._contact_uri = Uri(address=self.transport.local_address, port=self.transport.local_port)
    #     return self._contact_uri

    # def _gen_header(self, **kwargs) -> Header:
    #     h = Header(
    #         via_uri=kwargs.get('via_uri', [Via(via_uri=Uri(address=self.transport.local_address, port=self.transport.local_port), attr={'branch': self.branch})]),
    #         from_uri=kwargs.get('from_uri', From(from_uri=Uri(username=self.user.username, address=self.transport.public_address, port=self.user.port), attr={'tag': self.tag})),
    #         to_uri=kwargs.get('to_uri', None),
    #         call_id=kwargs.get('call_id', None),
    #         contact_uri=kwargs.get('contact_uri', Contact(contact_uri=Uri(address=self.transport.local_address, port=self.transport.local_port))),
    #         cseq=kwargs.get('cseq', None),
    #         max_forwards=kwargs.get('max_forwards', MaxForwards(max_forwards=SIP_MAX_FORWARDS)),
    #         user_agent=kwargs.get('user_agent', UserAgent(user_agent=self.user.user_agent)),
    #         expires=kwargs.get('expires', Expires(expires=self.user.expires)),
    #         allow=kwargs.get('allow', Allow(allowed_methods=SIP_METHODS)),
    #         supported=kwargs.get('supported', Supported(supported=SIP_SUPPORTED)),
    #         unsupported=kwargs.get('unsupported', Unsupported(unsupported=SIP_UNSUPPORTED)),
    #         content_type=kwargs.get('content_type', ContentType(content_type=SIP_CONTENT_TYPE)),
    #         content_length=kwargs.get('content_length', ContentLength(content_length=0)),
    #         route=kwargs.get('route', []),
    #         record_route=kwargs.get('record_route', []),            
    #     )
    #     return h
    
    # def _gen_body(self, **kwargs) -> Body:
    #     b = Body()
    #     return b
    
    # @property
    # def content_length(self) -> int:
    #     if not self._body:
    #         return 0
    #     return len(str(self._body.to_bytes()))

    # def process_message(self, data, addr) -> Union[SipRequest, SipResponse]:
    #     pass

    # def gen_invite(self, destination: str, call_id: str) -> SipRequest:
    #     h = self._gen_header(
    #         to_uri=Uri(address=destination),
    #         call_id=CallId(call_id=call_id),
    #     )
    #     b = Body()
    #     return SipRequest(method=SipMethod.INVITE, uri=Uri(address=destination), header=h, body=b)
        

    # def gen_register(self) -> SipRequest:
    #     pass


#TODO: implementar mecanismo de envio/recebimento de chamadas

if __name__ == "__main__":
    s = Stack()

    r = s.gen_invite('XXXXXXX', '312321321')
    cl.print(r)