from typing import List, Union
from rich.panel import Panel
from uuid import uuid4

from pyphone.core.utils import (
    SipMethod,
    SipStatusCode,
    SIP_VERSION,
    SIP_METHODS,
    EOL
)
from pyphone.core.header import (
    Header,
    Uri,
)
from pyphone.core.payload import (
    Body
)
from pyphone.transport import Transport
from pyphone.user import User



class SipRequest:
    method: SipMethod
    uri: Uri
    header: Header
    body: Body
    def __str__(self) -> str:
        return f"{self.method} {self.uri} SIP/2.0{EOL}{self.header}{EOL}{EOL}{self.body}"

    def __rich__(self):
        return Panel(self.__str__(), title="SIP Request", highlight=True, expand=False)

    def to_bytes(self) -> bytes:
        return str(self).encode()


class SipResponse:
    status_code: SipStatusCode
    uri: Uri
    header: Header
    def __str__(self) -> str:
        return f"{SIP_VERSION} {self.status_code}{EOL}{self.header}"

    def __rich__(self):
        return Panel(self.__str__(), title="SIP Response", highlight=True, expand=False)

    def to_bytes(self) -> bytes:
        return str(self).encode()



class Dialog:
    def __init__(self):
        self.transport: Transport = None
        self.user: User = None
        self._cseq = 0
        self._call_id = None
        self._branch = None
        self._tag = None
        self._via_uri = None
        self._from_uri = None
        self._to_uri = None
        self._dialogs: List[Union[SipRequest, SipResponse]] = []
        self._header = Header()
        self._body = None


    @property
    def cseq(self):
        return self._cseq

    @property
    def call_id(self):
        if not self._call_id:
            self._call_id = f'{uuid4().hex}@{self.user.domain}'
        return self._call_id

    @property
    def branch(self):
        if not self._branch:
            self._branch = f'z9hG4bK-{uuid4().hex}'
        return self._branch

    @property
    def tag(self):
        return f'{uuid4().hex}'[0:8]

    @property
    def via_uri(self) -> Uri:
        if not self._via_uri:
            self._via_uri = Uri(address=self.transport.public_address, port=self.transport.public_port)
        return self._via_uri
    
    @property
    def from_uri(self) -> Uri:
        if not self._from_uri:
            self._from_uri = Uri(username=self.user.username, address=self.user.domain, port=self.user.port)
        return self._from_uri
    
    @property
    def to_uri(self) -> Uri:
        if not self._to_uri:
            self._to_uri = Uri(username=self.user.username, address=self.user.domain, port=self.user.port)
        return self._to_uri
    
    @property
    def contact_uri(self) -> Uri:
        if not self._contact_uri:
            self._contact_uri = Uri(address=self.transport.local_address, port=self.transport.local_port)
        return self._contact_uri
    
    @property
    def content_length(self) -> int:
        if not self._body:
            return 0
        return len(str(self._body.to_bytes()))

    def process_message(self, data, addr) -> Union[SipRequest, SipResponse]:
        pass

    def gen_invite(self) -> SipRequest:
        pass

    def gen_register(self) -> SipRequest:
        pass


#TODO: implementar mecanismo de envio/recebimento de chamadas