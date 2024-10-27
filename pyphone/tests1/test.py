import logging
from enum import Enum, IntEnum
from dataclasses import dataclass, field
from typing import List, Dict, Optional

from rich.logging import RichHandler
from rich.console import Console

cl = Console()

logging.basicConfig(
    level="NOTSET",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, console=cl)],
)

logging = logging.getLogger("rich")

class SIPStateInfo(Enum):
    TRYING = (100, "Trying")
    RINGING = (180, "Ringing")
    SESSION_PROGRESS = (183, "Session Progress")
    ANSWERED = (200, "OK")
    CANCELLED = (487, "CANCELLED")
    COMPLETED = (200, "COMPLETED")
    FAILED = (500, "FAILED")
    ESTABLISHED = (200, "ESTABLISHED")

    def __new__(cls, code, name):
        obj = object.__new__(cls)
        obj._value_ = name
        obj.code = code
        return obj


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


class RequestLine:
    def __init__(self):
        self._method: str = None
        self._request_uri: str = None
        self._attr: dict = None
    
    @property
    def method(self):
        return self._method

    @method.setter
    def method(self, value):
        self._method = value
    
    @property
    def request_uri(self):
        return self._request_uri

    @request_uri.setter
    def request_uri(self, value):
        self._request_uri = value

    @property
    def attr(self):
        return [f'{key}={value}' for key, value in self._attr.items()]
    
    @attr.setter
    def attr(self, attr, value):
        self._attr[attr] = value
    
    @staticmethod
    def parser(message: str) -> 'RequestLine':
        method = ''
        request_uri = ''
        attr = {}
        rl = RequestLine()
        rl.method = method
        rl.request_uri = request_uri
        rl.attr = attr
        return rl

    def __str__(self) -> str:
        #TODO: Refactor to include attr
        return f"{self.method.value} {self.request_uri} SIP/2.0\r\n"
    
    

class SIPHeader:
    def __init__(self):
        self._via: List[str] = None
        self._from: str = None
        self._to: str = None
        self._call_id: str = None
        self._cseq: str = None
        self._contact: str = None
        self._user_agent: str = None
        self._server: str = None
        self._content_type: str = None
        self._content_length: str = None
        self._max_forwards: str = None
        self._session_expires: str = None
        self._supported: str = None
        self._allow: List[str] = None
        self._proxy_authenticate: str = None
        self._authorization: str = None
        self._record_route: List[str] = None
        self._route: List[str] = None

    @property
    def uri_via(self):
        return *self._via

    @uri_via.setter
    def uri_via(self, uri: str):        
        self._via.append(uri)

    @property
    def uri_from(self):
        return self._from

    @uri_from.setter
    def uri_from(self, value):
        self._from = value

    @property
    def uri_to(self):
        return self._to

    @uri_to.setter
    def uri_to(self, value):
        self._to = value

    @property
    def call_id(self):
        return self._call_id

    @call_id.setter
    def call_id(self, value):
        self._call_id = value

    @property
    def cseq(self):
        return self._cseq

    @cseq.setter
    def cseq(self, value):
        self._cseq = value

    @property
    def uri_contact(self):
        return self._contact

    @uri_contact.setter
    def uri_contact(self, value):
        self._contact = value

    @property
    def user_agent(self):
        return self._user_agent

    @user_agent.setter
    def user_agent(self, value):
        self._user_agent = value

    @property
    def server(self):
        return self._server

    @server.setter
    def server(self, value):
        self._server = value

    @property
    def content_type(self):
        return self._content_type

    @content_type.setter
    def content_type(self, value):
        self._content_type = value

    @property
    def content_length(self):
        return self._content_length

    @content_length.setter
    def content_length(self, value):
        self._content_length = value

    @property
    def max_forwards(self):
        return self._max_forwards

    @max_forwards.setter
    def max_forwards(self, value):
        self._max_forwards = value

    @property
    def session_expires(self):
        return self._session_expires

    @session_expires.setter
    def session_expires(self, value):
        self._session_expires = value

    @property
    def supported(self):
        return self._supported

    @supported.setter
    def supported(self, value):
        self._supported = value

    @property
    def allow(self):
        return self._allow

    @allow.setter
    def allow(self, value):
        self._allow = value

    @property
    def proxy_authenticate(self):
        return self._proxy_authenticate

    @proxy_authenticate.setter
    def proxy_authenticate(self, value):
        self._proxy_authenticate = value

    @property
    def authorization(self):
        return self._authorization

    @authorization.setter
    def authorization(self, value):
        self._authorization = value

    @property
    def record_route(self):
        return *self._record_route

    @record_route.setter
    def record_route(self, value):
        self._record_route.append(value)

    @property
    def route(self):
        return *self._route

    @route.setter
    def route(self, value):
        self._route.append(value)
    
    
    



class StatusLine:
    pass

class SIPRequest:
    pass

class SIPResponse:
    pass


@dataclass
class SDP:
    version: str = "v=0"
    origin: str = field(default_factory=lambda: "o=- 20518 0 IN IP4 192.0.2.1")
    session_name: str = "s=Session"
    connection_info: str = field(default_factory=lambda: "c=IN IP4 192.0.2.1")
    media: Dict[str, str] = field(default_factory=lambda: {
        "audio": "m=audio 49170 RTP/AVP 0",
        "port": "a=rtpmap:0 PCMU/8000"
    })

@dataclass
class SIPMessage:
    method: str
    uri: str
    headers: Dict[str, str]
    body: Optional[str] = None

def create_invite_message(uri: str, from_uri: str, to_uri: str, contact_uri: str,
                          via: str, sdp: SDP) -> SIPMessage:
    return SIPMessage(
        method="INVITE",
        uri=uri,
        headers={
            "Via": via,
            "Max-Forwards": "70",
            "To": to_uri,
            "From": from_uri,
            "Call-ID": "a84b4c76e66710",
            "CSeq": "314159 INVITE",
            "Contact": contact_uri,
            "Content-Type": "application/sdp",
            "Content-Length": str(len(str(sdp)))
        },
        body=str(sdp)
    )

def create_response_message(sip_message: SIPMessage, status_code: int, reason_phrase: str) -> SIPMessage:
    return SIPMessage(
        method=f"{status_code} {reason_phrase}",
        uri=sip_message.uri,
        headers={
            "Via": sip_message.headers["Via"],
            "To": sip_message.headers["From"],
            "From": sip_message.headers["To"],
            "Call-ID": sip_message.headers["Call-ID"],
            "CSeq": sip_message.headers["CSeq"],
            "Contact": sip_message.headers["Contact"]
        },
        body="Call accepted." if status_code == 200 else ""
    )

class SIPDialog:
    def __init__(self):
        self.state = "INIT"

    def process_invite(self, invite_message: SIPMessage):
        logging.info(f"Sending INVITE:\n{invite_message}")
        
        # Simulando o recebimento de Trying
        trying_response = create_response_message(invite_message, 100, "Trying")
        logging.info(f"Receiving Response:\n{trying_response}")

        # Simulando o recebimento de Session Progress
        session_progress_response = create_response_message(invite_message, 183, "Session Progress")
        logging.info(f"Receiving Response:\n{session_progress_response}")

        # Simulando o recebimento de Ringing
        ringing_response = create_response_message(invite_message, 180, "Ringing")
        logging.info(f"Receiving Response:\n{ringing_response}")

        # Simulando o recebimento de 200 OK
        ok_response = create_response_message(invite_message, 200, "OK")
        logging.info(f"Receiving Response:\n{ok_response}")

        self.state = "ESTABLISHED"

    def send_ack(self):
        ack_message = SIPMessage(
            method="ACK",
            uri="sip:bob@192.0.2.4",
            headers={
                "Via": "SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds9",
                "Max-Forwards": "70",
                "To": "<sip:bob@biloxi.com>;tag=a6c85cf",
                "From": "<sip:alice@atlanta.com>;tag=1928301774",
                "Call-ID": "a84b4c76e66710",
                "CSeq": "314159 ACK"
            }
        )
        logging.info(f"Sending ACK:\n{ack_message}")

    def send_bye(self):
        bye_message = SIPMessage(
            method="BYE",
            uri="sip:bob@192.0.2.4",
            headers={
                "Via": "SIP/2.0/UDP 192.0.2.4;branch=z9hG4bKnashds10",
                "Max-Forwards": "70",
                "From": "<sip:bob@biloxi.com>;tag=a6c85cf",
                "To": "<sip:alice@atlanta.com>;tag=1928301774",
                "Call-ID": "a84b4c76e66710",
                "CSeq": "231 BYE"
            }
        )
        logging.info(f"Sending BYE:\n{bye_message}")

    def send_cancel(self):
        cancel_message = SIPMessage(
            method="CANCEL",
            uri="sip:bob@biloxi.com",
            headers={
                "Via": "<SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8>",
                "Max-Forwards": "70",
                "From": "<sip:alice@atlanta.com>;tag=1928301774",
                "To": "<sip:bob@biloxi.com>",
                "Call-ID": "<a84b4c76e66710>",
                "CSeq": "<314159 CANCEL>"
            }
        )
        logging.info(f"Sending CANCEL:\n{cancel_message}")

    def gen_msg_ringing(self):
        """
        SIP/2.0 180 Ringing
        Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8
        ;received=192.0.2.1
        To: Bob <sip:bob@biloxi.com>;tag=a6c85cf
        From: Alice <sip:alice@atlanta.com>;tag=1928301774
        Call-ID: a84b4c76e66710
        Contact: <sip:bob@192.0.2.4>
        CSeq: 314159 INVITE
        Content-Length: 0
        """
        
        msg = SIPMessage(
        )


from typing import Optional

try:
    from utils import SIPStatusCode, SIPMethod, Uri, gen_uuid
    from header import SIPHeader
    from payload import SIPBody
except ImportError:
    from pyphone.core.dialog.utils import SIPStatusCode, SIPMethod, Uri, gen_uuid
    from pyphone.core.dialog.header import SIPHeader
    from pyphone.core.dialog.payload import SIPBody
    

class SIPRequestMessage:
    def __init__(self, method: SIPMethod, uri: Uri, header: SIPHeader, body: SIPBody) -> None:
        self.method = method
        self.uri = uri
        self.header = header
        self.body = body

        self.calculate_content_length()

    def calculate_content_length(self) -> int:
        body_length = 0
        if self.body:
            body_length = len(str(self.body))
        self.header.content_length = str(body_length)

    def __str__(self) -> str:
        return f'{str(self.method)} {str(self.uri)} SIP/2.0\r\n{str(self.header)}\r\n{str(self.body)}'


class SIPResponseMessageMessage:
    def __init__(self, status_code: SIPStatusCode, header: SIPHeader, reason_phrase: Optional[str] = None) -> None:
        self.status_code = status_code
        self.header = header
        self.reason_phrase: str = reason_phrase if reason_phrase else self.status_code.description

    def __str__(self) -> str:
        return f'SIP/2.0 {str(self.status_code)}\r\n{self.status_line}{self.header}'



class Dialog:
    def __init__(self, transpost: 'Transport', user: 'User',) -> None:
        self.transport = transpost
        self.user = user
        self._cseq = 0
        self._call_id = lambda: gen_uuid(size=10, use_digits=True)+'@'+self.transport.local_address
        self._header = SIPHeader()
        
    @property
    def cseq(self) -> int:
        return self._cseq
    
    @cseq.setter
    def cseq(self, value: int) -> None:
        self._cseq += value

    @property
    def call_id(self) -> str:
        return self._call_id
    
    @call_id.setter
    def call_id(self, value: str) -> None:
        self._call_id = value
    
    def generate_register(self) -> SIPRequestMessage:
        headers = SIPHeader()        
        headers.add_via(
            self.transport.local_address,
            self.transport.local_address,
            self.transport,
            {
                "branch": lambda: gen_uuid(branch=True),
            }
            )        
        headers.max_forwards = '70'
        headers.from_(
            uri=self.user.uri,
            tag=gen_uuid(use_digits=True),
            )
        headers.to(
            uri=self.user.uri,
            display_info=self.user.display_info,
            #TODO: Add called id "display name <calle_id>
            )
        headers.contact(
            uri=self.user.uri
        )
        
        headers.call_id(self.call_id)
        headers.cseq(self.cseq, SIPMethod.REGISTER)
        headers.user_agent(self.user.user_agent)
        headers.expires(self.user.register_expires)
        headers.allow([SIPMethod.INVITE, SIPMethod.ACK, SIPMethod.BYE, SIPMethod.CANCEL, SIPMethod.REGISTER])
        headers.supported([SIPMethod.INVITE, SIPMethod.ACK, SIPMethod.BYE, SIPMethod.CANCEL, SIPMethod.REGISTER])
        headers.content_type('application/sdp')
        headers.content_length('0')
        
        
        req = SIPRequestMessage(
            method=SIPMethod.REGISTER,
            request_uri=self.user.uri,
            header=headers
            )        
        return req
    
    # def generate_invite(self) -> SIPRequestMessage:
    #     headers = SIPHeader(
            
    #     )
        
    #     body = SIPBody()
    #     req = SIPRequestMessage(
    #         method=SIPMethod.INVITE,
    #         request_uri=Uri(
    #             user=self.user.username,
    #             address=self.user.local_address
    #             ),
    #         header=headers,
    #         body=body
    #     )
    #     return req

    # def generate_ack(self, response: SIPResponseMessage) -> SIPResponseMessage:
    #     headers = SIPHeader()
    #     req_line = StatusLine(status_code=SIPStatusCode.OK)        
    #     req = SIPResponseMessage(
    #         req_line=req_line,
    #         header=headers,
    #     )        
    #     return req

    # def generate_trying(self, response: SIPResponseMessage) -> SIPResponseMessage:
    #     headers = SIPHeader()
    #     req_line = StatusLine(status_code=SIPStatusCode.TRYING)        
    #     req = SIPResponseMessage(
    #         req_line=req_line,
    #         header=headers,
    #     )
    #     return req
    
    # def generate_cancel(self, response: SIPResponseMessage = None) -> SIPRequest:
    #     headers = SIPHeader()
    #     req_line = SIPRequestMessage(method=SIPMethod.CANCEL)        
    #     req = SIPRequest(
    #         request_line=req_line,
    #         header=headers,
    #     )        
    #     return req
        
    # def generate_bye(self, response: SIPResponseMessage = None) -> SIPRequest:
    #     headers = SIPHeader()
    #     req_line = SIPRequestMessage(method=SIPMethod.BYE)        
    #     req = SIPRequest(
    #         request_line=req_line,
    #         header=headers,
    #     )        
    #     return req
        
    # def generate_info(self) -> SIPRequest:
    #     headers = SIPHeader()
    #     req_line = SIPRequestMessage(method=SIPMethod.INFO)        
    #     req = SIPRequest(
    #         request_line=req_line,
    #         header=headers,
    #     )        
    #     return req
        
    # def generate_options(self) -> SIPRequest:
    #     headers = SIPHeader()
    #     req_line = SIPRequestMessage(method=SIPMethod.OPTIONS)        
    #     req = SIPRequest(
    #         request_line=req_line,
    #         header=headers,
    #     )        
    #     return req
        
    # def generate_notify(self) -> SIPRequest:
    #     headers = SIPHeader()
    #     req_line = SIPRequestMessage(method=SIPMethod.NOTIFY)        
    #     req = SIPRequest(
    #         request_line=req_line,
    #         header=headers,
    #     )        
    #     return req
        
    # def generate_subscribe(self) -> SIPRequest:
    #     headers = SIPHeader()
    #     req_line = SIPRequestMessage(method=SIPMethod.SUBSCRIBE)        
    #     req = SIPRequest(
    #         request_line=req_line,
    #         header=headers,
    #     )        
    #     return req
        
    # def generate_update(self) -> SIPRequest:
    #     headers = SIPHeader()
    #     req_line = SIPRequestMessage(method=SIPMethod.UPDATE)        
    #     req = SIPRequest(
    #         request_line=req_line,
    #         header=headers,
    #     )        
    #     return req

    # def process_dialog(self, message: SIPResponseMessage) -> SIPRequest:        
    #     match message.status_line.status_code:
    #         case 100:
    #             return self.generate_ack(message)
    #         case 180:
    #             return self.generate_ack(message)
    #         case 487:
    #             return self.generate_ack(message)
    #         case 200:
    #             return self.generate_bye(message)
    #         case _:
    #             return self.generate_info(message)




def main():
    
    h = SIPHeader()
    
    h.via = "SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8"
    h.to = "Bob <sip:bob@biloxi.com>;tag=a6c85cf"
    h.from_ = "Alice <sip:alice@atlanta.com>;tag=1928301774"
    h.call_id = "a84b4c76e66710"
    h.cseq = "314159 INVITE"
    
    print(h)

if __name__ == "__main__":
    dialog = SIPDialog()
    
    # Criando uma mensagem INVITE com SDP
    sdp = SDP(origin="o=- 20518 0 IN IP4 192.0.2.1", 
              connection_info="c=IN IP4 192.0.2.1", 
              media={"audio": "m=audio 49170 RTP/AVP 0", 
                     "port": "a=rtpmap:0 PCMU/8000"})
    
    invite_message = create_invite_message(
        uri="sip:bob@biloxi.com",
        from_uri="<sip:alice@atlanta.com>;tag=1928301774",
        to_uri="<sip:bob@biloxi.com>",
        contact_uri="<sip:alice@pc33.atlanta.com>",
        via="SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8",
        sdp=sdp
    )
    
    dialog.process_invite(invite_message)
    
    # Enviando ACK após receber 200 OK
    dialog.send_ack()
    
    # Enviando BYE após a chamada
    dialog.send_bye()