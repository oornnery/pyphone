from typing import List, Optional, Union
import threading
import time

from pyphone.dialog import Dialog, DialogState
from pyphone.message import Request, Response, SIPMessage, MessageFactory
from pyphone.utils import StatusCode, Method
from pyphone.header import Header, HeaderField, Address, Via, From, To, CallId, CSeq
from pyphone.sdp import Sdp, SdpField
from pyphone.utils import logger
from pyphone.connection import Connection
from pyphone.transport import Transport
from pyphone.user_agent import UserAgent


class Session:
    def __init__(self, user_agent: UserAgent, transport: Transport = None) -> None:
        self.user_agent = user_agent
        if self.user_agent.transport:
            self.transport = self.user_agent.transport
        elif transport:
            self.transport = transport
        else:
            self.transport = Transport()
        # Dialogs are stored in a list
        self._dialogs: List[Dialog] = []
        self._keepalive_interval = 30
        self._last_keepalive = time.time()
        
        # Start the session
        self.start()

    def start(self):
        # Create a client
        self.connection: Connection = Connection(
            address=self.user_agent.domain,
            port=self.user_agent.port,
            protocol=self.transport.protocol,
            callback=self._callback_connection,
            buffer_size=self.transport.buffer_size
            )
        self.connection.start()

    def _callback_connection(self, data: bytes, addr):
        logger.debug(f"Received data from {addr}")
        # Parse SIP message
        if not data:
            logger.error("Received empty data")
            return
        m = SIPMessage.from_bytes(data)
        if not m:
            logger.error("Failed to parse SIP message")
            return
        logger.info(str(m))
        # Update dialog
        d = self._update_dialog(m)
        # Handle message
        if isinstance(m, Request):
            self.handle_request(m, d)
        elif isinstance(m, Response):
            self.handle_response(m, d)
    
    def _create_dialog(self, message: Union[Request, Response] = None, **kwargs) -> Dialog:
        d = Dialog(on_message_created=message)
        self._dialogs.append(d)
        return d
    
    def _update_dialog(self, message: Union[Request, Response]):
        for dialog in self._dialogs:
            if dialog.call_id == message.header['Call-ID']:
                dialog.append(message)
                return dialog
        return self._create_dialog(message)

    def send_message(self, message: Union[Request, Response], target_address: Optional[Tuple[str, int]]=None):
        pass
    
    def create_request(
            self,
            method: Method,
            to_addr: Address = None,
            branch: str = None,
            local_tag: str = None,
            remote_tag: str = None,
            call_id: str = None,
            seq: int = None,
            sdp: Sdp = None,
            extra_headers_fields: List[HeaderField] = None,
            **kwargs
        ) -> Request:
        addr = Address(
            host=self.user_agent.host,
            port=self.user_agent.port,
            user=self.user_agent.username,
            display_name=self.user_agent.display_name
        )
        h = Header()
        h.add(kwargs.get('via_field', Via(
                host=self.user_agent.transport.local_address,
                port=self.user_agent.transport.local_port,
                branch=branch
            )))
        h.add(kwargs.get('from_field', From(
                address=addr,
                tag=local_tag
            )))
        h.add(kwargs.get('to_field', To(
                address=to_addr or addr,
                tag=remote_tag
            )))
        h.add(kwargs.get('call_id_field', CallId(call_id)))
        h.add(kwargs.get('cseq_field', CSeq(method=method, seq=seq)))
        h.add(HeaderField(key='Max-Forwards', value=70))
        #TODO: Add extra headers
        match method:
            case Method.INVITE:
                h.add(HeaderField(key='Contact', value=str(Address(
                    host=self.user_agent.transport.local_address,
                    port=self.user_agent.transport.local_port,
                    user=self.user_agent.username,
                ))))
            case Method.REGISTER:
                h.add(HeaderField(key='Expires', value=self.user_agent.expires))
                h.add(HeaderField(key='User-Agent', value=self.user_agent.user_agent))
            case (Method.OPTIONS, Method.INVITE):
                h.add(HeaderField(key='Allow', value=Method.string_values()))
                # TODO: Criar enum para os valores de Allow-Events
                h.add(HeaderField(key='Allow-Events', value='talk, hold, conference, refer'))
            case _:
                pass
        # TODO: Implementar corretamente o SDP
        if sdp:
            h.add(HeaderField(key='Content-Type', value='application/sdp'))
            h.add(HeaderField(key='Content-Length', value=len(sdp)))
        else:
            h.add(HeaderField(key='Content-Length', value=0))
        
        if extra_headers_fields:
            for header in extra_headers_fields:
                h.add(header)
        
        return Request(
            method=method,
            host=self.user_agent.domain,
            port=self.user_agent.port,
            header=h,
            sdp=sdp
        )
    
    def create_response(
            self,
            status_code: StatusCode,
            request: Request,
            sdp: Sdp = None,
            extra_headers_fields: List[HeaderField] = None,
            **kwargs
        ) -> Request:
        h = Header()
        
        return Response(
            status_code=status_code,
            host=self.user_agent.domain,
            port=self.user_agent.port,
            header=h,
            sdp=sdp
        )
    
    def handle_request(self, message: Union[Request, Response], dialog: Dialog):
        logger.info(f"Received {message.method} request")
        match message.method:
            case Method.INVITE:
                dialog.state = DialogState.PROGRESS
                # TODO: Generate 100 Trying response
            case Method.ACK:
                dialog.state = DialogState.CONFIRMED
                if dialog._on_message_created.method == Method.INVITE:
                    # TODO: Update call state
                    pass
            case Method.BYE:
                # TODO: Handle BYE request
                # Check Dialog and CSeq
                pass
            case Method.CANCEL:
                pass
            case Method.OPTIONS:
                pass
            case _:
                pass

    def handle_response(self, message: Union[Request, Response]):
        logger.info(f"Received {message.status_code} response")
        match message.status_code:
            case StatusCode.OK:
                # TODO: Handle call established
                pass
            case (
                StatusCode.TRYING,
                StatusCode.RINGING,
                StatusCode.SESSION_PROGRESS,
            ):
                # TODO: Handle call progress
                pass
            case (
                    StatusCode.ADDRESS_INCOMPLETE,
                    StatusCode.REQUEST_TIMEOUT,
                    StatusCode.SERVER_INTERNAL_ERROR,
                    StatusCode.TEMPORARILY_UNAVAILABLE,
                    StatusCode.USE_PROXY,
                    ):
                pass
            case StatusCode.CALL_TRANSACTION_DOES_NOT_EXIST:
                # TODO: Handle call transaction does not exist, check CSeq and Dialog
                pass
            case (
                    StatusCode.BUSY_HERE,
                    StatusCode.DECLINE,
                    StatusCode.NOT_FOUND,
                ):
                pass
            case StatusCode.FORBIDDEN:
                # TODO: Handle forbidden
                # Check if the request was a REGISTER request with CSeq and Dialod.state
                pass
            case StatusCode.REQUEST_TERMINATED:
                pass
            case (
                    StatusCode.PROXY_AUTHENTICATION_REQUIRED,
                    StatusCode.UNAUTHORIZED
                    ):
                # TODO: Handle authentication
                pass
            case _:
                pass
    
    def _generate_header(self):
        h = Header()
    
    def handle_ok_response(self, message: Response, dialog: Dialog):
        # Generate ACK request
        # Send ACK request
        m = MessageFactory.create_request(
            method=Method.ACK,
            )

        pass