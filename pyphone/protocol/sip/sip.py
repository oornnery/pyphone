from typing import Callable, Dict
from pyphone.protocol.sip.message import Message, SIPRequest, SIPResponse
from pyphone.protocol.sip.dialog import SIPDialog
from pyphone.connection import ConnCfg, ConnectionHandler
from pyphone.utils import log


class SIP(ConnectionHandler):
    def __init__(self, cfg: ConnCfg, callback: Callable):
        super().__init__(cfg, self.handle_transport)
        self.callback = callback
        self.dialogs: Dict[str, SIPDialog]
        
    def create_dialog(self, message: Message):
        if not message.is_request:
            log.error("Dialog/Transaction not found for response")
            # TODO: implement 481 response
            return
        dialog = SIPDialog(message)
        self.dialogs[message.call_id] = dialog
        return dialog

    def handle_message_sending(self, message: SIPRequest):
        """Handle SIP message and send it"""
        msg_type = "request" if isinstance(message, SIPRequest) else "response"
        log.info(f"Sending {msg_type}\n{message}")
        dlg = self.dialogs.get(message.call_id, self.create_dialog(message))
        self.send(message)
        dlg.handle_message(message)

    def handle_transport(self, raw: bytes, addr: tuple):
        """Handle incoming data from transport"""
        message = Message.from_bytes(raw)
        if message is None:
            log.error(f"Invalid SIP message received: {raw}")
            return
        log.info(f"Received {message.type}\n{message}")
        self.handle_message_received(message) 
    
    def handle_message_received(self, message: SIPResponse):
        """Handle a received SIP message and update dialog state"""
        dialog = self.dialogs.get(message.call_id, self.create_dialog(message))
        dialog.handle_message(message)
        self.callback(message)
        return dialog
