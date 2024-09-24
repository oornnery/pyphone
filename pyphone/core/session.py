from pyphone.core.user import User
from pyphone.core.transport import Transport, TransportType
from pyphone.core.message import ParserMessage
from pyphone.core.dialog import Dialog
from pyphone.core.utils import log

class Session:
    def __init__(self, user: User, transport_type: TransportType = None) -> None:
        self.transport_type = transport_type
        self.user = user
        self.transport = Transport(self.transport_type, self.on_message)
        self.dialog = Dialog(self.user)

    def start(self):
        self.transport.start()
    
    def stop(self):
        self.transport.stop()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def __str__(self):
        return ""
    
    def on_message(self, data, addr):
        pm = ParserMessage(data)
        if pm.is_request():
            m = self.dialog.process_request(pm)
            self.transport.send(m, addr)
        elif pm.is_response():
            m = self.dialog.process_response(pm)
            self.transport.send(m, addr)
        log(f'Received {data} | from {addr}')
        log(m)