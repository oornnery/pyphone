from pyphone.core.user import User
from pyphone.core.peer import Peer
from pyphone.core.transport import Transport
from pyphone.core.dialog import Dialog
from pyphone.core.utils import log

class Session:
    stack = []
    def __init__(self, user: User, transport: Transport) -> None:
        self.transport = transport
        self.user = user
        self.peer = Peer(transport, self.on_message)
        self.dialog = Dialog(transport, user)

    def start(self):
        self.peer.start()

    def stop(self):
        self.peer.stop()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def __str__(self):
        return ""
    
    def on_message(self, data, addr):
        pm = self.dialog.process_dialog(data)
        if pm.is_request():
            m = self.dialog.process_request(pm)
            self.transport.send(m, addr)
        elif pm.is_response():
            m = self.dialog.process_response(pm)
            self.transport.send(m, addr)
        log(f'Received {data} | from {addr}')
        log(m)


if __name__ == '__main__':
    dl = Session(User(), Transport())
    dl.dialog.generate_register()