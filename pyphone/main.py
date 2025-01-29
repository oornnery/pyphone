
from datetime import datetime
from typing import List

class Message: ...

class Request(Message): ...

class Response(Message): ...

class Transaction:
    def __init__(self, m: Message):
        self.messages: List[Message] = [m]
        self.branch = m.branch
        self.status = None

    def on_transaction_update(self, m: Message):
        self.messages.append(m)
        if isinstance(m, Request):
            self.status = 'trying'
        elif isinstance(m, Response):
            if m.status_code > 100 and m.status_code < 200:
                self.status = 'connecting'
            elif m.status_code >= 200 and m.status_code < 300:
                self.status = 'completed'
            elif m.status_code >= 300 and m.status_code < 400:
                self.status = 'redirected'
            elif m.status_code >= 400 and m.status_code < 500:
                self.status = 'terminated'
            elif m.status_code >= 500 and m.status_code < 600:
                self.status = 'server_error'
            else:
                self.status = 'unknown' 
        else:
            self.status = 'unknown'

class Dialog:
    _started_at = None
    _ended_at = None
    
    def __init__(self, tr: Transaction):
        self.tr = tr
        self.transactions: List[Transaction] = []
    
    @property
    def started_at(self):
        if not self._started_at:
            self._started_at = datetime.now().timestamp()
        return self._started_at
    
    @property
    def ended_at(self):
        if not self._ended_at:
            self._ended_at = datetime.now().timestamp()
        return self._ended_at

    async def on_dialog_update(self, m: Message):
        for _tr in self.transactions:
            if _tr.branch == m.branch:
                tr = _tr
        else:
            tr = Transaction(m)
            self.transactions.append(tr)
        await tr.on_transaction_update(m)
    def re_invite(self):
        pass
    
    def ack(self):
        pass
    
    def bye(self):
        pass
    
    def cancel(self):
        pass
    


class Call(Dialog):
    hold: bool = False
    mute: bool = False
    speaker: bool = False
    recording: bool = False

    def __init__(self, tr: Transaction):
        super().__init__(tr)
    
        self.duration = None
        self.status = None

    
    def end(self):
        self.duration = datetime.now() - self.started_at
        self.status = 'ended'
    
    def hold(self):
        self.hold = True
        self.
    

class PhoneClient:
    
    