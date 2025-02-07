'''
Session Initiation Protocol (SIP)
RFC 3261: https://tools.ietf.org/html/rfc3261
'''

from typing import List
import uuid

from message import Message
from utils import log


class Transaction:
    def __init__(self, request: Message, branch: str):
        self.request = request
        self.branch = branch
        self.responses: List[Message] = []
        self.requests: List[Message] = []
        self.state = "TRYING"

    def handle_transaction(self, m: Message):
        if m.is_response:
            self.responses.append(m)
            sc = m.first_line.status_code
            match sc:
                case sc if sc >= 100 and sc < 200:
                    self.state = "PROCEEDING"
                case sc if sc >= 200 and sc < 300:
                    self.state = "COMPLETED"
                case sc if sc >= 300 and sc < 400:
                    self.state = "REDIRECTED"
                case sc if sc >= 400 and sc < 500:
                    self.state = "FAILED"
                case sc if sc >= 500 and sc < 600:
                    self.state = "ERROR"
                case _:
                    self.state = "UNKNOWN"
        else:
            log.error(f"Received request in transaction {self.branch}")


class Dialog:
    def __init__(self, request: Message):
        self.request = request
        self.transactions: List[Transaction] = []
        
        self.call_id = request.header.call_id
        self.new_transaction(request)
    
    def new_transaction(self, m: Message):
        tr = Transaction(m)
        self.transactions.append(tr)
        return tr

    def handle_dialog(self, m: Message):
        for _tr in self.transactions:
            if _tr.branch == m.branch:
                tr = _tr
        else:
            tr = self.new_transaction(m)
        tr.handle_transaction(m)

    def re_invite(self):
        pass

    def _generate_branch(self):
        return f"z9hG4bK{str(uuid.uuid4())[:8]}"

    def _generate_call_id(self):
        return str(uuid.uuid4())

    def _generate_tag(self):
        return str(uuid.uuid4())[:4]