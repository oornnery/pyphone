from typing import List
from pyphone.protocol.sip.message import Message, SIPRequest
from pyphone.protocol.sip.transaction import SIPTransaction
from pyphone.utils import log


class SIPDialog:
    def __init__(self, message: Message):
        self.message = message
        self.transactions: List[SIPTransaction]

    def handle_message(self, message: Message):
        # Update dialog and transaction state based on status code and method
        for transaction in self.transactions:
            if transaction.request.branch == message.branch:
                log.info("Received message for existing transaction")
                transaction.handle_message(message)
                break
        else:
            if isinstance(message, SIPRequest):
                log.info(
                    "Received request for non-existent transaction, creating new transaction"
                )
                transaction = SIPTransaction(message)
                self.transactions.append(transaction)
            else:
                log.info("Received response for non-existent transaction")
