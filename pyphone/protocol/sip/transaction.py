from typing import List
from enum import Enum

from pyphone.protocol.sip.message import SIPRequest, SIPResponse
from pyphone.utils import log


class SIPTransactionState(Enum):
    TRYING = 1
    PROCEEDING = 2
    COMPLETED = 3
    TERMINATED = 4


class SIPTransaction:
    def __init__(self, request: SIPRequest):
        self.request = request
        self.response: List[SIPResponse]
        self.state = SIPTransactionState.TRYING

    def handle_message(self, response: SIPResponse):
        if isinstance(response, SIPResponse):
            if response.status >= 100 and response.status < 200:
                log.info("Received 1xx response - provisional response")
                self.state = SIPTransactionState.PROCEEDING
            elif response.status >= 200 and response.status < 300:
                log.info("Received 2xx response - successful response")
                self.state = SIPTransactionState.COMPLETED
            elif response.status >= 300 and response.status < 400:
                log.info("Received 3xx response - redirection response")
                self.state = SIPTransactionState.TERMINATED
            elif response.status >= 400 and response.status < 500:
                log.info("Received 4xx response - request failure")
                self.state = SIPTransactionState.TERMINATED
            elif response.status >= 500 and response.status < 600:
                log.info("Received 5xx response - server failure")
                self.state = SIPTransactionState.TERMINATED
            elif response.status >= 600 and response.status < 700:
                log.info("Received 6xx response - global failure")
                self.state = SIPTransactionState.TERMINATED
            else:
                log.info("Received unknown response")
                self.state = SIPTransactionState.TERMINATED
            self.response.append(response)
        else:
            log.error("Received non-response message")
