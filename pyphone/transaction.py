import time
import uuid
from typing import List, Optional, Callable, Dict
from dataclasses import dataclass, field
from pyphone.exceptions import TransactionError
from pyphone.utils import SIPStatusCode, SIPMessageType, TransactionState
from pyphone.logger import logger


@dataclass
class  SIPResponse:
    status_code: SIPStatusCode
    headers: dict
    body: Optional[str] = None
    raw_message: str = ''


@dataclass
class SIPRequest:
    method: SIPMessageType
    uri: str
    headers: dict
    body: Optional[str] = None
    raw_message: str = ''

@dataclass
class TransactionConfig:
    timeout: int = field(default=32)
    max_reties: int = field(default=3)
    backoff_multiplier: int = field(default=2.0)

@dataclass
class SIPTransaction:
    method: SIPMessageType
    branch: str = field(default_factory=lambda: f"z9hG4bK{uuid.uuid4().hex[:8]}")
    state: TransactionState = TransactionState.TRYING
    config: TransactionConfig = field(default_factory=TransactionConfig)
    
    _request: Optional[SIPRequest] = None
    _responses: List[SIPResponse] = field(default_factory=list)
    _created_at: float = field(default_factory=time.time)
    _completed_at: Optional[float] = None
    _retries: int = 0
    _callbacks: dict = field(default_factory=dict)

    def set_request(self, request: SIPRequest):
        logger.debug(f"Transaction  {self.branch}: Request set - {request.method.value}")
        self._request = request

    def add_response(self, response: SIPResponse):
        logger.debug(f"Transaction  {self.branch}: Response added - {response.status_code.value}")
        self._responses.append(response)
        self._update_state(response.status_code)
    
    def _update_state(self, status_code: SIPStatusCode):
        # TODO: Add handlers for each state
        try:
            if status_code in (SIPStatusCode.REQUEST_TIMEOUT, SIPStatusCode.SERVER_TIMEOUT):
                self.state = TransactionState.TIMEOUT
            elif status_code in (SIPStatusCode.OK, SIPStatusCode.ACCEPTED):
                self.state = TransactionState.COMPLETED
                self._completed_at = time.time()
            elif status_code in (SIPStatusCode.BUSY_HERE, SIPStatusCode.NOT_FOUND, SIPStatusCode.NOT_ACCEPTABLE_HERE):
                self.state = TransactionState.REJECTED
            elif status_code in (SIPStatusCode.REQUEST_TERMINATED, SIPStatusCode.REQUEST_CANCELLED):
                self.state = TransactionState.CANCELLED
            elif status_code in (SIPStatusCode.REQUEST_IN_PROGRESS, SIPStatusCode.OK):
                self.state = TransactionState.PROCEEDING
            else:
                self.state = TransactionState.TRYING
        except Exception as e:
            self.logger.error(f"Transaction {self.branch}: Error updating state: {e}")
            raise TransactionError(f"Failed to update transaction state: {e}")
    
    def is_timeout(self):
        """Verifica se a transação excedeu o timeout"""
        current_timeout = self.config.timeout * (
            self.config.backoff_multiplier ** self._retries
        )
        return time.time() - self._created_at > current_timeout

    def can_retry(self) -> bool:
        """Verifica se a transação pode ser retentada"""
        return self._retries < self.config.max_retries

    def increment_retry(self) -> None:
        """Incrementa o contador de tentativas"""
        self.logger.debug(f"Transaction {self.branch}: Retry {self._retries}")
        self._retries += 1
    
    def set_callback(self, event: str, callback: Callable) -> None:
        """Define um callback para eventos da transação"""
        self._callbacks[event] = callback

    def _execute_callback(self, event: str, *args, **kwargs) -> None:
        """Executa um callback registrado"""
        callback = self._callbacks.get(event)
        if callback:
            try:
                callback(*args, **kwargs)
            except Exception as e:
                self.logger.error(
                    f"Transaction {self.branch}: Error executing {event} callback: {e}"
                )

class TransactionManager:
    def __init__(self):
        self.transactions: Dict[str, SIPTransaction] = {}
    
    def create_transaction(self, method: SIPMessageType, config: Optional[TransactionConfig] = None) -> SIPTransaction:
        """Cria uma nova transação"""
        transaction = SIPTransaction(method=method, config=config or TransactionConfig())
        logger.info(f"Created transaction: {transaction.branch} - {method.value}")
        self.transactions[transaction.branch] = transaction
        return transaction

    def get_transaction(self, branch: str) -> SIPTransaction:
        return self.transactions.get(branch)
    
    def remove_transaction(self, branch: str) -> None:
        if branch in self.transactions:
            logger.debug(f"Removed transaction: {branch}")
            del self.transactions[branch]

    def cleanup_transactions(self) -> None:
        """Remove transações completadas ou expiradas"""
        to_remove = []
        logger.debug("Checking for transactions to cleanup")
        for branch, transaction in self.transactions.items():
            if (transaction.state == TransactionState.COMPLETED or 
                (transaction.is_timeout() and not transaction.can_retry())):
                to_remove.append(branch)

        for branch in to_remove:
            self.remove_transaction(branch)

        if to_remove:
            logger.info(f"Cleaned up {len(to_remove)} transactions")