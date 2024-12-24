from dataclasses import dataclass, field
from typing import List, Optional, Dict
from datetime import datetime
import random
from pyphone.utils import DialogState
from pyphone.exceptions import DialogError
from pyphone.logger import logger


@dataclass
class RouteSet:
    routes: List[str] = field(default_factory=list)
    record_route: Optional[str] = None


@dataclass
class DialogIdentifier:
    """Identificador único do diálogo"""
    call_id: str
    local_tag: str
    remote_tag: Optional[str] = None

    def __str__(self) -> str:
        return f"{self.call_id}:{self.local_tag}:{self.remote_tag or 'None'}"

@dataclass
class DialogInfo:
    """Informações do diálogo"""
    local_uri: str
    remote_uri: str
    remote_target: str
    secure: bool = False
    created_at: datetime = field(default_factory=datetime.now)
    route_set: RouteSet = field(default_factory=RouteSet)

@dataclass
class DialogState:
    """Estado do diálogo"""
    local_seq: int = field(default_factory=lambda: random.randint(1, 65535))
    remote_seq: int = 0
    state: DialogState = DialogState.INIT
    last_updated: datetime = field(default_factory=datetime.now)


class SIPDialog:
    """
    Implementação completa de diálogo SIP conforme RFC 3261
    Gerencia o ciclo de vida do diálogo e suas transações associadas
    """

    def __init__(self, identifier: DialogIdentifier, info: DialogInfo):
        self.identifier = identifier
        self.info = info
        self.state = DialogState()
        self.transactions: Dict[str, str] = {}  # branch -> transaction_type
        logger.info(f"Dialog created: {self.identifier}")

    def update_state(self, new_state: DialogState) -> None:
        """Atualiza o estado do diálogo"""
        try:
            old_state = self.state.state
            self.state.state = new_state
            self.state.last_updated = datetime.now()
            
            logger.info(
                f"Dialog {self.identifier}: State changed from {old_state} to {new_state}"
            )
            
        except Exception as e:
            logger.error(f"Error updating dialog state: {e}")
            raise DialogError(f"Failed to update dialog state: {e}")

    def add_transaction(self, branch: str, transaction_type: str) -> None:
        """Adiciona uma transação ao diálogo"""
        self.transactions[branch] = transaction_type
        logger.debug(
            f"Dialog {self.identifier}: Added transaction {branch} ({transaction_type})"
        )

    def remove_transaction(self, branch: str) -> None:
        """Remove uma transação do diálogo"""
        if branch in self.transactions:
            del self.transactions[branch]
            logger.debug(f"Dialog {self.identifier}: Removed transaction {branch}")

    def increment_local_seq(self) -> int:
        """Incrementa o número de sequência local"""
        self.state.local_seq += 1
        return self.state.local_seq

    def update_remote_seq(self, seq: int) -> None:
        """Atualiza o número de sequência remoto"""
        self.state.remote_seq = seq

    def update_route_set(self, record_route_headers: List[str]) -> None:
        """Atualiza o conjunto de rotas do diálogo"""
        try:
            if record_route_headers:
                self.info.route_set.routes = record_route_headers
                self.info.route_set.record_route = record_route_headers[0]
                logger.debug(
                    f"Dialog {self.identifier}: Updated route set with {len(record_route_headers)} routes"
                )
        except Exception as e:
            logger.error(f"Error updating route set: {e}")
            raise DialogError(f"Failed to update route set: {e}")

    def get_remote_target(self) -> str:
        """Obtém o destino remoto atual"""
        return self.info.remote_target

    def is_secure(self) -> bool:
        """Verifica se o diálogo é seguro"""
        return self.info.secure

    def match_response(self, response_headers: Dict[str, str]) -> bool:
        """Verifica se uma resposta pertence a este diálogo"""
        try:
            call_id = response_headers.get('Call-ID')
            to_tag = self._extract_tag(response_headers.get('To', ''))
            from_tag = self._extract_tag(response_headers.get('From', ''))
            
            return (call_id == self.identifier.call_id and 
                    to_tag == self.identifier.remote_tag and 
                    from_tag == self.identifier.local_tag)
                    
        except Exception as e:
            logger.error(f"Error matching response: {e}")
            return False

    def _extract_tag(self, header: str) -> Optional[str]:
        """Extrai a tag de um cabeçalho To/From"""
        import re
        match = re.search(r'tag=([^;>\s]+)', header)
        return match.group(1) if match else None

class DialogManager:
    """Gerenciador de diálogos SIP"""

    def __init__(self):
        self.dialogs: Dict[str, SIPDialog] = {}

    def create_dialog(self, identifier: DialogIdentifier, info: DialogInfo) -> SIPDialog:
        """Cria um novo diálogo"""
        try:
            if str(identifier) in self.dialogs:
                raise DialogError(f"Dialog already exists: {identifier}")
                
            dialog = SIPDialog(identifier, info)
            self.dialogs[str(identifier)] = dialog
            logger.info(f"Created new dialog: {identifier}")
            return dialog
            
        except Exception as e:
            logger.error(f"Error creating dialog: {e}")
            raise DialogError(f"Failed to create dialog: {e}")

    def get_dialog(self, identifier: str) -> Optional[SIPDialog]:
        """Recupera um diálogo pelo identificador"""
        return self.dialogs.get(identifier)

    def find_dialog_by_response(self, response_headers: Dict[str, str]) -> Optional[SIPDialog]:
        """Encontra um diálogo correspondente a uma resposta"""
        try:
            for dialog in self.dialogs.values():
                if dialog.match_response(response_headers):
                    return dialog
            return None
            
        except Exception as e:
            logger.error(f"Error finding dialog by response: {e}")
            return None

    def terminate_dialog(self, identifier: str) -> None:
        """Termina um diálogo"""
        try:
            dialog = self.dialogs.get(identifier)
            if dialog:
                dialog.update_state(DialogState.TERMINATED)
                del self.dialogs[identifier]
                logger.info(f"Terminated dialog: {identifier}")
                
        except Exception as e:
            logger.error(f"Error terminating dialog: {e}")
            raise DialogError(f"Failed to terminate dialog: {e}")

    def cleanup_dialogs(self) -> None:
        """Remove diálogos terminados"""
        try:
            terminated = [
                id for id, dialog in self.dialogs.items()
                if dialog.state.state == DialogState.TERMINATED
            ]
            
            for id in terminated:
                del self.dialogs[id]
                
            if terminated:
                logger.info(f"Cleaned up {len(terminated)} terminated dialogs")
                
        except Exception as e:
            logger.error(f"Error cleaning up dialogs: {e}")