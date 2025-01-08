import threading

from pyphone.header import (
    Header,
    HeaderFactory
)

from pyphone.sdp import (
    Body,
    BodyFactory
)

from pyphone.message import (
    Message,
    MessageFactory
)

from pyphone.connection import (
    ConnectionConfig,
    Connection
)

from pyphone.user_agent import (
    UserAgentConfig
)





class Client:
    def __init__(self, config: UserAgentConfig, conn_cfg: ConnectionConfig):
        if not config.conn_cfg and not conn_cfg:
            raise Exception("Connection config is required")
        self.config = config
        self.connection = Connection(
            config.conn_cfg or conn_cfg, targe_address=config.server, target_port=config.port, callback=self.on_message)
        self.transactions = {}
        self._is_running = False
        
    
    def start(self):
        self._is_running = True
        self.connection.start()
    
    def on_message(self, message: Message, address: str):
        print('\n')
        print(f"Received message from: {address}")
        print('\n')
        print(message)
        print('\n')
    
    def invite(self, target_address: str, target_port: int):
        if not self._is_running:
            raise Exception("Client not running")
        message = MessageFactory.request('INVITE', user_agent_cfg=self.config)
        self.connection.send(message.to_bytes())
    
    