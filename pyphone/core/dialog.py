from enum import Enum

from pyphone.core.message import Message, ParserMessage
from pyphone.core.user import User


class Method(Enum):
    REGISTER = 'REGISTER'
    INVITE = 'INVITE'
    ACK = 'ACK'
    CANCEL = 'CANCEL'
    BYE = 'BYE'
    INFO = 'INFO'
    OPTIONS = 'OPTIONS'
    NOTIFY = 'NOTIFY'
    SUBSCRIBE = 'SUBSCRIBE'
    UPDATE = 'UPDATE'

class Dialog:
    def __init__(self, user: User) -> None:
        self.user = user

    def genate_register(self, message: ParserMessage = None) -> Message:
        m = Message()
        return m
    
    def generate_invite(self, message: ParserMessage = None) -> Message:
        m = Message()
        return m
        
    def generate_ack(self, message: ParserMessage = None) -> Message:
        m = Message()
        return m
        
    def generate_cancel(self, message: ParserMessage = None) -> Message:
        m = Message()
        return m
        
    def generate_bye(self, message: ParserMessage = None) -> Message:
        m = Message()
        return m
        
    def generate_info(self, message: ParserMessage = None) -> Message:
        m = Message()
        return m
        
    def generate_options(self, message: ParserMessage = None) -> Message:
        m = Message()
        return m
        
    def generate_notify(self, message: ParserMessage = None) -> Message:
        m = Message()
        return m
        
    def generate_subscribe(self, message: ParserMessage = None) -> Message:
        m = Message()
        return m
        
    def generate_update(self, message: ParserMessage = None) -> Message:
        m = Message()
        return m

    def process_dialog(self, message: ParserMessage) -> Message:        
        match message.method:
            case Method.REGISTER:
                m = self.generate_register(message)
            case Method.INVITE:
                m = self.generate_invite(message)
            case Method.ACK:
                m = self.generate_ack(message)
            case Method.CANCEL:
                m = self.generate_cancel(message)
            case Method.BYE:
                m = self.generate_bye(message)
            case Method.INFO:
                m = self.generate_info(message)
            case Method.OPTIONS:
                m = self.generate_options(message)
            case Method.NOTIFY:
                m = self.generate_notify(message)
            case Method.SUBSCRIBE:
                m = self.generate_subscribe(message)
            case Method.UPDATE:
                m = self.generate_update(message)
        return m
