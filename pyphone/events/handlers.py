from functools import wraps
from typing import Callable, Dict
from pyphone.utils import SIPMessageType
from pyphone.logger import logger

class SIPHandler:
    _handlers: Dict[SIPMessageType, Callable] = {}

    @classmethod
    def on(cls, message_type: SIPMessageType):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                logger.debug(f"Handling {message_type.value} message")
                #TODO: show summary of the message
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    logger.error(f"Error in {message_type.value} handler: {e}")
                    raise
            cls._handlers[message_type] = wrapper
            return wrapper
        return decorator

    @classmethod
    def get_handler(cls, message_type: SIPMessageType):
        return cls._handlers.get(message_type)
