from typing import Callable
import threading

class Transport:
    def __init__(self, callback: Callable):
        self.callback = callback
        self.thread = threading.Thread(target=self._receive_loop).start()

    def send(self, data: bytes):
        raise NotImplementedError()
    
    def _receive_loop(self, data: bytes):
        raise NotImplementedError()
    