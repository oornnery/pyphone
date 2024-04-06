import logging, time, datetime
import os, sys, subprocess, re
from enum import Enum
from typing import Any
from multiprocessing import Process, Manager, Value
from rich.logging import RichHandler
from dataclasses import dataclass

logging.basicConfig(
    level="NOTSET",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, omit_repeated_times=False)],
)

log = logging.getLogger("rich")

class TwinkleError(Exception):
    pass

@dataclass
class Call:
    line: int
    destination: str
    status: str
    start_time: str
    end_time: str
    
    
    def duration(self):
        return int(self.end_time) - int(self.start_time)
    

class CallStatus(Enum):
    TRYING = 'TRYING'
    RINGING = 'RINGING'
    SESSION_PROGRESS = 'SESSION_PROGRESS'
    ANSWERED = 'ANSWERED'
    FAILED = 'FAILED'
    ENDED = 'ENDED'
    # NOT_FOUND = 'NOT_FOUND'
    # FORBIDDEN = 'FORBIDDEN'
    # BUSY_HERE = 'BUSY_HERE'
    # REQUEST_TERMINATED = 'REQUEST_TERMINATED'
    # TEMPORARY_UNAVAILABLE = 'TEMPORARY_UNAVAILABLE'
    


class CallStatusCode(Enum):
    TRYING = '100'
    RINGING = '180'
    SESSION_PROGRESS = '183'
    ANSWERED = '200'
    FAILED = '487'
    ENDED = '487'
    # NOT_FOUND = '404'
    # FORBIDDEN = '403'
    # BUSY_HERE = '486'
    # REQUEST_TERMINATED = '487'
    # TEMPORARY_UNAVAILABLE = '480'
    


class CallDirection(Enum):
    INCOMING = 'INCOMING'
    OUTGOING = 'OUTGOING'

class Call:
    def __init__(self, line: str, destination: str, direction: CallDirection = CallDirection.OUTGOING) -> None:
        self.line = line
        self.destination = destination
        self.direction = direction
        self._status: list[CallStatus] = []
        self._start_time: str = None
        self._end_time: str = None
        self.start_time

    @property
    def status(self) -> list[CallStatus]:
        return self._status

    @property
    def start_time(self) -> str:
        return self._start_time

    @property
    def end_time(self) -> str:
        return self._end_time

    @status.setter
    def status(self, status: CallStatus):
        self._status.append(status)

    @start_time.setter
    def start_time(self, start_time: str = None):
        if start_time is None:
            start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._start_time = start_time

    @end_time.setter
    def end_time(self, end_time: str = None):
        if end_time is None:
            end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._end_time = end_time

    def duration(self):
        return int(self.end_time) - int(self.start_time)
    

class Phone:
    def __init__(self, debug: bool = False, flags: list[str] = ['--force']) -> None:
        self.debug = debug
        self.proc: Popen = subprocess.Popen(
            ['twinkle -c'],
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE
        )
        if self.proc.wait() != 0:
            log.error('Twinkle failed to start')
            msg = self.proc.stdout.read().decode("utf-8").strip().split('\n')[0]
            log.error(f'{msg}')
            raise TwinkleError(f'{self.proc.stdout.read().decode("utf-8")}')
        self.process = Process(target=self.run,args=[])
        self.process.start()
        self._active_line = None
        self._active_call: list = []

    def stop_twinkle(self) -> None:
        """Send 'quit' to Twinkle CLI."""
        self.send_command('quit')
        self.process.terminate()

    def send_command(self, command: str) -> None:
        """Send any string to stdin then line break."""
        if command == '':
            return
        if self.debug:
            log.debug(f'Sending command: {command}')
        self.proc.stdin.write(f'{command}\n'.encode())
        self.proc.stdin.flush()
        time.sleep(1)

    def call(self, number: str, line: int = 1, display_name: str = None, anonymous: bool = False):
        """
        Call someone
        """
        flags = []
        if display_name:
            flags.append(f'-d {display_name}')
        if anonymous:
            flags.append('-h')
        flags = ' '.join(flags)
        number = re.sub(r'\D', '', number)
        self.line(line)
        self.send_command(f'call {flags} {number}')
        self._active_call.append(Call(line, number))
        return self._active_call[-1]

    def answer(self):
        """
        Answer an incoming call
        """
        self.send_command('answer')

    def reject(self):
        """
        Reject an incoming call
        """
        return self.send_command('reject')

    def redirect(self):
        """
        Redirect an incoming call
        """
        return self.send_command('redirect')

    def transfer(self):
        """
        Transfer a standing call
        """
        return self.send_command('transfer')

    def bye(self):
        """
        End a call
        """
        return self.send_command('bye')

    def hold(self):
        """
        Put a call on-hold
        """
        return self.send_command('hold')

    def retrieve(self):
        """
        Retrieve a held call
        """
        return self.send_command('retrieve')

    def conference(self):
        """
        Join 2 calls in a 3-way conference
        """
        return self.send_command('conference')

    def mute(self):
        """
        Mute a line
        """
        return self.send_command('mute')

    def dtmf(self):
        """
        Send DTMF
        """
        return self.send_command('dtmf')

    def redial(self):
        """
        Repeat last call
        """
        return self.send_command('redial')

    def register(self):
        """
        Register your phone at a registrar
        """
        return self.send_command('register')

    def deregister(self):
        """
        De-register your phone at a registrar
        """
        return self.send_command('deregister')

    def fetch_reg(self):
        """
        Fetch registrations from registrar
        """
        return self.send_command('fetch_reg')

    def line(self, line: int = None):
        """
        Toggle between phone lines
        """
        return self.send_command(f'line {line}')

    def dnd(self):
        """
        Do not disturb
        """
        return self.send_command('dnd')

    def auto_answer(self):
        """
        Auto answer
        """
        return self.send_command('auto_answer')

    def user(self):
        """
        Show users / set active user
        """
        return self.send_command('user')

    def presence(self):
        """
        Publish your presence state
        """
        return self.send_command('presence')

    def handle_line(self, message: str):
        m = re.match(r"^Line (\d+) is now active\.$", message)
        log.info(m)

    def handle_call(self, stdout: str):
        line, code, message = re.match(
            'Line (\d): received (\d+) (trying|ringing|answered|ok|ended)', 
            stdout, 
            re.IGNORECASE
            ).group(1, 2, 3)
        log.info(f'Line {line}: {code} {message}')
        
        ringing = 'Line (\d): received 180 Ringing'
        answered = 'Line (\d): far end answered call.'
        ok = '200 OK'
        to = 'To: sip:0916770737@proxy2.idtbrasilhosted.com'
        ended = 'Line 1: far end ended call.'
    
    def is_message(self, message: str, stdout: str) -> str:
        return re.match(message, stdout)
    
    def _is_line(self, stdout: str) -> str:
        line = re.match(r"^Line (\d+):", stdout)
        if m:
            return m.group(1)
        return None
    
    def handle_call_status(self, stdout: str) -> str:
        """
        Status of a call:
        
        Line (\d): received 100 trying -- your call is important to us
        Line (\d): received 183 Session Progress
        Line (\d): received 180 Ringing
        Line (\d): far end answered call.
        To: sip:0916770737@proxy2.idtbrasilhosted.com
        Line (\d): far end ended call.
        
        Error:
        
        Line (\d): call failed.
        404 Not Found
        480 Temporarily unavailable
        """
        # Call status
        messages = [
            'Line (\d): received (\d+) (\w+)',
            'Line (\d): far end (answered) call.'
            
        ]
        line, code, message = None, None, None
        _ = re.match(r"^Line (\d+):", stdout)
        if _:
            line = _.group(1)
        _ = re.match(r".(\d+) (\w+)", stdout)
        if _:
            code, message = _.group(1, 2)
            if code in CallStatusCode.__dict__.values():
                code = CallStatusCode(code).name
        if line:
            log.info(f'Line {line}: {code} {message}')
        return line, code, message

    def run(self):
        last_message = ''
        line_active = ''
        while True:
            stdout_line = self.proc.stdout.readline().decode('utf-8').strip()
            if stdout_line == '':
                continue
            if self.debug:
                log.debug(stdout_line)
            
            if 'Twinkle>' in stdout_line:
                log.info('Twinkle is active')
            if 'Failed' in stdout_line:
                log.error(stdout_line)

            self.handle_call_status(stdout_line)


def main():
    p = Phone(debug=True)
    while True:
        ask = input('>> ')
        if ask == 'quit':
            p.stop_twinkle()
            break
        elif ask == 'call':
            p.line(1)
            p.call('039959137')
        p.send_command(ask)

    

if __name__ == "__main__":
    main()
