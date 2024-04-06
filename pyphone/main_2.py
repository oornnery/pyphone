import asyncio
import pexpect
import re
import time
import signal
import logging
import json
from enum import Enum
from threading import Thread
from dataclasses import dataclass
from rich import print
from rich.logging import RichHandler
from rich.console import Console


console = Console()

logging.basicConfig(
    level="NOTSET",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, omit_repeated_times=False, console=console)],
)

log = logging.getLogger("rich")

class Phone(Thread):
    def __init__(self):
        self.running: bool = False
        self.dnd: bool = False
        self.mute: bool = False
        self.sip_uri: str = ''
        self.call_uri: str = ''
        self.call_id: str = ''
        self.sip_response: list[str] = []
        self.call_in_progress: bool = False
        self.call_in_established: bool = False
        self.codec_outgoing: str = ''
        self.codec_incoming: str = ''
        self.rtp_outgoing_ip: str = ''
        self.rtp_outgoing_port: str = ''
        self.rtp_incoming_ip: str = ''
        self.rtp_incoming_port: str = ''
        self.number_to_redial: str = ''
        self.accounts_sip: str = ''
        
        self.child = pexpect.spawn("baresip -v")
        is_ready = self.child.expect(["baresip is ready.", pexpect.EOF, pexpect.TIMEOUT])
        if is_ready == 0:
            self.running = True
            log.info(f"Baresip is ready. - {self.running}")
        super().__init__()
        self.start()
    
    def register(self, username: str, password: str, domain: str, port: str = 5060):
        if username == '' or password == '' or domain == '':
            return
        self.sip_uri = f'{username}@{domain}:{port}'
        self.child.sendline(f"/uanew <sip:{self.sip_uri}>;auth_pass={password}")
        time.sleep(1)
        self.register_info()
    
    def call(self, number):
        number = re.sub(r"\D", "", number)
        if number == '':
            return
        log.info(f"Calling to {number}")
        self.child.sendline(f"/dial {number}")
        self.call_in_progress = True
        self.number_to_redial = number
        time.sleep(1)
        
    def redial(self):
        self.call(self.number_to_redial)

    def hangup(self):
        self.child.sendline("/hangup")
        time.sleep(2)

    def mute(self):
        if not self.call_in_progress:
            log.error("Call not in progress to mute")
            return
        if self.mute:
            self.mute = False
        else:
            self.mute = True
        status = "yes" if self.mute else "no"
        self.child.sendline(f"/mute {status}")
        log.info(f"Set mute to {self.mute}")
        time.sleep(1)

    def dnd(self):
        if self.dnd:
            self.dnd = False
        else:
            self.dnd = True
        status = "yes" if self.dnd else "no"
        self.child.sendline(f"/dnd {status}")
        log.info(f"Set DND to {self.dnd}")
        time.sleep(1)
        
    def register_info(self):
        self.child.sendline("/apistate")
        time.sleep(1)
        return self.accounts_sip
        
    def quit(self):
        if self.running:
            if self.call_in_progress:
                self.hangup()
            self.running = False
        log.info(f"Quit bye - is running: {self.running}")
        self.child.sendline("/quit")
        self.child.close()
        self.join()
        self.child.kill(signal.SIGKILL)
    
    
    def handle_sip_account(self, line: str):
        if 'registered successfully!' in line:
            qtd_sip_account = re.search(r'All (\d+) useragent registered successfully!', line)
            if qtd_sip_account:
                qtd_sip_account = qtd_sip_account.group(1)
                log.info(f'SIP Register account: {qtd_sip_account}')
        if '{' in line:
            self.accounts_sip = line
            log.info(f'Accounts SIP: {line}')
            
    def handle_call_in_progress(self, line: str):
        if 'call uri:' in line:
            call_uri = re.search(r'call uri: (.*)', line)
            if call_uri:
                self.call_uri = call_uri.group(1)
                log.info(f'Call URI: {self.call_uri}')
        # Call id
        if 'call id:' in line:
            call_id = re.search(r'call id: (.*)', line)
            if call_id:
                self.call_id = call_id.group(1)
                log.info(f'Call ID: {self.call_id}')

        if 'call:' in line:
            # Call in progress
            call_connecting = re.search(r"'(sip:.*)'", line)
            if call_connecting:
                self.call_uri = call_connecting.group(1)
                log.info(f'Call connecting: {self.call_uri}')
            # SIP Response
            sip_response = re.search(r'call: SIP Progress: (.*)', line)
            if sip_response:
                self.sip_response.append(sip_response.group(1))
                log.info(f'SIP response: {self.sip_response[-1]}')
            # Call terminated
            call_terminate = re.search(r"call: terminate call '(.*)' with (sip:.*)", line)
            if call_terminate:
                if self.call_id == call_terminate.group(1):
                    self.call_in_progress = False
                    self.sip_response.append('BYE')
                log.info(f'Call terminated: {self.call_id} with {call_terminate.group(2)}')
        # Call answered
        if 'Call answered:' in line:
            call_answered = re.search(r'Call answered: (sip:.*)', line)
            if call_answered:
                if self.call_uri == call_answered.group(1):
                    self.call_in_progress = True
                log.info(f'Call answered: {self.call_uri} - {self.call_in_progress}')
        # Call established
        if 'Call established' in line:
            call_established = re.search(r'Call established: (sip:.*)', line)
            if call_established:
                if self.call_uri == call_established.group(1):
                    self.call_in_established = True
                log.info(f'Call established: {self.call_uri} - {self.call_in_established}')
        # Session close or hangup
        if 'session closed:' in line:
            # Session close
            session_close = re.search(r'(sip:.*): session closed: (.*)', line)
            if session_close:
                if self.call_uri == session_close.group(1):
                    self.call_in_progress = False
                    self.sip_response.append(session_close.group(2))
                log.info(f'Session close: {self.call_uri} - {self.sip_response[-1]}')
    def handle_stream_in_progress(self, line: str):
        if 'stream:' in line:
            # RTP outgoing
            rtp_outgoing_ip = re.search(fr'stream: audio: starting RTCP with remote (.*)', line)
            if rtp_outgoing_ip:
                rtp_ip, rtp_port = rtp_outgoing_ip.group(1).split(':')
                self.rtp_outgoing_ip = rtp_ip
                self.rtp_outgoing_port = rtp_port
                log.info(f'RTCP outgoing IP: {self.rtp_outgoing_ip}:{self.rtp_outgoing_port}')
            # RTP incoming
            rtp_incoming_ip = re.search(fr"stream: incoming rtp for 'audio' established, receiving from (.*)", line)
            if rtp_incoming_ip:
                rtp_ip, rtp_port = rtp_incoming_ip.group(1).split(':')
                self.rtp_incoming_ip = rtp_ip
                self.rtp_incoming_port = rtp_port
                log.info(f'RTCP incoming IP: {self.rtp_incoming_ip}:{self.rtp_incoming_port}')
    def handle_audio_in_progress(self, line: str):
        if 'audio:' in line:
            # Codec outgoing
            codec_outgoing = re.search(fr'audio: Set audio decoder: (.*)', line)
            if codec_outgoing:
                self.codec_outgoing = codec_outgoing.group(1)
                log.info(f'Codec outgoing: {self.codec_outgoing}')
            # Codec incoming
            codec_incoming = re.search(fr'audio: Set audio encoder: (.*)', line)
            if codec_incoming:
                self.codec_incoming = codec_incoming.group(1)
                log.info(f'Codec incoming: {self.codec_incoming}')

    def run(self):
        last_line: str = None
        self.running = True
        while self.running:
            try:
                line = self.child.readline().decode('utf-8').strip()
                if not line:
                    continue
                if line == last_line:
                    continue
                last_line = line
                # Handles
                self.handle_sip_account(line)
                self.handle_call_in_progress(line)
                self.handle_stream_in_progress(line)
                self.handle_audio_in_progress(line)
                # print(line)
            except pexpect.EOF:
                self.running = False
            except pexpect.TIMEOUT:
                pass
            except KeyboardInterrupt:
                self.quit()
                break
            else:
                last_line = line
            finally:
                pass


if __name__ == "__main__":
    from rich.prompt import Prompt
    from rich.progress import Progress
    
    phone = Phone()
    time.sleep(1)
    
    def register():
        username = Prompt.ask("Username", console=console)
        password = Prompt.ask("Password", console=console)
        domain = Prompt.ask("Domain", console=console)
        port = Prompt.ask("Port", console=console)
        phone.register(username, password, domain, port)
        time.sleep(1)
        phone.register_info()
        
    
    def call(n):
        phone.call(n)
        while True:
            time.sleep(3)
            if phone.call_in_established:
                ask = Prompt.ask("Do you want to hangup?", choices=['y', 'n'], console=console, default='n', show_default=True)
                if ask.lower() == 'y':
                    phone.hangup()
                    break
            if phone.call_in_progress == False:
                time.sleep(1)
                break
    register()
    console.print('Please enter phone number to call')
    numbers = Prompt.ask("Phone number", console=console)
    for number in numbers.split(','):
        ask = Prompt.ask(f"Do you want to call {number}?", choices=['y', 'n'], console=console, default='y', show_default=True)
        if ask.lower() == 'y':
            call(number)
        else:
            ask = Prompt.ask("Do you want to redial?", choices=['y', 'n'], console=console, default='y', show_default=True)
            if ask.lower() == 'y':
                phone.redial()
            break
    
    while phone.running:
        ask = Prompt.ask("Do you want to quit?", choices=['y', 'n'], console=console)
        if ask.lower() == 'y':
            phone.quit()