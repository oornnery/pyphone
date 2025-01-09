import socket
import time
import uuid
import threading
import logging
import base64
import hashlib
import re
import asyncio
from enum import Enum, IntEnum
from collections import defaultdict
from abc import ABC, abstractmethod
from typing import Callable, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SipMethod(Enum):
    INVITE = "INVITE"
    ACK = "ACK"
    BYE = "BYE"
    CANCEL = "CANCEL"
    REGISTER = "REGISTER"
    OPTIONS = "OPTIONS"
    INFO = "INFO"

class SipStatusCode(IntEnum):
    TRYING = 100
    RINGING = 180
    OK = 200
    UNAUTHORIZED = 401
    NOT_FOUND = 404
    SERVER_ERROR = 500

class DialogState(Enum):
    INIT = "INIT"
    EARLY = "EARLY"
    CONFIRMED = "CONFIRMED"
    TERMINATED = "TERMINATED"

class SipMessage:
    def __init__(self, method_or_status, uri_or_reason):
        self.is_request = isinstance(method_or_status, SipMethod)
        self.method = method_or_status if self.is_request else None
        self.status_code = int(method_or_status) if not self.is_request else None
        self.uri = uri_or_reason if self.is_request else None
        self.reason = uri_or_reason if not self.is_request else None
        self.headers = defaultdict(list)
        self.body = ""

    def add_header(self, name, value):
        self.headers[name].append(value)

    def get_header(self, name):
        return self.headers.get(name, [None])[0]

    def set_body(self, body):
        self.body = body

    def __str__(self):
        if self.is_request:
            start_line = f"{self.method.value} {self.uri} SIP/2.0\r\n"
        else:
            start_line = f"SIP/2.0 {self.status_code} {self.reason}\r\n"
        
        headers = "".join(f"{name}: {value}\r\n" for name, values in self.headers.items() for value in values)
        return f"{start_line}{headers}\r\n{self.body}"

class SipDialog:
    def __init__(self, call_id, local_tag, remote_tag):
        self.call_id = call_id
        self.local_tag = local_tag
        self.remote_tag = remote_tag
        self.state = DialogState.INIT
        self.local_seq = 0
        self.remote_seq = 0

    def update_state(self, new_state):
        logging.info(f"Dialog {self.call_id} state changed: {self.state} -> {new_state}")
        self.state = new_state

class SipTransaction:
    def __init__(self, request, client):
        self.request = request
        self.client = client
        self.response = None
        self.state = "TRYING"
        self.timer = asyncio.create_task(self.transaction_timer())

    async def transaction_timer(self):
        await asyncio.sleep(32)  # RFC 3261 recommends 32 seconds
        if self.state != "COMPLETED":
            logging.warning(f"Transaction {self.request.get_header('CSeq')} timed out")
            self.state = "TERMINATED"

    def receive_response(self, response):
        self.response = response
        if 200 <= response.status_code < 300:
            self.state = "COMPLETED"
        elif response.status_code >= 300:
            self.state = "COMPLETED"
            # Handle failure scenarios

class SdpMessage:
    def __init__(self):
        self.session_name = "-"
        self.connection_info = "IN IP4 127.0.0.1"
        self.media = []

    def add_media(self, type, port, protocol, formats):
        self.media.append(f"m={type} {port} {protocol} {' '.join(map(str, formats))}")

    def __str__(self):
        sdp = [
            "v=0",
            f"o=user1 {int(time.time())} {int(time.time())} IN IP4 127.0.0.1",
            f"s={self.session_name}",
            f"c={self.connection_info}",
            "t=0 0"
        ]
        sdp.extend(self.media)
        return "\r\n".join(sdp)

class RtpInterface(ABC):
    @abstractmethod
    def send_rtp_packet(self, payload):
        pass

    @abstractmethod
    def receive_rtp_packet(self):
        pass

class DummyRtpHandler(RtpInterface):
    def send_rtp_packet(self, payload):
        logging.info(f"Sending RTP packet: {payload}")

    def receive_rtp_packet(self):
        logging.info("Received RTP packet")
        return b"dummy_rtp_data"

class SipSocket:
    def __init__(self, local_ip, local_port):
        self.local_ip = local_ip
        self.local_port = local_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((local_ip, local_port))

    async def receive(self):
        return await asyncio.get_event_loop().sock_recvfrom(self.socket, 4096)

    async def send(self, message, addr):
        await asyncio.get_event_loop().sock_sendto(self.socket, str(message).encode('utf-8'), addr)

def sip_callback(event_type):
    def decorator(func):
        func._sip_callback = event_type
        return func
    return decorator

class SipClient:
    def __init__(self, local_ip, local_port, username, password):
        self.username = username
        self.password = password
        self.socket = SipSocket(local_ip, local_port)
        self.dialogs = {}
        self.transactions = {}
        self.cseq = 1
        self.event_loop = asyncio.get_event_loop()
        self.callbacks = defaultdict(list)
        self.rtp_handler = DummyRtpHandler()

        for name in dir(self):
            method = getattr(self, name)
            if hasattr(method, '_sip_callback'):
                self.callbacks[method._sip_callback].append(method)

    async def start(self):
        await self.event_loop.create_task(self.receive_messages())

    async def receive_messages(self):
        while True:
            data, addr = await self.socket.receive()
            message = self.parse_message(data.decode('utf-8'))
            await self.handle_message(message, addr)

    def parse_message(self, data):
        lines = data.split('\r\n')
        first_line = lines[0].split()
        
        if first_line[0] == 'SIP/2.0':
            message = SipMessage(SipStatusCode(int(first_line[1])), ' '.join(first_line[2:]))
        else:
            message = SipMessage(SipMethod(first_line[0]), first_line[1])
        
        for line in lines[1:]:
            if not line:
                break
            name, value = line.split(':', 1)
            message.add_header(name.strip(), value.strip())
        
        message.set_body('\r\n'.join(lines[lines.index('')+1:]))
        return message

    async def handle_message(self, message, addr):
        if message.is_request:
            await self.handle_request(message, addr)
        else:
            await self.handle_response(message, addr)

    async def handle_request(self, request, addr):
        logging.info(f"Received request: {request.method}")
        for callback in self.callbacks[request.method]:
            await callback(request, addr)

    async def handle_response(self, response, addr):
        logging.info(f"Received response: {response.status_code}")
        transaction = self.transactions.get(response.get_header('CSeq'))
        if transaction:
            transaction.receive_response(response)
        
        for callback in self.callbacks[response.status_code]:
            await callback(response, addr)

    def create_request(self, method, uri):
        request = SipMessage(method, uri)
        call_id = str(uuid.uuid4())
        from_tag = str(uuid.uuid4())
        branch = f"z9hG4bK-{uuid.uuid4()}"
        
        request.add_header("Via", f"SIP/2.0/UDP {self.socket.local_ip}:{self.socket.local_port};branch={branch}")
        request.add_header("From", f"<sip:{self.username}@{self.socket.local_ip}>;tag={from_tag}")
        request.add_header("To", f"<{uri}>")
        request.add_header("Call-ID", call_id)
        request.add_header("CSeq", f"{self.cseq} {method.value}")
        request.add_header("Contact", f"<sip:{self.username}@{self.socket.local_ip}:{self.socket.local_port}>")
        
        self.cseq += 1
        return request

    def create_response(self, request, status_code, reason):
        response = SipMessage(status_code, reason)
        for header in ['Via', 'From', 'To', 'Call-ID', 'CSeq']:
            if header in request.headers:
                response.add_header(header, request.get_header(header))
        response.add_header("Contact", f"<sip:{self.username}@{self.socket.local_ip}:{self.socket.local_port}>")
        return response

    def create_ack(self, response):
        ack = SipMessage(SipMethod.ACK, response.get_header('Contact')[1:-1].split(';')[0])
        ack.add_header("Via", response.get_header('Via'))
        ack.add_header("From", response.get_header('From'))
        ack.add_header("To", response.get_header('To'))
        ack.add_header("Call-ID", response.get_header('Call-ID'))
        cseq = response.get_header('CSeq').split()[0]
        ack.add_header("CSeq", f"{cseq} ACK")
        return ack

    def add_auth_header(self, request, auth_header):
        auth_match = re.match(r'Digest realm="([^"]+)",\s*nonce="([^"]+)"', auth_header)
        if auth_match:
            realm, nonce = auth_match.groups()
            ha1 = hashlib.md5(f"{self.username}:{realm}:{self.password}".encode()).hexdigest()
            ha2 = hashlib.md5(f"{request.method.value}:{request.uri}".encode()).hexdigest()
            response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
            
            auth_response = (f'Digest username="{self.username}", realm="{realm}", nonce="{nonce}", '
                             f'uri="{request.uri}", response="{response}", algorithm=MD5')
            request.add_header("Authorization", auth_response)
        return request

    async def send_message(self, message, addr):
        logging.info(f"Sending: {message.method if message.is_request else message.status_code}")
        await self.socket.send(message, addr)
        
        if message.is_request:
            transaction = SipTransaction(message, self)
            self.transactions[message.get_header('CSeq')] = transaction

    @sip_callback(SipMethod.INVITE)
    async def handle_invite(self, request, addr):
        response = self.create_response(request, SipStatusCode.RINGING, "Ringing")
        await self.send_message(response, addr)
        # Simulate answering after 2 seconds
        await asyncio.sleep(2)
        response = self.create_response(request, SipStatusCode.OK, "OK")
        sdp = SdpMessage()
        sdp.add_media("audio", 5004, "RTP/AVP", [0])
        response.set_body(str(sdp))
        await self.send_message(response, addr)

    @sip_callback(SipMethod.BYE)
    async def handle_bye(self, request, addr):
        response = self.create_response(request, SipStatusCode.OK, "OK")
        await self.send_message(response, addr)

    @sip_callback(SipStatusCode.OK)
    async def handle_200_ok(self, response, addr):
        logging.info("Call established successfully")
        if response.get_header('CSeq').split()[1] == 'INVITE':
            ack = self.create_ack(response)
            await self.send_message(ack, addr)

    @sip_callback(SipStatusCode.UNAUTHORIZED)
    async def handle_401_unauthorized(self, response, addr):
        original_request = self.transactions[response.get_header('CSeq')].request
        new_request = self.add_auth_header(original_request, response.get_header('WWW-Authenticate'))
        await self.send_message(new_request, addr)

    async def invite(self, uri):
        invite = self.create_request(SipMethod.INVITE, uri)
        sdp = SdpMessage()
        sdp.add_media("audio", 5004, "RTP/AVP", [0])
        invite.set_body(str(sdp))
        await self.send_message(invite, (uri.split('@')[1], 5060))

    async def register(self, registrar):
        register = self.create_request(SipMethod.REGISTER, f"sip:{registrar}")
        register.add_header("Expires", "3600")
        await self.send_message(register, (registrar, 5060))

    async def bye(self, uri):
        bye = self.create_request(SipMethod.BYE, uri)
        await self.send_message(bye, (uri.split('@')[1], 5060))

    async def cancel(self, uri):
        cancel = self.create_request(SipMethod.CANCEL, uri)
        await self.send_message(cancel, (uri.split('@')[1], 5060))

    async def options(self, uri):
        options = self.create_request(SipMethod.OPTIONS, uri)
        await self.send_message(options, (uri.split('@')[1], 5060))

    async def info(self, uri, dtmf):
        info = self.create_request(SipMethod.INFO, uri)
        info.add_header("Content-Type", "application/dtmf-relay")
        info.set_body(f"Signal={dtmf}\nDuration=250")
        await self.send_message(info, (uri.split('@')[1], 5060))

    def send_dtmf(self, uri, digit):
        info = self.create_request(SipMethod.INFO, uri)
        info.add_header("Content-Type", "application/dtmf-relay")
        info.set_body(f"Signal={digit}\nDuration=250")
        asyncio.create_task(self.send_message(info, (uri.split('@')[1], 5060)))

    @sip_callback(SipMethod.INFO)
    async def handle_info(self, request, addr):
        if request.get_header('Content-Type') == 'application/dtmf-relay':
            dtmf = re.search(r'Signal=(\d)', request.body)
            if dtmf:
                logging.info(f"Received DTMF: {dtmf.group(1)}")
        response = self.create_response(request, SipStatusCode.OK, "OK")
        await self.send_message(response, addr)

    def start_rtp_stream(self, remote_ip, remote_port):
        # This is a placeholder for RTP stream initialization
        logging.info(f"Starting RTP stream to {remote_ip}:{remote_port}")
        # Here you would typically start a new thread or task to handle RTP packets

    def stop_rtp_stream(self):
        # This is a placeholder for stopping the RTP stream
        logging.info("Stopping RTP stream")
        # Here you would typically signal the RTP handling thread or task to stop

async def main():
    client = SipClient("127.0.0.1", 5060, "user", "password")
    
    await client.start()
    await client.register("example.com")
    await client.invite("sip:bob@example.com")
    
    # Simulate sending DTMF after 5 seconds
    await asyncio.sleep(5)
    client.send_dtmf("sip:bob@example.com", "5")
    
    # Keep the event loop running
    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
