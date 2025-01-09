import socket
import time
import uuid
import logging
import base64
import hashlib
import re
import asyncio
from enum import Enum, IntEnum
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SipMethod(Enum):
    INVITE = "INVITE"
    ACK = "ACK"
    BYE = "BYE"
    CANCEL = "CANCEL"
    REGISTER = "REGISTER"
    OPTIONS = "OPTIONS"
    INFO = "INFO"
    SUBSCRIBE = "SUBSCRIBE"
    NOTIFY = "NOTIFY"

class SipStatusCode(IntEnum):
    TRYING = 100
    RINGING = 180
    OK = 200
    UNAUTHORIZED = 401
    NOT_FOUND = 404
    REQUEST_TIMEOUT = 408
    INTERNAL_SERVER_ERROR = 500

class DialogState(Enum):
    INIT = "INIT"
    EARLY = "EARLY"
    CONFIRMED = "CONFIRMED"
    TERMINATED = "TERMINATED"

class SipRequest:
    def __init__(self, method, uri):
        self.method = method
        self.uri = uri
        self.headers = defaultdict(list)
        self.body = ""

    def add_header(self, name, value):
        self.headers[name].append(value)

    def get_header(self, name):
        return self.headers.get(name, [None])[0]

    def set_body(self, body):
        self.body = body

    def __str__(self):
        start_line = f"{self.method.value} {self.uri} SIP/2.0\r\n"
        headers = "".join(f"{name}: {value}\r\n" for name, values in self.headers.items() for value in values)
        return f"{start_line}{headers}\r\n{self.body}"

class SipResponse:
    def __init__(self, status_code, reason):
        self.status_code = status_code
        self.reason = reason
        self.headers = defaultdict(list)
        self.body = ""

    def add_header(self, name, value):
        self.headers[name].append(value)

    def get_header(self, name):
        return self.headers.get(name, [None])[0]

    def set_body(self, body):
        self.body = body

    def __str__(self):
        start_line = f"SIP/2.0 {self.status_code.value} {self.reason}\r\n"
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
        self.state = "TRYING"
        self.responses = []
        self.timer = None

    async def start(self):
        self.timer = asyncio.create_task(self.transaction_timer())
        await self.client.send_message(self.request, (self.request.uri.split('@')[1], 5060))

    async def transaction_timer(self):
        await asyncio.sleep(32)  # RFC 3261 recommends 32 seconds
        if self.state != "COMPLETED":
            logging.warning(f"Transaction {self.request.get_header('CSeq')} timed out")
            self.state = "TERMINATED"

    def add_response(self, response):
        self.responses.append(response)
        if 200 <= response.status_code.value < 300:
            self.state = "COMPLETED"
            if self.timer:
                self.timer.cancel()

class SipClient:
    def __init__(self, local_ip, local_port, username, password):
        self.local_ip = local_ip
        self.local_port = local_port
        self.username = username
        self.password = password
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((local_ip, local_port))
        self.dialogs = {}
        self.transactions = {}
        self.cseq = 1
        self.event_loop = asyncio.get_event_loop()
        self.callbacks = defaultdict(list)

    async def start(self):
        await self.event_loop.create_task(self.receive_messages())

    async def receive_messages(self):
        while True:
            data, addr = await self.event_loop.sock_recvfrom(self.socket, 4096)
            message = self.parse_message(data.decode('utf-8'))
            await self.handle_message(message, addr)

    def parse_message(self, data):
        lines = data.split('\r\n')
        first_line = lines[0].split()
        if first_line[0] == 'SIP/2.0':
            message = SipResponse(SipStatusCode(int(first_line[1])), ' '.join(first_line[2:]))
        else:
            message = SipRequest(SipMethod(first_line[0]), first_line[1])

        for line in lines[1:]:
            if not line:
                break
            name, value = line.split(':', 1)
            message.add_header(name.strip(), value.strip())

        message.set_body('\r\n'.join(lines[lines.index('')+1:]))
        return message

    async def handle_message(self, message, addr):
        if isinstance(message, SipRequest):
            await self.handle_request(message, addr)
        else:
            await self.handle_response(message, addr)

    async def handle_request(self, request, addr):
        logging.info(f"Received request: {request.method}")
        if request.method == SipMethod.INVITE:
            response = self.create_response(request, SipStatusCode.RINGING, "Ringing")
            await self.send_message(response, addr)
            # Simulate answering after 2 seconds
            await asyncio.sleep(2)
            response = self.create_response(request, SipStatusCode.OK, "OK")
            await self.send_message(response, addr)
        elif request.method == SipMethod.BYE:
            response = self.create_response(request, SipStatusCode.OK, "OK")
            await self.send_message(response, addr)
        elif request.method == SipMethod.CANCEL:
            response = self.create_response(request, SipStatusCode.OK, "OK")
            await self.send_message(response, addr)
        elif request.method == SipMethod.OPTIONS:
            response = self.create_response(request, SipStatusCode.OK, "OK")
            await self.send_message(response, addr)
        elif request.method == SipMethod.INFO:
            response = self.create_response(request, SipStatusCode.OK, "OK")
            await self.send_message(response, addr)
        elif request.method == SipMethod.SUBSCRIBE:
            response = self.create_response(request, SipStatusCode.OK, "OK")
            await self.send_message(response, addr)
        elif request.method == SipMethod.NOTIFY:
            response = self.create_response(request, SipStatusCode.OK, "OK")
            await self.send_message(response, addr)

    async def handle_response(self, response, addr):
        logging.info(f"Received response: {response.status_code}")
        transaction = self.transactions.get(response.get_header('CSeq'))
        if transaction:
            transaction.add_response(response)
            if 200 <= response.status_code.value < 300:
                if transaction.request.method == SipMethod.INVITE:
                    ack = self.create_ack(response)
                    await self.send_message(ack, addr)
            elif response.status_code == SipStatusCode.UNAUTHORIZED:
                if 'WWW-Authenticate' in response.headers:
                    auth_header = response.get_header('WWW-Authenticate')
                    new_request = self.add_auth_header(transaction.request, auth_header)
                    await self.send_message(new_request, addr)

        for callback in self.callbacks[response.status_code]:
            callback(response)

    def create_request(self, method, uri):
        request = SipRequest(method, uri)
        call_id = str(uuid.uuid4())
        from_tag = str(uuid.uuid4())
        branch = f"z9hG4bK-{uuid.uuid4()}"

        request.add_header("Via", f"SIP/2.0/UDP {self.local_ip}:{self.local_port};branch={branch}")
        request.add_header("From", f"<sip:{self.username}@{self.local_ip}>;tag={from_tag}")
        request.add_header("To", f"<{uri}>")
        request.add_header("Call-ID", call_id)
        request.add_header("CSeq", f"{self.cseq} {method.value}")
        request.add_header("Contact", f"<sip:{self.username}@{self.local_ip}:{self.local_port}>")

        self.cseq += 1
        return request

    def create_response(self, request, status_code, reason):
        response = SipResponse(status_code, reason)
        for header in ['Via', 'From', 'To', 'Call-ID', 'CSeq']:
            if header in request.headers:
                response.add_header(header, request.get_header(header))
        response.add_header("Contact", f"<sip:{self.username}@{self.local_ip}:{self.local_port}>")
        return response

    def create_ack(self, response):
        ack = SipRequest(SipMethod.ACK, response.get_header('Contact')[1:-1].split(';')[0])
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
        logging.info(f"Sending: {message.method if isinstance(message, SipRequest) else message.status_code}")
        await self.event_loop.sock_sendto(self.socket, str(message).encode('utf-8'), addr)

        if isinstance(message, SipRequest):
            transaction = SipTransaction(message, self)
            self.transactions[message.get_header('CSeq')] = transaction
            await transaction.start()

    def add_callback(self, status_code, callback):
        self.callbacks[status_code].append(callback)

    async def invite(self, uri):
        invite = self.create_request(SipMethod.INVITE, uri)
        invite.set_body("v=0\r\no=user1 53655765 2353687637 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n")
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

    async def info(self, uri):
        info = self.create_request(SipMethod.INFO, uri)
        await self.send_message(info, (uri.split('@')[1], 5060))

    async def subscribe(self, uri):
        subscribe = self.create_request(SipMethod.SUBSCRIBE, uri)
        subscribe.add_header("Event", "presence")
        subscribe.add_header("Expires", "3600")
        await self.send_message(subscribe, (uri.split('@')[1], 5060))

    async def notify(self, uri):
        notify = self.create_request(SipMethod.NOTIFY, uri)
        notify.add_header("Event", "presence")
        notify.add_header("Subscription-State", "active")
        await self.send_message(notify, (uri.split('@')[1], 5060))

async def main():
    client = SipClient("127.0.0.1", 5060, "user", "password")

    def on_200_ok(response):
        logging.info("Call established successfully")

    client.add_callback(SipStatusCode.OK, on_200_ok)

    await client.start()
    await client.register("example.com")
    await client.invite("sip:bob@example.com")

    # Keep the event loop running
    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
