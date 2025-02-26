import socket
import logging
import uuid
import random
import struct
import hashlib
import time
from enum import Enum


class Transport:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    def send(self, message, address):
        self.socket.sendto(message.encode(), address)
    
    def receive(self, buffer_size=4096):
        data, addr = self.socket.recvfrom(buffer_size)
        return data.decode(), addr

    def close(self):
        self.socket.close()



class SDP:
    def __init__(self):
        self.session_id = str(uuid.uuid4())
        self.session_version = 0
        self.media = []

    def generate_offer(self, ip, port, codecs):
        sdp = [
            "v=0",
            f"o=- {self.session_id} {self.session_version} IN IP4 {ip}",
            "s=Pyphone Session",
            f"c=IN IP4 {ip}",
            "t=0 0",
            f"m=audio {port} RTP/AVP {' '.join(str(c) for c in codecs)}",
        ]
        for codec in codecs:
            sdp.append(f"a=rtpmap:{codec} PCMU/8000")
        return "\r\n".join(sdp)

    def parse_offer(self, sdp_str):
        lines = sdp_str.split("\r\n")
        parsed = {}
        for line in lines:
            if line.startswith("m="):
                parsed["media"] = line.split()[1:]
            elif line.startswith("c="):
                parsed["connection"] = line.split()[2]
        return parsed

    def generate_answer(self, offer):
        # Simplified answer generation
        return self.generate_offer(offer["connection"], offer["media"][1], [0])

    def negotiate(self, offer, answer):
        # Simplified negotiation
        offer_codecs = set(offer["media"][3:])
        answer_codecs = set(answer["media"][3:])
        return list(offer_codecs.intersection(answer_codecs))



class RTP:
    def __init__(self, payload_type, ssrc=None):
        self.version = 2
        self.padding = 0
        self.extension = 0
        self.csrc_count = 0
        self.marker = 0
        self.payload_type = payload_type
        self.sequence_number = random.randint(0, 65535)
        self.timestamp = random.randint(0, 2**32 - 1)
        self.ssrc = ssrc or random.randint(0, 2**32 - 1)

    def create_packet(self, payload):
        header = struct.pack(
            "!BBHII",
            (self.version << 6) | (self.padding << 5) | (self.extension << 4) | self.csrc_count,
            (self.marker << 7) | self.payload_type,
            self.sequence_number,
            self.timestamp,
            self.ssrc
        )
        return header + payload

    def parse_packet(self, packet):
        header = struct.unpack("!BBHII", packet[:12])
        payload = packet[12:]
        return {
            "version": header[0] >> 6,
            "padding": (header[0] >> 5) & 1,
            "extension": (header[0] >> 4) & 1,
            "csrc_count": header[0] & 0xF,
            "marker": header[1] >> 7,
            "payload_type": header[1] & 0x7F,
            "sequence_number": header[2],
            "timestamp": header[3],
            "ssrc": header[4],
            "payload": payload
        }

class DTMF:
    def __init__(self):
        self.dtmf_payload_type = 101
        self.event_codes = {
            '0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7,
            '8': 8, '9': 9, '*': 10, '#': 11, 'A': 12, 'B': 13, 'C': 14, 'D': 15
        }

    def create_event(self, digit, duration=160, volume=10):
        event = self.event_codes.get(digit, 0)
        return struct.pack("!BBBB", event, 0x80 | volume, (duration >> 8) & 0xFF, duration & 0xFF)

    def parse_event(self, payload):
        event, volume_end, duration_high, duration_low = struct.unpack("!BBBB", payload[:4])
        return {
            "event": event,
            "end": bool(volume_end & 0x80),
            "volume": volume_end & 0x3F,
            "duration": (duration_high << 8) | duration_low
        }



class Codec:
    @staticmethod
    def ulaw_encode(pcm_data):
        # return audioop.lin2ulaw(pcm_data, 2)
        return 'Not implemented yet'

    @staticmethod
    def ulaw_decode(ulaw_data):
        # return audioop.ulaw2lin(ulaw_data, 2)
        return 'Not implemented yet'

    @staticmethod
    def alaw_encode(pcm_data):
        # return audioop.lin2alaw(pcm_data, 2)
        return 'Not implemented yet'

    @staticmethod
    def alaw_decode(alaw_data):
        # return audioop.alaw2lin(alaw_data, 2)
        return 'Not implemented yet'

class DialogState(Enum):
    INIT = 0
    EARLY = 1
    CONFIRMED = 2
    TERMINATED = 3

class Dialog:
    def __init__(self, local_tag, remote_tag, call_id):
        self.local_tag = local_tag
        self.remote_tag = remote_tag
        self.call_id = call_id
        self.state = DialogState.INIT
        self.local_seq = 0
        self.remote_seq = 0

    def update_state(self, new_state):
        self.state = new_state

    def increment_local_seq(self):
        self.local_seq += 1
        return self.local_seq

    def set_remote_seq(self, seq):
        self.remote_seq = seq

class TransactionState(Enum):
    TRYING = 0
    PROCEEDING = 1
    COMPLETED = 2
    TERMINATED = 3

class Transaction:
    def __init__(self, method, branch):
        self.method = method
        self.branch = branch
        self.state = TransactionState.TRYING
        self.dialog = None

    def set_dialog(self, dialog):
        self.dialog = dialog

    def update_state(self, new_state):
        self.state = new_state

class Session:
    def __init__(self):
        self.dialogs = {}
        self.transactions = {}

    def create_dialog(self, local_tag, remote_tag, call_id):
        dialog = Dialog(local_tag, remote_tag, call_id)
        self.dialogs[call_id] = dialog
        return dialog

    def get_dialog(self, call_id):
        return self.dialogs.get(call_id)

    def create_transaction(self, method, branch):
        transaction = Transaction(method, branch)
        self.transactions[branch] = transaction
        return transaction

    def get_transaction(self, branch):
        return self.transactions.get(branch)




class SIPMessage:
    def __init__(self, start_line: str, headers: dict, body: str = ""):
        self.start_line = start_line
        self.headers = headers
        self.body = body

    @property
    def is_request(self):
        return not self.start_line.startswith("SIP/2.0")

    @property
    def is_response(self):
        return self.start_line.startswith("SIP/2.0")

    @classmethod
    def request(cls, method: str, uri: str, headers: dict, body: str = "") -> 'SIPMessage':
        start_line = f"{method} {uri} SIP/2.0"
        return cls(start_line, headers, body)

    @classmethod
    def response(cls, status_code: int, reason: str, headers: dict, body: str = "") -> 'SIPMessage':
        start_line = f"SIP/2.0 {status_code} {reason}"
        return cls(start_line, headers, body)

    @classmethod
    def parse(cls, message: str) -> 'SIPMessage':
        lines = message.split("\r\n")
        start_line = lines[0]
        headers = {}
        body = ""
        body_start = False
        for line in lines[1:]:
            if line == "":
                body_start = True
                continue
            if body_start:
                body += line + "\r\n"
            else:
                name, value = line.split(":", 1)
                headers[name.strip()] = value.strip()
        return cls(start_line, headers, body.strip())

    def __str__(self):
        headers_str = "\r\n".join([f"{k}: {v}" for k, v in self.headers.items()])
        return f"{self.start_line}\r\n{headers_str}\r\n\r\n{self.body}"

    def generate_auth_response(self, username: str, password: str, method: str, uri: str) -> str:
        auth_header = self.headers.get('WWW-Authenticate', '')
        if not auth_header:
            return ""

        auth_parts = dict(part.split('=', 1) for part in auth_header.split(','))
        realm = auth_parts.get('realm', '').strip('"')
        nonce = auth_parts.get('nonce', '').strip('"')

        ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()

        return f'Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{response}"'

class SIP:
    def __init__(self, uri: str, conn: Transport):
        self.uri = uri
        self.conn = conn
        self.username = uri.split(':')[1].split('@')[0]
        self.domain = uri.split('@')[1]
        self.call_id = f"{int(time.time())}@{self.domain}"
        self.cseq = 1

    def register(self, registrar: str, expires: int = 3600, auth_info: tuple = None) -> SIPMessage:
        headers = {
            "Via": f"SIP/2.0/UDP {self.conn.host};branch=z9hG4bK{int(time.time())}",
            "Max-Forwards": "70",
            "To": f"<sip:{self.uri}>",
            "From": f"<sip:{self.uri}>;tag={int(time.time())}",
            "Call-ID": self.call_id,
            "CSeq": f"{self.cseq} REGISTER",
            "Contact": f"<sip:{self.uri}>",
            "Expires": str(expires),
            "User-Agent": "Pyphone/1.0",
            "Content-Length": "0"
        }

        if auth_info:
            username, password = auth_info
            headers["Authorization"] = self.generate_auth_header(username, password, "REGISTER", f"sip:{self.domain}")

        register_msg = SIPMessage.request("REGISTER", f"sip:{registrar}", headers)
        self.conn.send(str(register_msg), (registrar.split(':')[0], int(registrar.split(':')[1])))
        response, _ = self.conn.receive()
        response_msg = SIPMessage.parse(response)

        if response_msg.start_line.split()[1] == "401":
            if not auth_info:
                raise ValueError("Authentication required but no credentials provided")
            
            username, password = auth_info
            auth_response = response_msg.generate_auth_response(username, password, "REGISTER", f"sip:{self.domain}")
            headers["Authorization"] = auth_response
            headers["CSeq"] = f"{self.cseq + 1} REGISTER"
            self.cseq += 1

            register_msg = SIPMessage.request("REGISTER", f"sip:{registrar}", headers)
            self.conn.send(str(register_msg), (registrar.split(':')[0], int(registrar.split(':')[1])))
            response, _ = self.conn.receive()
            response_msg = SIPMessage.parse(response)

        return response_msg

    def generate_auth_header(self, username: str, password: str, method: str, uri: str) -> str:
        realm = self.domain
        nonce = hashlib.md5(str(time.time()).encode()).hexdigest()
        ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        return f'Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{response}"'

class Pyphone:
    def __init__(self, uri, transport):
        self.uri = uri
        self.transport = transport
        self.sip = SIP(uri, transport)
        self.session = Session()
        self.sdp = SDP()
        self.rtp = RTP(0)  # 0 for PCMU
        self.dtmf = DTMF()
        self.codec = Codec()

    def register(self, registrar, expires=3600):
        register_msg = self.sip.register(registrar, expires)
        self.transport.send(str(register_msg), (registrar.split(':')[0], int(registrar.split(':')[1])))
        response, _ = self.transport.receive()
        return SIPMessage.parser_message(response)

    def invite(self, to_uri):
        invite_msg = self.sip.invite(to_uri)
        sdp_offer = self.sdp.generate_offer(self.transport.host, self.transport.port, [0])  # 0 for PCMU
        invite_msg.body = sdp_offer
        self.transport.send(str(invite_msg), (to_uri.split(':')[0], int(to_uri.split(':')[1])))
        response, _ = self.transport.receive()
        return SIPMessage.parser_message(response)

    def options(self, to_uri):
        options_msg = self.sip.options(to_uri)
        self.transport.send(str(options_msg), (to_uri.split(':')[0], int(to_uri.split(':')[1])))
        response, _ = self.transport.receive()
        return SIPMessage.parser_message(response)

    def send_dtmf(self, digit):
        dtmf_event = self.dtmf.create_event(digit)
        rtp_packet = self.rtp.create_packet(dtmf_event)
        self.transport.send(rtp_packet, (self.transport.host, self.transport.port))

    def close(self):
        self.transport.close()


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_mizu_voip():
    mizu_server = "demo.mizu-voip.com:37075"
    local_ip = "0.0.0.0"  # Use your actual local IP
    local_port = 5060

    transport = Transport(local_ip, local_port)
    pyphone = Pyphone(f"sip:testuser@{local_ip}:{local_port}", transport)

    # Test REGISTER
    logger.info("Testing REGISTER...")
    register_response = pyphone.register(mizu_server)
    logger.info(f"REGISTER response: {register_response.start_line}")

    # Test OPTIONS
    logger.info("Testing OPTIONS...")
    options_response = pyphone.options(mizu_server)
    logger.info(f"OPTIONS response: {options_response.start_line}")

    # Test INVITE
    logger.info("Testing INVITE...")
    invite_response = pyphone.invite(f"sip:echo@{mizu_server}")
    logger.info(f"INVITE response: {invite_response.start_line}")

    # Close the connection
    pyphone.close()

if __name__ == "__main__":
    test_mizu_voip()
