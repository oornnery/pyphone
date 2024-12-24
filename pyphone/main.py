import uuid
import time
import socket
import struct
import threading
import ssl
import math
import logging
from enum import Enum
import functools
import asyncio
import os
from abc import ABC, abstractmethod
from typing import Dict, Optional, List, Callable


class SDPMediaDescription:
    def __init__(self, media_type: str, port: int, protocol: str, formats: List[str]):
        self.media_type = media_type
        self.port = port
        self.protocol = protocol
        self.formats = formats

    def __str__(self):
        return f"m={self.media_type} {self.port} {self.protocol} {' '.join(self.formats)}"

class SDPMessage:
    def __init__(self, version: str = "0", origin: str = "", session_name: str = "", connection: str = "", time: str = "0 0", media: List[str] = None):
        self.version = version
        self.origin = origin
        self.session_name = session_name
        self.connection = connection
        self.time = time
        self.media = [SDPMediaDescription(*m.split(' ', 3)) for m in (media or [])]

    def __str__(self):
        lines = [
            f"v={self.version}",
            f"o={self.origin}",
            f"s={self.session_name}",
            f"c={self.connection}",
            f"t={self.time}"
        ]
        for media in self.media:
            lines.append(str(media))
        return "\r\n".join(lines)

    @classmethod
    def parse(cls, sdp_string: str):
        lines = sdp_string.split("\r\n")
        sdp = cls()
        media = []
        for line in lines:
            match line:
                case line if line.startswith("v="):
                    sdp.version = line[2:]
                case line if line.startswith("o="):
                    sdp.origin = line[2:]
                case line if line.startswith("s="):
                    sdp.session_name = line[2:]
                case line if line.startswith("c="):
                    sdp.connection = line[2:]
                case line if line.startswith("t="):
                    sdp.time = line[2:]
                case line if line.startswith("m="):
                    media.append(line[2:])
        sdp.media = media
        return sdp

class HeaderField:
    def __init__(self, key: str, value: str):
        self.key = key
        self.value = value

    def __str__(self):
        return f"{self.key}: {self.value}"

class DTMFGenerator:
    def __init__(self, sample_rate: int = 8000):
        self.sample_rate = sample_rate
        self.dtmf_freqs = {
            '1': (697, 1209), '2': (697, 1336), '3': (697, 1477),
            '4': (770, 1209), '5': (770, 1336), '6': (770, 1477),
            '7': (852, 1209), '8': (852, 1336), '9': (852, 1477),
            '*': (941, 1209), '0': (941, 1336), '#': (941, 1477),
            'A': (697, 1633), 'B': (770, 1633), 'C': (852, 1633), 'D': (941, 1633)
        }

    def generate_tone(self, digit: str, duration: float = 0.1) -> bytes:
        if digit not in self.dtmf_freqs:
            raise ValueError(f"Invalid DTMF digit: {digit}")

        f1, f2 = self.dtmf_freqs[digit]
        samples = int(self.sample_rate * duration)
        tone = bytearray(samples * 2)

        for i in range(samples):
            t = i / self.sample_rate
            sample = int(32767 * 0.5 * (math.sin(2 * math.pi * f1 * t) + math.sin(2 * math.pi * f2 * t)))
            struct.pack_into("<h", tone, i * 2, sample)

        return bytes(tone)

class DTMFDetector:
    def __init__(self, sample_rate: int = 8000):
        self.sample_rate = sample_rate
        self.dtmf_freqs = {
            (697, 1209): '1', (697, 1336): '2', (697, 1477): '3',
            (770, 1209): '4', (770, 1336): '5', (770, 1477): '6',
            (852, 1209): '7', (852, 1336): '8', (852, 1477): '9',
            (941, 1209): '*', (941, 1336): '0', (941, 1477): '#',
            (697, 1633): 'A', (770, 1633): 'B', (852, 1633): 'C', (941, 1633): 'D'
        }

    def detect(self, audio_data: bytes) -> Optional[str]:
        # Implement Goertzel algorithm for DTMF detection
        # This is a simplified version and may need improvement for real-world use
        samples = struct.unpack(f"<{len(audio_data)//2}h", audio_data)
        freqs = [697, 770, 852, 941, 1209, 1336, 1477, 1633]
        detected = []

        for freq in freqs:
            coeff = 2 * math.cos(2 * math.pi * freq / self.sample_rate)
            s_prev = 0
            s_prev2 = 0
            for sample in samples:
                s = sample + coeff * s_prev - s_prev2
                s_prev2 = s_prev
                s_prev = s
            power = s_prev2 * s_prev2 + s_prev * s_prev - coeff * s_prev * s_prev2
            if power > 1e6:  # Threshold may need adjustment
                detected.append(freq)

        if len(detected) == 2:
            low_freq = min(detected)
            high_freq = max(detected)
            return self.dtmf_freqs.get((low_freq, high_freq))

        return None

class SIPMethod(Enum):
    INVITE = "INVITE"
    ACK = "ACK"
    BYE = "BYE"
    CANCEL = "CANCEL"
    REGISTER = "REGISTER"
    OPTIONS = "OPTIONS"
    INFO = "INFO"
    MESSAGE = "MESSAGE"

class SIPStatusCode(Enum):
    OK = (200, "OK")
    RINGING = (180, "Ringing")
    TRYING = (100, "Trying")
    BAD_REQUEST = (400, "Bad Request")
    UNAUTHORIZED = (401, "Unauthorized")
    NOT_FOUND = (404, "Not Found")
    REQUEST_TIMEOUT = (408, "Request Timeout")
    INTERNAL_SERVER_ERROR = (500, "Internal Server Error")

    def __init__(self, code, reason):
        self.code = code
        self.reason = reason


class SIPMessage:
    def __init__(self, method: Optional[SIPMethod] = None, status: Optional[SIPStatusCode] = None, uri: Optional[str] = None, headers: Dict[str, str] = None, body: Optional[str] = None):
        self.method = method
        self.status = status
        self.uri = uri
        self.headers = headers or {}
        self.body = body

    def serialize(self) -> bytes:
        lines = []
        if self.method:
            lines.append(f"{self.method.value} {self.uri} SIP/2.0")
        elif self.status:
            lines.append(f"SIP/2.0 {self.status.code} {self.status.reason}")
        for key, value in self.headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        if self.body:
            lines.append(self.body)
        return "\r\n".join(lines).encode()

    @classmethod
    def deserialize(cls, data: bytes):
        lines = data.decode().split("\r\n")
        first_line = lines.pop(0)
        headers = {}
        body = None
        if first_line.startswith("SIP/2.0"):
            method, uri = None, None
            status = next((s for s in SIPStatusCode if str(s.code) in first_line), None)
        else:
            method, uri, _ = first_line.split(" ", 2)
            status = None
        for line in lines:
            if not line:
                body = "\r\n".join(lines[lines.index(line) + 1:])
                break
            key, value = line.split(": ", 1)
            headers[key] = value
        return cls(
            method=SIPMethod(method) if method else None,
            status=status,
            uri=uri,
            headers=headers,
            body=body
        )

class SIPDialog:
    def __init__(self, call_id: str, local_uri: str, remote_uri: str):
        self.call_id = call_id
        self.local_uri = local_uri
        self.remote_uri = remote_uri
        self.state = "INIT"
        self.local_seq = 0
        self.remote_seq = 0

    def update_state(self, new_state: str):
        log.info(f"Dialog {self.call_id} state changed from {self.state} to {new_state}")
        self.state = new_state

class SIPException(Exception):
    pass

class RTPPacket:
    def __init__(self, payload_type: int, sequence_number: int, timestamp: int, ssrc: int, payload: bytes):
        self.version = 2
        self.padding = 0
        self.extension = 0
        self.csrc_count = 0
        self.marker = 0
        self.payload_type = payload_type
        self.sequence_number = sequence_number
        self.timestamp = timestamp
        self.ssrc = ssrc
        self.payload = payload

    def pack(self) -> bytes:
        header = struct.pack(
            "!BBHII",
            (self.version << 6) | (self.padding << 5) | (self.extension << 4) | self.csrc_count,
            (self.marker << 7) | self.payload_type,
            self.sequence_number,
            self.timestamp,
            self.ssrc
        )
        return header + self.payload

    @classmethod
    def unpack(cls, packet: bytes):
        header = struct.unpack("!BBHII", packet[:12])
        payload = packet[12:]
        return cls(
            payload_type=header[1] & 0x7F,
            sequence_number=header[2],
            timestamp=header[3],
            ssrc=header[4],
            payload=payload
        )

class RTPHandler:
    def __init__(self):
        self.streams: Dict[str, RTPStream] = {}

    def start_stream(self, call_id: str, local_ip: str, remote_port: int, remote_ip: str, local_port: int = 0):
        stream = RTPStream(local_ip, local_port, remote_ip, remote_port)
        actual_port = stream.socket.getsockname()[1]
        self.streams[call_id] = stream
        stream.start()
        return actual_port

    def close_stream(self, call_id: str):
        if call_id in self.streams:
            self.streams[call_id].stop()
            del self.streams[call_id]

    def send_audio(self, call_id: str, audio_data: bytes):
        if call_id in self.streams:
            self.streams[call_id].send_packet(audio_data)

class RTPStream:
    def __init__(self, local_ip: str, local_port: int, remote_ip: str, remote_port: int):
        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((local_ip, local_port))
        self.sequence_number = 0
        self.timestamp = 0
        self.ssrc = struct.unpack("!I", os.urandom(4))[0]
        self.running = False
        self.receive_thread = None

    def start(self):
        self.running = True
        self.receive_thread = threading.Thread(target=self._receive_packets)
        self.receive_thread.start()

    def stop(self):
        self.running = False
        if self.receive_thread:
            self.receive_thread.join()
        self.socket.close()

    def send_packet(self, payload: bytes, payload_type: int = 0):
        packet = RTPPacket(payload_type, self.sequence_number, self.timestamp, self.ssrc, payload)
        self.socket.sendto(packet.pack(), (self.remote_ip, self.remote_port))
        self.sequence_number = (self.sequence_number + 1) & 0xFFFF
        self.timestamp += len(payload)

    def _receive_packets(self):
        while self.running:
            try:
                data, addr = self.socket.recvfrom(2048)
                packet = RTPPacket.unpack(data)
                # Process received packet (e.g., play audio)
                print(f"Received RTP packet: seq={packet.sequence_number}, ts={packet.timestamp}")
            except socket.error:
                pass

class Transport(ABC):
    @abstractmethod
    def send(self, data: bytes, address: tuple):
        pass

    @abstractmethod
    def receive(self) -> tuple:
        pass

class UDPTransport(Transport):
    def __init__(self, local_ip: str, local_port: int):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((local_ip, local_port))

    def send(self, data: bytes, address: tuple):
        self.socket.sendto(data, address)

    def receive(self) -> tuple:
        return self.socket.recvfrom(8192)

class TCPTransport(Transport):
    def __init__(self, local_ip: str, local_port: int):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((local_ip, local_port))
        self.socket.listen(5)
        self.connections = {}

    def send(self, data: bytes, address: tuple):
        if address not in self.connections:
            conn = self.socket.accept()[0]
            self.connections[address] = conn
        else:
            conn = self.connections[address]
        conn.sendall(data)

    def receive(self) -> tuple:
        conn, addr = self.socket.accept()
        data = conn.recv(8192)
        return data, addr


class TLSTransport(Transport):
    def __init__(self, local_ip: str, local_port: int, cert_file: str, key_file: str):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        self.socket = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_side=True)
        self.socket.bind((local_ip, local_port))
        self.socket.listen(5)
        self.connections = {}

    def send(self, data: bytes, address: tuple):
        if address not in self.connections:
            conn = self.socket.accept()[0]
            self.connections[address] = conn
        else:
            conn = self.connections[address]
        conn.sendall(data)

    def receive(self) -> tuple:
        conn, addr = self.socket.accept()
        data = conn.recv(8192)
        return data, addr


def sip_request(method: SIPMethod):
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            log.info(f"Sending SIP {method.value} request")
            result = func(self, *args, **kwargs)
            log.info(f"SIP {method.value} request sent")
            return result
        return wrapper
    return decorator

def sip_response(func):
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(self, message: SIPMessage, source: tuple):
            log.info(f"Handling SIP response: {message.status.code} {message.status.reason}")
            result = func(self, message, source)
            log.info("SIP response handled")
            return result
        return wrapper
    return decorator

class SIPStack:
    def __init__(self, local_ip: str, local_port: int, transport_type: str = "UDP"):
        self.local_ip = local_ip
        self.local_port = local_port
        self.transport = self._create_transport(transport_type)
        self.dialogs: Dict[str, SIPDialog] = {}
        self.rtp_handler = RTPHandler()

    def _create_transport(self, transport_type: str) -> Transport:
        if transport_type == "UDP":
            return UDPTransport(self.local_ip, self.local_port)
        elif transport_type == "TCP":
            return TCPTransport(self.local_ip, self.local_port)
        elif transport_type == "TLS":
            return TLSTransport(self.local_ip, self.local_port, "cert.pem", "key.pem")
        else:
            raise ValueError("Invalid transport type")

    def send_message(self, message: SIPMessage, destination: tuple):
        try:
            self.transport.send(message.serialize(), destination)
            log.info(f"Sent SIP message to {destination}")
        except Exception as e:
            log.error(f"Failed to send SIP message: {e}")
            raise SIPException("Message sending failed") from e

    def receive_message(self) -> tuple:
        try:
            data, addr = self.transport.receive()
            log.info(f"Received SIP message from {addr}")
            return SIPMessage.deserialize(data), addr
        except Exception as e:
            log.error(f"Failed to receive SIP message: {e}")
            raise SIPException("Message receiving failed") from e

    def create_dialog(self, local_uri: str, remote_uri: str) -> str:
        call_id = str(uuid.uuid4())
        dialog = SIPDialog(call_id, local_uri, remote_uri)
        self.dialogs[call_id] = dialog
        log.info(f"Created new dialog with Call-ID: {call_id}")
        return call_id

    @sip_request(SIPMethod.INVITE)
    def invite(self, call_id: str, sdp: SDPMessage):
        dialog = self.dialogs[call_id]
        invite_msg = SIPMessage(
            method=SIPMethod.INVITE,
            uri=dialog.remote_uri,
            headers={
                "Call-ID": call_id,
                "From": dialog.local_uri,
                "To": dialog.remote_uri,
                "CSeq": f"{dialog.local_seq} INVITE",
                "Content-Type": "application/sdp"
            },
            body=str(sdp)
        )
        self.send_message(invite_msg, self._get_destination(dialog.remote_uri))
        dialog.local_seq += 1

    @sip_request(SIPMethod.REGISTER)
    def register(self, user_uri: str, registrar_uri: str, expires: int = 3600):
        call_id = str(uuid.uuid4())
        register_msg = SIPMessage(
            method=SIPMethod.REGISTER,
            uri=registrar_uri,
            headers={
                "Call-ID": call_id,
                "From": user_uri,
                "To": user_uri,
                "CSeq": "1 REGISTER",
                "Expires": str(expires)
            }
        )
        self.send_message(register_msg, self._get_destination(registrar_uri))

    @sip_request(SIPMethod.OPTIONS)
    def options(self, target_uri: str):
        call_id = str(uuid.uuid4())
        options_msg = SIPMessage(
            method=SIPMethod.OPTIONS,
            uri=target_uri,
            headers={
                "Call-ID": call_id,
                "From": f"<sip:{self.local_ip}>",
                "To": target_uri,
                "CSeq": "1 OPTIONS"
            }
        )
        self.send_message(options_msg, self._get_destination(target_uri))

    def start_keep_alive(self, interval: int = 30):
        self.keep_alive_interval = interval
        self.keep_alive_thread = threading.Thread(target=self._keep_alive_loop)
        self.keep_alive_thread.daemon = True
        self.keep_alive_thread.start()
        
    def _keep_alive_loop(self):
        while True:
            for dialog in self.dialogs.values():
                if dialog.state == "ESTABLISHED":
                    self._send_keep_alive(dialog)
            time.sleep(self.keep_alive_interval)

    def _send_keep_alive(self, dialog: SIPDialog):
        options_msg = SIPMessage(
            method=SIPMethod.OPTIONS,
            uri=dialog.remote_uri,
            headers={
                "Call-ID": dialog.call_id,
                "From": dialog.local_uri,
                "To": dialog.remote_uri,
                "CSeq": f"{dialog.local_seq} OPTIONS"
            }
        )
        self.send_message(options_msg, self._get_destination(dialog.remote_uri))
        dialog.local_seq += 1
    
    def _get_destination(self, uri: str) -> tuple:
        try:
            ip = uri.split("@")[1].split(":")[0]
            port = 5060  # Default SIP port
            return (ip, port)
        except IndexError:
            log.error(f"Invalid URI format: {uri}")
            raise SIPException("Invalid URI format")

    def handle_incoming_message(self, message: SIPMessage, source: tuple):
        try:
            if message.method == SIPMethod.INVITE:
                self._handle_invite(message, source)
            elif message.method == SIPMethod.BYE:
                self._handle_bye(message, source)
            elif message.method == SIPMethod.ACK:
                self._handle_ack(message, source)
            elif message.status:
                self._handle_response(message, source)
            else:
                log.warning(f"Unhandled SIP method: {message.method}")
        except Exception as e:
            log.error(f"Error handling incoming message: {e}")

    def _handle_invite(self, message: SIPMessage, source: tuple):
        call_id = message.headers["Call-ID"]
        if call_id not in self.dialogs:
            dialog = SIPDialog(call_id, message.headers["To"], message.headers["From"])
            self.dialogs[call_id] = dialog
        else:
            dialog = self.dialogs[call_id]
        
        dialog.update_state("RINGING")
        ringing_response = SIPMessage(
            status_code=180,
            reason="Ringing",
            headers={
                "Call-ID": call_id,
                "From": dialog.remote_uri,
                "To": dialog.local_uri,
                "CSeq": message.headers["CSeq"]
            }
        )
        self.send_message(ringing_response, source)

        # Auto-answer for demonstration purposes
        sdp = SDPMessage.parse(message.body)
        remote_rtp_port = sdp.media[0].port
        local_rtp_port = self.rtp_handler.start_stream(call_id, self.local_ip, remote_rtp_port, source[0], 0)
        
        answer_sdp = SDPMessage(
            origin=f"- {uuid.uuid4()} 1 IN IP4 {self.local_ip}",
            session_name="PyPhone Call",
            connection=f"IN IP4 {self.local_ip}",
            media=[f"audio {local_rtp_port} RTP/AVP 0"]
        )
        ok_response = SIPMessage(
            status_code=200,
            reason="OK",
            headers={
                "Call-ID": call_id,
                "From": dialog.remote_uri,
                "To": dialog.local_uri,
                "CSeq": message.headers["CSeq"],
                "Content-Type": "application/sdp"
            },
            body=str(answer_sdp)
        )
        self.send_message(ok_response, source)
        dialog.update_state("ESTABLISHED")

    def _handle_bye(self, message: SIPMessage, source: tuple):
        call_id = message.headers["Call-ID"]
        if call_id in self.dialogs:
            dialog = self.dialogs[call_id]
            dialog.update_state("TERMINATED")
            del self.dialogs[call_id]
            self.rtp_handler.close_stream(call_id)
            ok_response = SIPMessage(
                status_code=200,
                reason="OK",
                headers={
                    "Call-ID": call_id,
                    "From": dialog.remote_uri,
                    "To": dialog.local_uri,
                    "CSeq": message.headers["CSeq"]
                }
            )
            self.send_message(ok_response, source)

    def _handle_ack(self, message: SIPMessage, source: tuple):
        call_id = message.headers["Call-ID"]
        if call_id in self.dialogs:
            dialog = self.dialogs[call_id]
            dialog.update_state("CONFIRMED")
        else:
            log.warning(f"Received ACK for non-existent dialog: {call_id}")

    @sip_response
    def _handle_response(self, message: SIPMessage, source: tuple):
        call_id = message.headers["Call-ID"]
        if call_id in self.dialogs:
            dialog = self.dialogs[call_id]
            if message.status == SIPStatusCode.OK:
                dialog.update_state("ESTABLISHED")
                if 'INVITE' in message.headers["CSeq"]:
                    sdp = SDPMessage.parse(message.body)
                    remote_rtp_port = sdp.media[0].port
                    self.rtp_handler.start_stream(call_id, self.local_ip, remote_rtp_port, source[0], 0)
                elif 'OPTIONS' in message.headers["CSeq"]:
                    self.options(dialog.remote_uri)
                    log.info(f"Sent OPTIONS request to {dialog.remote_uri}")
                elif 'REGISTER' in message.headers["CSeq"]:
                    log.info(f"Registered successfully with registrar {dialog.remote_uri}")
            elif message.status == SIPStatusCode.REQUEST_TIMEOUT:
                dialog.update_state("TERMINATED")
                del self.dialogs[call_id]
                self.rtp_handler.close_stream(call_id)
        else:
            log.warning(f"Received response for non-existent dialog: {call_id}")
    
    def run(self):
        while True:
            try:
                message, source = self.receive_message()
                self.handle_incoming_message(message, source)
            except Exception as e:
                log.error(f"Error in SIP stack: {e}")

class CustomSIPClient(SIPStack):
    def __init__(self, local_ip: str, local_port: int, transport_type: str = "UDP"):
        super().__init__(local_ip, local_port, transport_type)
        self.user_agent = "CustomSIPClient/1.0"

    def custom_invite(self, target_uri: str, sdp: SDPMessage):
        call_id = self.create_dialog(f"<sip:{self.local_ip}>", target_uri)
        invite_msg = SIPMessage(
            method=SIPMethod.INVITE,
            uri=target_uri,
            headers={
                "Call-ID": call_id,
                "From": f"<sip:{self.local_ip}>",
                "To": target_uri,
                "CSeq": "1 INVITE",
                "User-Agent": self.user_agent,
                "Content-Type": "application/sdp"
            },
            body=str(sdp)
        )
        self.send_message(invite_msg, self._get_destination(target_uri))
        log.info(f"Sent custom INVITE to {target_uri}")
        return call_id

    def custom_bye(self, call_id: str):
        dialog = self.dialogs.get(call_id)
        if dialog:
            bye_msg = SIPMessage(
                method=SIPMethod.BYE,
                uri=dialog.remote_uri,
                headers={
                    "Call-ID": call_id,
                    "From": dialog.local_uri,
                    "To": dialog.remote_uri,
                    "CSeq": f"{dialog.local_seq} BYE",
                    "User-Agent": self.user_agent
                }
            )
            self.send_message(bye_msg, self._get_destination(dialog.remote_uri))
            log.info(f"Sent custom BYE for call {call_id}")
        else:
            log.warning(f"Attempted to send BYE for non-existent dialog: {call_id}")

    def custom_message(self, target_uri: str, content: str, content_type: str = "text/plain"):
        call_id = str(uuid.uuid4())
        message_msg = SIPMessage(
            method=SIPMethod.MESSAGE,
            uri=target_uri,
            headers={
                "Call-ID": call_id,
                "From": f"<sip:{self.local_ip}>",
                "To": target_uri,
                "CSeq": "1 MESSAGE",
                "User-Agent": self.user_agent,
                "Content-Type": content_type
            },
            body=content
        )
        self.send_message(message_msg, self._get_destination(target_uri))
        log.info(f"Sent custom MESSAGE to {target_uri}")

    def handle_incoming_message(self, message: SIPMessage, source: tuple):
        super().handle_incoming_message(message, source)
        if message.method == SIPMethod.MESSAGE:
            self._handle_message(message, source)

    def _handle_message(self, message: SIPMessage, source: tuple):
        log.info(f"Received MESSAGE from {source}: {message.body}")
        ok_response = SIPMessage(
            status_code=200,
            reason="OK",
            headers={
                "Call-ID": message.headers["Call-ID"],
                "From": message.headers["To"],
                "To": message.headers["From"],
                "CSeq": message.headers["CSeq"]
            }
        )
        self.send_message(ok_response, source)



async def main():
    client = CustomSIPClient("192.168.1.100", 5060)
    
    # Registrar o cliente em um servidor SIP
    client.register("sip:user@example.com", "sip:registrar.example.com")
    
    # Iniciar uma chamada
    sdp = SDPMessage(
        origin=f"- {uuid.uuid4()} 1 IN IP4 192.168.1.100",
        session_name="PyPhone Call",
        connection="IN IP4 192.168.1.100",
        media=["audio 10000 RTP/AVP 0"]
    )
    call_id = client.custom_invite("sip:bob@example.com", sdp)
    
    # Enviar uma mensagem de texto
    client.custom_message("sip:alice@example.com", "Olá, Alice!")
    
    # Encerrar a chamada após 30 segundos
    await asyncio.sleep(30)
    client.custom_bye(call_id)
    
    # Executar o cliente SIP
    await asyncio.get_event_loop().run_in_executor(None, client.run)

if __name__ == "__main__":
    asyncio.run(main())
