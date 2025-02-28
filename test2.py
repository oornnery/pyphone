import argparse
import logging
import os
import sys
import time
import socket
import random
import re
from enum import Enum
from dataclasses import dataclass
from typing import List, Tuple, Optional
import threading

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Transport:
    def __init__(self, host: str, port: int, protocol: str = 'udp'):
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.socket = None

    def connect(self):
        if self.protocol == 'udp':
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif self.protocol == 'tcp':
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            raise ValueError("Protocolo não suportado. Use 'udp' ou 'tcp'.")
        
        self.socket.bind((self.host, self.port))

    def send(self, data: bytes, address: Tuple[str, int]):
        if self.protocol == 'udp':
            self.socket.sendto(data, address)
        else:
            self.socket.connect(address)
            self.socket.sendall(data)

    def receive(self, buffer_size: int = 4096) -> Tuple[bytes, Tuple[str, int]]:
        if self.protocol == 'udp':
            return self.socket.recvfrom(buffer_size)
        else:
            data = self.socket.recv(buffer_size)
            return data, self.socket.getpeername()

    def close(self):
        if self.socket:
            self.socket.close()

class SDP:
    def __init__(self):
        self.session_id = str(int(time.time()))
        self.session_version = "0"
        self.username = "-"
        self.session_name = "Pyphone Session"
        self.connection_info = "IN IP4 0.0.0.0"
        self.time_description = "0 0"
        self.media_description = "audio 0 RTP/AVP 0 8"  # G.711 µ-law and A-law

    def generate_offer(self) -> str:
        sdp = [
            f"v=0",
            f"o={self.username} {self.session_id} {self.session_version} {self.connection_info}",
            f"s={self.session_name}",
            f"c={self.connection_info}",
            f"t={self.time_description}",
            f"m={self.media_description}"
        ]
        return "\r\n".join(sdp)

    def generate_answer(self, offer: str) -> str:
        # Por simplicidade, estamos apenas retornando a mesma oferta como resposta
        # Em uma implementação real, você analisaria a oferta e geraria uma resposta apropriada
        return offer

    def parse_offer(self, offer: str) -> dict:
        parsed = {}
        lines = offer.split("\r\n")
        for line in lines:
            if '=' in line:
                key, value = line.split('=', 1)
                parsed[key] = value
        return parsed

    def parse_answer(self, answer: str) -> dict:
        # Similar ao parse_offer
        return self.parse_offer(answer)

    def negotiate(self, offer: str, answer: str) -> dict:
        offer_dict = self.parse_offer(offer)
        answer_dict = self.parse_answer(answer)
        # Aqui você implementaria a lógica de negociação
        # Por simplicidade, estamos apenas retornando os codecs suportados
        return {"codecs": ["PCMU", "PCMA"]}

class RTP:
    def __init__(self, local_ip: str, local_port: int):
        self.local_ip = local_ip
        self.local_port = local_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.local_ip, self.local_port))

    def send_packet(self, payload: bytes, destination: Tuple[str, int]):
        # Implementação simplificada, sem cabeçalho RTP completo
        self.socket.sendto(payload, destination)

    def receive_packet(self, buffer_size: int = 1024) -> Tuple[bytes, Tuple[str, int]]:
        return self.socket.recvfrom(buffer_size)

class DTMF:
    @staticmethod
    def generate_tone(digit: str, duration: int = 200) -> bytes:
        # Implementação simplificada, retornando apenas o dígito como bytes
        return digit.encode()

class Codec:
    @staticmethod
    def encode_ulaw(audio: bytes) -> bytes:
        # Implementação simplificada de codificação µ-law
        return audio

    @staticmethod
    def decode_ulaw(encoded: bytes) -> bytes:
        # Implementação simplificada de decodificação µ-law
        return encoded

    @staticmethod
    def encode_alaw(audio: bytes) -> bytes:
        # Implementação simplificada de codificação A-law
        return audio

    @staticmethod
    def decode_alaw(encoded: bytes) -> bytes:
        # Implementação simplificada de decodificação A-law
        return encoded

class SIPMessage:
    def __init__(self, start_line: str, headers: List[Tuple[str, str]], body: str):
        self.start_line = start_line
        self.headers = headers
        self.body = body

    @property
    def is_request(self):
        return not self.start_line.startswith("SIP/2.0")

    @property
    def is_response(self):
        return self.start_line.startswith("SIP/2.0")

    @staticmethod
    def __build_header(headers: List[Tuple[str, str]]) -> str:
        return "".join([f"{name}: {value}\r\n" for name, value in headers])

    @classmethod
    def request(cls, method: str, uri: str, headers: List[Tuple[str, str]], body: str) -> 'SIPMessage':
        start_line = f"{method} {uri} SIP/2.0"
        return cls(start_line, headers, body)

    @classmethod
    def response(cls, status_code: int, reason_phrase: str, headers: List[Tuple[str, str]], body: str) -> 'SIPMessage':
        start_line = f"SIP/2.0 {status_code} {reason_phrase}"
        return cls(start_line, headers, body)

    @classmethod
    def parse_message(cls, message: str) -> 'SIPMessage':
        lines = message.split("\r\n")
        start_line = lines[0]
        headers = []
        body = ""
        header_end = lines.index("")
        for line in lines[1:header_end]:
            name, value = line.split(":", 1)
            headers.append((name.strip(), value.strip()))
        if header_end < len(lines) - 1:
            body = "\r\n".join(lines[header_end+1:])
        return cls(start_line, headers, body)

    def __str__(self):
        headers_str = self.__build_header(self.headers)
        return f"{self.start_line}\r\n{headers_str}\r\n{self.body}"

class Dialog:
    def __init__(self, local_tag: str, remote_tag: str, call_id: str):
        self.local_tag = local_tag
        self.remote_tag = remote_tag
        self.call_id = call_id
        self.local_seq = random.randint(1, 65535)
        self.remote_seq = 0

    def increment_local_seq(self):
        self.local_seq += 1

    def set_remote_seq(self, seq: int):
        self.remote_seq = seq

class Transaction:
    def __init__(self, dialog: Dialog, method: str):
        self.dialog = dialog
        self.method = method
        self.state = "Trying"

    def set_state(self, state: str):
        self.state = state

class SIP:
    def __init__(self, uri: str, transport: Transport):
        self.uri = uri
        self.transport = transport
        self.user_agent = "Pyphone/0.1"
        self.display_name = None
        self.contact = None
        self.dialogs = {}

    def create_dialog(self, remote_uri: str) -> Dialog:
        call_id = f"{time.time()}@{self.uri}"
        local_tag = f"{random.randint(1000, 9999)}"
        dialog = Dialog(local_tag, "", call_id)
        self.dialogs[call_id] = dialog
        return dialog

    def invite(self, to_uri: str, sdp: str) -> SIPMessage:
        dialog = self.create_dialog(to_uri)
        headers = [
            ("To", f"<sip:{to_uri}>"),
            ("From", f"{self.display_name or ''}<sip:{self.uri}>;tag={dialog.local_tag}"),
            ("Call-ID", dialog.call_id),
            ("CSeq", f"{dialog.local_seq} INVITE"),
            ("Contact", f"<sip:{self.contact or self.uri}>"),
            ("Content-Type", "application/sdp"),
            ("Content-Length", str(len(sdp))),
            ("User-Agent", self.user_agent)
        ]
        return SIPMessage.request("INVITE", f"sip:{to_uri}", headers, sdp)

    def options(self) -> SIPMessage:
        headers = [
            ("To", f"<sip:{self.uri}>"),
            ("From", f"{self.display_name or ''}<sip:{self.uri}>;tag={random.randint(1000, 9999)}"),
            ("Call-ID", f"{time.time()}@{self.uri}"),
            ("CSeq", f"{random.randint(1, 65535)} OPTIONS"),
            ("Contact", f"<sip:{self.contact or self.uri}>"),
            ("User-Agent", self.user_agent),
            ("Accept", "application/sdp")
        ]
        return SIPMessage.request("OPTIONS", f"sip:{self.uri}", headers, "")

    def register(self, registrar: str, expires: int = 3600) -> SIPMessage:
        headers = [
            ("To", f"<sip:{self.uri}>"),
            ("From", f"{self.display_name or ''}<sip:{self.uri}>;tag={random.randint(1000, 9999)}"),
            ("Call-ID", f"{time.time()}@{self.uri}"),
            ("CSeq", f"{random.randint(1, 65535)} REGISTER"),
            ("Contact", f"<sip:{self.contact or self.uri}>"),
            ("Expires", str(expires)),
            ("User-Agent", self.user_agent)
        ]
        return SIPMessage.request("REGISTER", f"sip:{registrar}", headers, "")

    def ack(self, dialog: Dialog, to_uri: str) -> SIPMessage:
        headers = [
            ("To", f"<sip:{to_uri}>"),
            ("From", f"{self.display_name or ''}<sip:{self.uri}>;tag={dialog.local_tag}"),
            ("Call-ID", dialog.call_id),
            ("CSeq", f"{dialog.local_seq} ACK"),
            ("User-Agent", self.user_agent)
        ]
        return SIPMessage.request("ACK", f"sip:{to_uri}", headers, "")

    def bye(self, dialog: Dialog, to_uri: str) -> SIPMessage:
        dialog.increment_local_seq()
        headers = [
            ("To", f"<sip:{to_uri}>"),
            ("From", f"{self.display_name or ''}<sip:{self.uri}>;tag={dialog.local_tag}"),
            ("Call-ID", dialog.call_id),
            ("CSeq", f"{dialog.local_seq} BYE"),
            ("User-Agent", self.user_agent)
        ]
        return SIPMessage.request("BYE", f"sip:{to_uri}", headers, "")

    def cancel(self, dialog: Dialog, to_uri: str) -> SIPMessage:
        headers = [
            ("To", f"<sip:{to_uri}>"),
            ("From", f"{self.display_name or ''}<sip:{self.uri}>;tag={dialog.local_tag}"),
            ("Call-ID", dialog.call_id),
            ("CSeq", f"{dialog.local_seq} CANCEL"),
            ("User-Agent", self.user_agent)
        ]
        return SIPMessage.request("CANCEL", f"sip:{to_uri}", headers, "")

    def response(self, request: SIPMessage, status_code: int, reason_phrase: str, body: str = "") -> SIPMessage:
        headers = [header for header in request.headers if header[0] in ("To", "From", "Call-ID", "CSeq")]
        headers.append(("Contact", f"<sip:{self.contact or self.uri}>"))
        headers.append(("User-Agent", self.user_agent))
        if body:
            headers.append(("Content-Type", "application/sdp"))
            headers.append(("Content-Length", str(len(body))))
        return SIPMessage.response(status_code, reason_phrase, headers, body)

class Session:
    def __init__(self, sip: SIP, sdp: SDP, rtp: RTP):
        self.sip = sip
        self.sdp = sdp
        self.rtp = rtp
        self.dialog = None
        self.remote_sdp = None

    def invite(self, to_uri: str):
        sdp_offer = self.sdp.generate_offer()
        invite_message = self.sip.invite(to_uri, sdp_offer)
        self.dialog = self.sip.create_dialog(to_uri)
        self.sip.transport.send(str(invite_message).encode(), (to_uri, 5060))

    def handle_invite_response(self, response: SIPMessage):
        if response.is_response:
            status_code = int(response.start_line.split()[1])
            if 200 <= status_code < 300:
                self.remote_sdp = self.sdp.parse_answer(response.body)
                ack_message = self.sip.ack(self.dialog, self.dialog.remote_tag)
                self.sip.transport.send(str(ack_message).encode(), (self.dialog.remote_tag, 5060))
            elif status_code >= 300:
                logger.info(f"INVITE falhou com status {status_code}")

    def bye(self):
        if self.dialog:
            bye_message = self.sip.bye(self.dialog, self.dialog.remote_tag)
            self.sip.transport.send(str(bye_message).encode(), (self.dialog.remote_tag, 5060))
            
    def handle_bye(self, response: SIPMessage):
        if response.is_request:
            self.sip.transport.send(str(response).encode(), (self.dialog.remote_tag, 5060))
            self.dialog = None
    
    def handle_cancel(self, response: SIPMessage):
        if response.is_request:
            self.sip.transport.send(str(response).encode(), (self.dialog.remote_tag, 5060))
            self.dialog = None
        
    def handle_invite(self, request: SIPMessage):
        if request.is_request:
            self.remote_sdp = self.sdp.parse_offer(request.body)
            response = self.sip.response(request, 200, "OK", self.sdp.generate_answer(request.body))
            self.sip.transport.send(str(response).encode(), (self.dialog.remote_tag, 5060))
            ack_message = self.sip.ack(self.dialog, self.dialog.remote_tag)
            self.sip.transport.send(str(ack_message).encode(), (self.dialog.remote_tag, 5060))
    
    def handle_response(self, response: SIPMessage):
        if response.is_response:
            status_code = int(response.start_line.split()[1])
            if 200 <= status_code < 300:
                self.dialog.set_remote_seq(int(response.headers[2][1].split()[0]))
            elif status_code >= 300:
                logger.info(f"Resposta falhou com status {status_code}")

class Pyphone:
    def __init__(self, local_ip: str, local_port: int, username: str, password: str, domain: str):
        self.local_ip = local_ip
        self.local_port = local_port
        self.username = username
        self.password = password
        self.domain = domain
        self.uri = f"{username}@{domain}"
        
        self.transport = Transport(local_ip, local_port)
        self.sip = SIP(self.uri, self.transport)
        self.sdp = SDP()
        self.rtp = RTP(local_ip, local_port + 2)  # RTP porta = SIP porta + 2
        
        self.session = None
        self.registered = False
        self.running = False

    def start(self):
        self.transport.connect()
        self.running = True
        threading.Thread(target=self._listen, daemon=True).start()

    def stop(self):
        self.running = False
        if self.session:
            self.session.bye()
        if self.registered:
            self._unregister()
        self.transport.close()

    def register(self):
        register_message = self.sip.register(self.domain)
        self.transport.send(str(register_message).encode(), (self.domain, 5060))
        response = self._wait_for_response()
        if response and 200 <= int(response.start_line.split()[1]) < 300:
            self.registered = True
            logger.info("Registrado com sucesso")
        else:
            logger.error("Falha no registro")

    def _unregister(self):
        register_message = self.sip.register(self.domain, expires=0)
        self.transport.send(str(register_message).encode(), (self.domain, 5060))
        response = self._wait_for_response()
        if response and 200 <= int(response.start_line.split()[1]) < 300:
            self.registered = False
            logger.info("Desregistrado com sucesso")
        else:
            logger.error("Falha no desregistro")

    def call(self, to_uri: str):
        if not self.registered:
            logger.error("Você precisa estar registrado para fazer chamadas")
            return
        
        self.session = Session(self.sip, self.sdp, self.rtp)
        self.session.invite(to_uri)
        response = self._wait_for_response()
        if response:
            self.session.handle_invite_response(response)

    def hangup(self):
        if self.session:
            self.session.bye()
            self.session = None

    def _listen(self):
        while self.running:
            try:
                data, addr = self.transport.receive()
                message = SIPMessage.parse_message(data.decode())
                self._handle_message(message, addr)
            except Exception as e:
                logger.error(f"Erro ao receber mensagem: {e}")

    def _handle_message(self, message: SIPMessage, addr: Tuple[str, int]):
        if message.is_request:
            method = message.start_line.split()[0]
            if method == "INVITE":
                self._handle_invite(message, addr)
            elif method == "BYE":
                self._handle_bye(message, addr)
            elif method == "OPTIONS":
                self._handle_options(message, addr)
        elif message.is_response:
            if self.session:
                self.session.handle_invite_response(message)

    def _handle_invite(self, message: SIPMessage, addr: Tuple[str, int]):
        sdp_answer = self.sdp.generate_answer(message.body)
        response = self.sip.response(message, 200, "OK", sdp_answer)
        self.transport.send(str(response).encode(), addr)
        self.session = Session(self.sip, self.sdp, self.rtp)
        self.session.dialog = self.sip.create_dialog(message.headers["From"][1])
        self.session.remote_sdp = self.sdp.parse_offer(message.body)

    def _handle_bye(self, message: SIPMessage, addr: Tuple[str, int]):
        response = self.sip.response(message, 200, "OK")
        self.transport.send(str(response).encode(), addr)
        if self.session:
            self.session = None
        logger.info("Chamada encerrada")

    def _handle_options(self, message: SIPMessage, addr: Tuple[str, int]):
        response = self.sip.response(message, 200, "OK")
        self.transport.send(str(response).encode(), addr)

    def _wait_for_response(self, timeout: float = 5.0) -> Optional[SIPMessage]:
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                data, _ = self.transport.receive()
                message = SIPMessage.parse_message(data.decode())
                if message.is_response:
                    return message
            except socket.timeout:
                pass
        return None

def main():
    parser = argparse.ArgumentParser(description="Pyphone - Um softphone SIP simples")
    parser.add_argument("--ip", help="Endereço IP local", default="0.0.0.0")
    parser.add_argument("--port", help="Porta local", type=int, default=5060)
    parser.add_argument("--username", help="Nome de usuário SIP", required=True)
    parser.add_argument("--password", help="Senha SIP", required=True)
    parser.add_argument("--domain", help="Domínio SIP", required=True)
    args = parser.parse_args()

    pyphone = Pyphone(args.ip, args.port, args.username, args.password, args.domain)
    pyphone.start()

    try:
        pyphone.register()
        while True:
            command = input("Digite um comando (call, hangup, quit): ").strip().lower()
            if command == "call":
                to_uri = input("Digite o URI SIP para chamar: ")
                pyphone.call(to_uri)
            elif command == "hangup":
                pyphone.hangup()
            elif command == "quit":
                break
            else:
                print("Comando inválido")
    finally:
        pyphone.stop()

if __name__ == "__main__":
    main()