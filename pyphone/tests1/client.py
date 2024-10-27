import socket
import re
import time
import random
import struct
import math
import threading
import hashlib
import numpy as np

from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, List

import pyaudio

from pyphone.settings import Settings
from pyphone.logger import logger

settings = Settings()

EOL = r'\n\r'
SIP_SCHEME = 'SIP'
SIP_VERSION = '2.0'
SIP_BRANCH = 'z9hG4bK'
SIP_MAX_FORWARDS = 70
SIP_CONTENT = "application"
SIP_CONTENT_TYPE = "sdp"

COMPACT_HEADERS = {
    "i": "call-id",
    "m": "contact",
    "e": "contact-encoding",
    "l": "content-length",
    "c": "content-type",
    "f": "from",
    "s": "subject",
    "k": "supported",
    "t": "to",
    "v": "via",
}

class SipMethod(Enum):
    INVITE = "INVITE"
    ACK = "ACK"
    BYE = "BYE"
    CANCEL = "CANCEL"
    REGISTER = "REGISTER"
    OPTIONS = "OPTIONS"
    SUBSCRIBE = "SUBSCRIBE"
    NOTIFY = "NOTIFY"
    UPDATE = "UPDATE"

    def __str__(self) -> str:
        return self._value_

    @staticmethod
    def methods() -> List[str]:
        return [str(m) for m in SipMethod]


class SipStatusCode(Enum):
    def __new__(cls, code, reason_phrase):
        obj = object.__new__(cls)
        obj._value_ = code
        obj.code = code
        obj.reason_phrase = reason_phrase
        return obj

    # SIP Status Codes 1xx
    TRYING = (100, "Trying")
    RINGING = (180, "Ringing")
    CALL_IS_BEING_FORWARDED = (181, "Call is being forwarded")
    QUEUED = (182, "Queued")
    SESSION_PROGRESS = (183, "Session Progress")
    EARLY_DIALOG_TERMINATED = (199, "Early Dialog Terminated")
    # SIP Status Codes 2xx
    OK = (200, "OK")
    ACCEPTED = (202, "Accepted")
    NO_NOTIFICATION = (204, "No Notification")
    # SIP Status Codes 3xx
    MULTIPLE_CHOICES = (300, "Multiple Choices")
    MOVED_PERMANENTLY = (301, "Moved Permanently")
    MOVED_TEMPORARILY = (302, "Moved Temporarily")
    USE_PROXY = (305, "Use Proxy")
    ALTERNATIVE_SERVICE = (380, "Alternative Service")
    # SIP Status Codes 4xx
    BAD_REQUEST = (400, "Bad Request")
    UNAUTHORIZED = (401, "Unauthorized")
    FORBIDDEN = (403, "Forbidden")
    NOT_FOUND = (404, "Not Found")
    METHOD_NOT_ALLOWED = (405, "Method Not Allowed")
    NOT_ACCEPTABLE = (406, "Not Acceptable")
    PROXY_AUTHENTICATION_REQUIRED = (407, "Proxy Authentication Required")
    REQUEST_TIMEOUT = (408, "Request Timeout")
    CONFLICT = (409, "Conflict")
    GONE = (410, "Gone")
    LENGTH_REQUIRED = (411, "Length Required")
    CONDITIONAL_REQUEST_FAILED = (412, "Conditional Request Failed")
    REQUEST_ENTITY_TOO_LARGE = (413, "Request Entity Too Large")
    REQUEST_URI_TOO_LONG = (414, "Request-URI Too Long")
    UNSUPPORTED_MEDIA_TYPE = (415, "Unsupported Media Type")
    UNSUPPORTED_URI_SCHEME = (416, "Unsupported URI Scheme")
    UNKNOWN_RESOURCE_PRIORITY = (417, "Unknown Resource-Priority")
    BAD_EXTENSION = (420, "Bad Extension")
    EXTENSION_REQUIRED = (421, "Extension Required")
    SESSION_INTERVAL_TOO_SMALL = (422, "Session Interval Too Small")
    INTERVAL_TOO_BRIEF = (423, "Interval Too Brief")
    BAD_LOCATION_INFORMATION = (424, "Bad Location Information")
    USE_IDENTITY_HEADER = (428, "Use Identity Header")
    PROVIDE_REFERRER_IDENTITY = (429, "Provide Referrer Identity")
    FLOW_FAILED = (430, "Flow Failed")
    ANONYMITY_DISALLOWED = (433, "Anonymity Disallowed")
    BAD_IDENTITY_INFO = (436, "Bad Identity-Info")
    UNSUPPORTED_CERTIFICATE = (437, "Unsupported Certificate")
    INVALID_IDENTITY_HEADER = (438, "Invalid Identity Header")
    FIRST_HOP_LACKS_OUTBOUND_SUPPORT = (439, "First Hop Lacks Outbound Support")
    MAX_BREADTH_EXCEEDED = (440, "Max-Breadth Exceeded")
    BAD_INFO_PACKAGE = (469, "Bad Info Package")
    CONSENT_NEEDED = (470, "Consent Needed")
    TEMPORARILY_UNAVAILABLE = (480, "Temporarily Unavailable")
    CALL_TRANSACTION_DOES_NOT_EXIST = (481, "Call/Transaction Does Not Exist")
    LOOP_DETECTED = (482, "Loop Detected")
    TOO_MANY_HOPS = (483, "Too Many Hops")
    ADDRESS_INCOMPLETE = (484, "Address Incomplete")
    AMBIGUOUS = (485, "Ambiguous")
    BUSY_HERE = (486, "Busy Here")
    REQUEST_TERMINATED = (487, "Request Terminated")
    NOT_ACCEPTABLE_HERE = (488, "Not Acceptable Here")
    BAD_EVENT = (491, "Bad Event")
    REQUEST_PENDING = (493, "Request Pending")
    UNDECIPHERABLE = (494, "Undecipherable")
    SECURITY_AGREEMENT_REQUIRED = (494, "Security Agreement Required")
    # SIP Status Codes 5xx
    SERVER_INTERNAL_ERROR = (500, "Server Internal Error")
    NOT_IMPLEMENTED = (501, "Not Implemented")
    BAD_GATEWAY = (502, "Bad Gateway")
    SERVICE_UNAVAILABLE = (503, "Service Unavailable")
    SERVER_TIMEOUT = (504, "Server Time-out")
    VERSION_NOT_SUPPORTED = (505, "Version Not Supported")
    MESSAGE_TOO_LARGE = (513, "Message Too Large")
    PUSH_NOTIFICATION_SERVICE_NOT_SUPPORTED = (555, "Push Notification Service Not Supported")
    PRECONDITION_FAILURE = (580, "Precondition Failure")
    # SIP Status Codes 6xx
    BUSY_EVERYWHERE = (600, "Busy Everywhere")
    DECLINE = (603, "Decline")
    DOES_NOT_EXIST_ANYWHERE = (604, "Does Not Exist Anywhere")
    UNWANTED = (607, "Unwanted")


class TransportType(Enum):
    def __str__(self):
        return self._value_

    def __repr__(self):
        return self.__str__()

    TLS = "TLS"
    TCP = "TCP"
    UDP = "UDP"


class MediaType(Enum):
    def __str__(self):
        return self._value_

    def __repr__(self):
        return self.__str__()

    RTP = "RTP"
    RTCP = "RTCP"


class Media(Enum):
    def __str__(self):
        return self._value_

    def __repr__(self):
        return self.__str__()
    AUDIO = "audio"
    VIDEO = "video"
    MESSAGE = "message"


class MediaSessionType(Enum):
    def __str__(self):
        return self._value_

    def __repr__(self):
        return self.__str__()

    SENDRECV = 'sendrecv'
    SENDONLY = 'sendonly'
    RECVONLY = 'recvonly'


class CodecType(Enum):
    def __str__(self):
        return self._value_[1]

    def __new__(self, code: int, description: str, sample_rate: int):
        obj = object.__new__(self)
        obj._value_ = description
        obj.code = code
        obj.description = description
        obj.sample_rate = sample_rate
        return obj

    def __repr__(self):
        return f'{self.code} {self.description}/{self.sample_rate}'

    PCMU = (0, 'PCMU', 8000)
    PCMA = (8, 'PCMA', 8000)


class DtmfType(Enum):
    def __new__(self, code: int, description: str, sample_rate: int, duration: int):
        obj = object.__new__(self)
        obj._value_ = f'{code} {description}/{sample_rate}'
        obj.code = code
        obj.description = description
        obj.sample_rate = sample_rate
        obj.duration = f'0-{duration}'
        return obj

    def __repr__(self):
        return f'{self.code} {self.description}/{self.sample_rate}'

    def rtpmap(self):
        return f'rtpmap:{self.code} {self.description}/{self.sample_rate}'

    def fmtp(self):
        return f'fmtp:{self.code} {self.duration}'

    RFC_2833 = (101, 'telephone-event', 8000, 16)


class DirectionType(Enum):
    INCOMING = "INCOMING"
    OUTGOING = "OUTGOING"
    BOTH = "BOTH"


class TransportConfig:
    protocol: TransportType = TransportType.UDP
    local_address: str = '0.0.0.0'
    local_port: str = '5060'
    public_address: str = '0.0.0.0'
    public_port: str = '5060'
    buffer_size: int = 1024


class UserConfig:
    username: str = '1001'
    password: str = 'secret'
    domain: str = 'example-domain-sip.com'
    port: int = 5060
    display_info: str = 'Ext 1001'
    caller_id: str = '1001'
    user_agent: str = 'pyphone'
    expires: int = 60


def parser_params_from_dict(params: Dict[str, str]) -> str:
    return ''.join([f';{k}={v}' for k, v in params.items()])


def parser_params_from_string(params: str) -> Dict[str, str]:
    return dict(
        (p.split('=') for p in [
            p for p in params.strip(';').split(';')
            ] if '=' in p))


def parser_uri_to_str(
        address: str,
        user: str = None,
        port: int = None,
        params: dict = None,
        scheme: str = 'SIP'
    ) -> str:
    _user = (f'{scheme.lower()}:{user}@' if user else '')
    _port = (f':{port}' if port else '')
    _params = (parser_params_from_dict(params) if params else '')
    return f'{_user}{address}{_port}{_params}'


class AbstractHeader(ABC):
    @abstractmethod
    def __str__(self) -> str:
        return ''

    def __repr__(self) -> str:
        return self.__str__()

    def to_bytes(self) -> bytes:
        return self.__str__().encode()


class RequestLine:
    scheme: str = SIP_SCHEME
    version: str = SIP_VERSION
    def __init__(self, method: SipMethod, remote_username: str, remote_address: str, remote_port: str) -> None:
        self.method = method
        self.remote_username = remote_username
        self.remote_address = remote_address
        self.remote_port = remote_port
    
    def __str__(self) -> str:
        return f'{self.method} sip:{self.remote_username}@{self.remote_address}:{self.remote_port} {self.scheme}/{self.version}'


class StatusLine:
    scheme: str = SIP_SCHEME
    version: str = SIP_VERSION
    def __init__(self, status_code: SipStatusCode, reason_phrase: str = None) -> None:
        self.status_code = status_code
        self.reason_phrase = reason_phrase

    def __str__(self) -> str:
        return f'{self.scheme}/{self.version} {self.status_code} {self.reason_phrase}'
    
    
    
class Via(AbstractHeader):
    scheme: str = SIP_SCHEME
    version: str = SIP_VERSION
    # Via: SIP/2.0/UDP 10.14.11.146:10060;branch=z9hG4bK8cafcde14db593eecde1f\r\n
    def __init__(self, public_address: str, public_port: str, branch: str, transport: TransportType = 'UDP', params: dict = None) -> None:
        self.transport = transport
        self.public_address = public_address
        self.public_port = public_port
        self.branch = branch
        self.params = params
    
    def __str__(self) -> str:
        _params = (''.join([f';{k}={v}' for k, v in self.params.items()]) if self.params else '')
        return f'Via: {self.scheme}/{self.version}/{self.transport} {self.public_address}:{self.public_port};branch={self.branch}{_params}'

class From:
    # From: "P2x9137" <sip:062099137@177.53.194.248:5060>;tag=3882100124\r\n
    pass










class Header:
    _via: list = []
    _from: str = None
    _to: str = None
    _contact: str = None
    _call_id: str = None
    _cseq: str = None
    _max_forwards: str = None
    _user_agent: str = None
    _server: str = None
    _expires: str = None
    _allow: str = None
    _supported: str = None
    _unsupported: str = None
    _content_type: str = None
    _content_length: str = None
    _route: list = []
    _record_route: list = []
    _www_authenticate: str = None
    _proxy_authenticate: str = None



class SIPRequest:
    pass


class SIPResponse:
    pass


class SIPDialog:
    def __init__(self):
        self.call_id = None
        self.cseq = None
        self.local_tag = None
        self.remote_tag = None
        self.local_uri = None
        self.remote_uri = None
        self.local_contact = None
        self.stack = []

    def genarate_call_id(self):
        return f"{random.randint(1000000, 9999999)}@{self.local_ip}"
    
    def genarate_cseq(self):
        return random.randint(1000, 9999)
        
    def generate_branch(self):
        return f"z9hG4bK-{random.randint(100000, 999999)}"

    def process_dialog(self, dialog) -> SIPRequest | SIPResponse:
        pass



class SIPAuth:
    def __init__(self, username, password, domain):
        self.username = username
        self.password = password
        self.domain = domain
        self.nonce = None
        self.realm = None

    def generate_auth_header(self, method, uri):
        if not self.nonce or not self.realm:
            raise ValueError(f"Nonce and realm must be set before generating auth header. Nonce: {self.nonce}, Realm: {self.realm}")

        ha1 = hashlib.md5(f"{self.username}:{self.realm}:{self.password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{self.nonce}:{ha2}".encode()).hexdigest()

        return (f'Authorization: Digest username="{self.username}", realm="{self.realm}", '
                f'nonce="{self.nonce}", uri="{uri}", response="{response}", algorithm=MD5')

    def update_auth_info(self, www_auth_header):
        logger.info(f"Received WWW-Authenticate header: {www_auth_header}")
        
        # Use regex to extract realm and nonce
        realm_match = re.search(r'realm="([^"]+)"', www_auth_header)
        nonce_match = re.search(r'nonce="([^"]+)"', www_auth_header)
        
        if realm_match:
            self.realm = realm_match.group(1)
        if nonce_match:
            self.nonce = nonce_match.group(1)
        
        logger.info(f"Extracted auth info - Realm: {self.realm}, Nonce: {self.nonce}")
        
        if not self.realm or not self.nonce:
            raise ValueError(f"Failed to extract realm or nonce from WWW-Authenticate header: {www_auth_header}")


class SIPClient:
    def __init__(self, username, password, domain, proxy):
        self.username = username
        self.password = password
        self.domain = domain
        self.proxy = proxy
        self.local_ip = self._get_local_ip()
        self.local_port = random.randint(10000, 65535)
        self.call_id = None
        self.cseq = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.local_ip, self.local_port))
        self.auth = SIPAuth(username, password, domain)


    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            logger.error(f"Failed to get local IP: {e}")
            return "127.0.0.1"

    def generate_branch(self):
        return f"z9hG4bK-{random.randint(100000, 999999)}"

    def generate_tag(self):
        return f"{random.randint(100000, 999999)}"

    def send_request(self, method, to_uri, from_uri, from_tag, to_tag=None, contact_uri=None, extra_headers=None, body=None):
        if not self.call_id:
            self.call_id = f"{random.randint(1000000, 9999999)}@{self.local_ip}"
        to_tag = f';tag={to_tag}' if to_tag else ''
        headers = [
            f"{method} {to_uri} SIP/2.0",
            f"Via: SIP/2.0/UDP {self.local_ip}:{self.local_port};branch={self.generate_branch()}",
            f"From: <{from_uri}>;tag={from_tag}",
            f"To: <{to_uri}>{to_tag}",
            f"Call-ID: {self.call_id}",
            f"CSeq: {self.cseq} {method}",
            "Max-Forwards: 70",
            "User-Agent: PythonSIPClient/0.0.1"
        ]

        if contact_uri:
            headers.append(f"Contact: <{contact_uri}>")

        if extra_headers:
            headers.extend(extra_headers)

        if body:
            headers.append("Content-Type: application/sdp")
            headers.append(f"Content-Length: {len(body)}")
        else:
            headers.append("Content-Length: 0")

        message = "\r\n".join(headers) + "\r\n\r\n"
        if body:
            message += body

        try:
            self.sock.sendto(message.encode(), (self.proxy, 5060))
            logger.info(f"Sent {method} request to {self.proxy}:5060")
            logger.info(f"Request:\n\n{message}")
        except Exception as e:
            logger.error(f"Failed to send {method} request: {e}")
        return message

    def receive_response(self, timeout=5):
        self.sock.settimeout(timeout)
        try:
            data, addr = self.sock.recvfrom(4096)
            return data.decode()
        except socket.timeout:
            logger.warning("Timeout while waiting for response")
            return None
        except Exception as e:
            logger.error(f"Error receiving response: {e}")
            return None
        finally:
            self.sock.settimeout(None)

    def register(self):
        to_uri = f"sip:{self.username}@{self.domain}"
        from_uri = to_uri
        contact_uri = f"sip:{self.username}@{self.local_ip}:{self.local_port}"
        from_tag = self.generate_tag()
        # Primeira tentativa de REGISTER sem autenticação
        self.send_request(
            method="REGISTER",
            to_uri=to_uri,
            from_uri=from_uri,
            from_tag=from_tag,
            contact_uri=contact_uri, 
            extra_headers=["Expires: 60"])

        response = self.receive_response()
        if not response:
            logger.error("No response received for REGISTER request")
            return False

        logger.info(f"Received response:\n\n{response}")

        if "401 Unauthorized" in response:
            # Extrair e atualizar as informações de autenticação
            www_auth_header = re.search('WWW-Authenticate: (.+)', response)
            if www_auth_header:
                www_auth_header = www_auth_header.group(1)
                try:
                    self.auth.update_auth_info(www_auth_header)
                except ValueError as e:
                    logger.error(f"Failed to update auth info: {str(e)}")
                    return False
                
                # Agora que temos o nonce e o realm, podemos gerar o cabeçalho de autenticação
                try:
                    auth_header = self.auth.generate_auth_header("REGISTER", to_uri)
                except ValueError as e:
                    logger.error(f"Failed to generate auth header: {str(e)}")
                    return False
                
                # Segunda tentativa de REGISTER com autenticação
                self.send_request(
                    method="REGISTER",
                    to_uri=to_uri,
                    from_uri=from_uri,
                    from_tag=from_tag,
                    contact_uri=contact_uri, 
                    extra_headers=["Expires: 60", auth_header])

                response = self.receive_response()
                if not response:
                    logger.error("No response received for authenticated REGISTER request")
                    return False

                logger.info(f"Received response:\n\n{response}")
            else:
                logger.error("WWW-Authenticate header not found in 401 response")
                return False

        return "200 OK" in response

    def generate_auth_header(self, method, uri, nonce):
        ha1 = f"{self.username}:{self.domain}:{self.password}"
        ha2 = f"{method}:{uri}"
        response = f"{ha1}:{nonce}:{ha2}"
        return f'Authorization: Digest username="{self.username}", realm="{self.domain}", nonce="{nonce}", uri="{uri}", response="{response}", algorithm=MD5'

    def invite(self, to_username):
        to_uri = f"sip:{to_username}@{self.domain}"
        from_uri = f"sip:{self.username}@{self.domain}"
        contact_uri = f"sip:{self.username}@{self.local_ip}:{self.local_port}"

        local_rtp_port = random.randint(10000, 20000)
        from_tag = self.generate_tag()
        sdp_body = self.generate_sdp(local_rtp_port)
        self.send_request(
            method="INVITE",
            to_uri=to_uri,
            from_uri=from_uri,
            from_tag=from_tag,
            contact_uri=contact_uri,
            body=sdp_body
            )

        # Definir um timeout para o processo de INVITE (por exemplo, 30 segundos)
        timeout = time.time() + 30
        record_route_headers = []

        while time.time() < timeout:
            response = self.receive_response()
            if not response:
                logger.error("No response received for INVITE request")
                return None

            logger.info(f"Received response:\n\n{response}")

            if "100 Trying" in response:
                logger.info("Received 100 Trying, waiting for final response")
                continue

            if "180 Ringing" in response:
                logger.info("Remote end is ringing, waiting for final response")
                continue

            if "200 OK" in response:
                logger.info("Received 200 OK response")
                call_id_match = re.search(r'Call-ID: (.+)', response)
                if call_id_match:
                    call_id = call_id_match.group(1)
                    logger.info(f"Call established. Call-ID: {call_id}")
                    to_tag = re.search(r'To: .*tag=([^ \r\n;]+)', response).group(1)
                    # Enviar ACK para confirmar o estabelecimento da chamada
                    # self.send_ack(to_uri, from_uri, call_id, tag=tag)
                    # Regex para capturar todas as instâncias de Record-Route
                    record_route_headers = re.findall(r'Record-Route: (.+)', response)

                    # Reverter a ordem dos Record-Route para incluí-los no ACK
                    record_route_headers.reverse()

                    # Construir os cabeçalhos 'Route' para o ACK a partir dos 'Record-Route'
                    route_headers = [f"Route: {route}" for route in record_route_headers]

                    self.send_request(
                        method="ACK",
                        to_uri=to_uri,
                        from_uri=from_uri,
                        from_tag=from_tag,
                        to_tag=to_tag,
                        contact_uri=contact_uri,
                        extra_headers=route_headers
                        )
                    
                    return call_id, local_rtp_port
                else:
                    logger.error("Failed to extract Call-ID from 200 OK response")
                    return None

            if response.startswith("SIP/2.0 4") or response.startswith("SIP/2.0 5") or response.startswith("SIP/2.0 6"):
                res = response.split('\n')[0]
                logger.error(f"INVITE request failed with response: {res}")
                return None

        logger.error("INVITE request timed out")
        return None

    def generate_sdp(self, rtp_port):
        sdp = [
            "v=0",
            f"o={self.username} {int(time.time())} {int(time.time())} IN IP4 {self.local_ip}",
            "s=Python SIP Client",
            f"c=IN IP4 {self.local_ip}",
            "t=0 0",
            f"m=audio {rtp_port} RTP/AVP 0 8",
            "a=rtpmap:0 PCMU/8000",
            "a=rtpmap:8 PCMA/8000"
        ]
        return "\r\n".join(sdp)

    def bye(self):
        to_uri = f"sip:{self.username}@{self.domain}"
        from_uri = to_uri

        self.send_request(
            method="BYE",
            to_uri=to_uri,
            from_uri=from_uri,
            )

        response = self.receive_response()
        if not response:
            logger.error("No response received for BYE request")
            return False

        logger.info(f"Received response:\n\n{response}")

        return "200 OK" in response

    def unregister(self):
        to_uri = f"sip:{self.username}@{self.domain}"
        from_uri = to_uri
        contact_uri = f"sip:{self.username}@{self.local_ip}:{self.local_port}"

        self.send_request(
            method="REGISTER",
            to_uri=to_uri,
            from_uri=from_uri,
            contact_uri=contact_uri, 
            extra_headers=["Expires: 0"]
            )

        response = self.receive_response()
        if not response:
            logger.error("No response received for UNREGISTER request")
            return False

        logger.info(f"Received response:\n\n{response}")

        return "200 OK" in response


class RTPClient:
    def __init__(self, local_ip, local_port):
        self.local_ip = local_ip
        self.local_port = local_port
        self.sequence_number = random.randint(0, 65535)
        self.timestamp = random.randint(0, 2**32 - 1)
        self.ssrc = random.randint(0, 2**32 - 1)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.local_ip, self.local_port))
        self.remote_ip = None
        self.remote_port = None

    def send_rtp_packet(self, payload, payload_type):
        if not self.remote_ip or not self.remote_port:
            logger.error("Remote RTP endpoint not set")
            return

        # Ensure payload is bytes
        if isinstance(payload, np.ndarray):
            payload = payload.tobytes()
        elif not isinstance(payload, bytes):
            payload = bytes(payload)

        # RTP header
        version = 2
        padding = 0
        extension = 0
        csrc_count = 0
        marker = 0
        
        header = struct.pack(
            '!BBHII',
            (version << 6) | (padding << 5) | (extension << 4) | csrc_count,
            (marker << 7) | payload_type,
            self.sequence_number,
            self.timestamp,
            self.ssrc
        )

        packet = header + payload
        try:
            self.sock.sendto(packet, (self.remote_ip, self.remote_port))
        except Exception as e:
            logger.error(f"Failed to send RTP packet: {e}")

        self.sequence_number = (self.sequence_number + 1) % 65536
        self.timestamp += len(payload)

    def receive_rtp_packet(self, timeout=0.02):
        self.sock.settimeout(timeout)
        try:
            data, addr = self.sock.recvfrom(4096)
            header = struct.unpack('!BBHII', data[:12])
            payload = data[12:]

            return {
                'version': header[0] >> 6,
                'padding': (header[0] >> 5) & 1,
                'extension': (header[0] >> 4) & 1,
                'csrc_count': header[0] & 0xF,
                'marker': header[1] >> 7,
                'payload_type': header[1] & 0x7F,
                'sequence_number': header[2],
                'timestamp': header[3],
                'ssrc': header[4],
                'payload': payload
            }
        except socket.timeout:
            return None
        except Exception as e:
            logger.error(f"Error receiving RTP packet: {e}")
            return None
        finally:
            self.sock.settimeout(None)

    def set_remote_endpoint(self, ip, port):
        self.remote_ip = ip
        self.remote_port = port
        logger.info(f"Set remote RTP endpoint to {ip}:{port}")


class AudioCodec:
    def __init__(self, sample_rate=8000, chunk_size=160):
        self.sample_rate = sample_rate
        self.chunk_size = chunk_size
        self.p = pyaudio.PyAudio()
        self.stream = self.p.open(format=pyaudio.paInt16,
                                  channels=1,
                                  rate=self.sample_rate,
                                  input=True,
                                  output=True,
                                  frames_per_buffer=self.chunk_size)

    def capture_audio(self):
        return np.frombuffer(self.stream.read(self.chunk_size), dtype=np.int16)

    def play_audio(self, audio):
        self.stream.write(audio.astype(np.int16).tobytes())

    def encode(self, audio, codec='alaw'):
        if codec == 'alaw':
            return self.linear_to_alaw(audio).tobytes()
        elif codec == 'ulaw':
            return self.linear_to_ulaw(audio).tobytes()
        else:
            raise ValueError("Unsupported codec. Use 'alaw' or 'ulaw'.")

    def decode(self, encoded_audio, codec='alaw'):
        if codec == 'alaw':
            return self.alaw_to_linear(encoded_audio)
        elif codec == 'ulaw':
            return self.ulaw_to_linear(encoded_audio)
        else:
            raise ValueError("Unsupported codec. Use 'alaw' or 'ulaw'.")

    @staticmethod
    def linear_to_alaw(samples):
        samples = samples.astype(np.float32)
        mask = (np.abs(samples) < 1.0/256)
        a_samples = np.zeros_like(samples)
        a_samples[mask] = (np.sign(samples[mask]) * (np.log(1 + 256*np.abs(samples[mask])) / np.log(1 + 256)))
        a_samples[~mask] = np.sign(samples[~mask]) * (1 + np.log(np.abs(samples[~mask])) / np.log(256))
        return (a_samples * 127).astype(np.int8)

    @staticmethod
    def alaw_to_linear(samples):
        samples = samples.astype(np.float32) / 127.0
        mask = (np.abs(samples) < (1.0/256))
        l_samples = np.zeros_like(samples)
        l_samples[mask] = samples[mask] * (256.0/257) * (1 + 256)
        l_samples[~mask] = np.sign(samples[~mask]) * (np.exp(np.abs(samples[~mask]) * np.log(256)) - 1) / 256.0
        return (l_samples * 32767).astype(np.int16)

    @staticmethod
    def linear_to_ulaw(samples):
        samples = samples.astype(np.float32) / 32768.0
        u_samples = np.sign(samples) * (np.log(1 + 255 * np.abs(samples)) / np.log(1 + 255))
        return ((u_samples + 1) * 127).astype(np.int8)

    @staticmethod
    def ulaw_to_linear(samples):
        samples = samples.astype(np.float32) / 127.0 - 1
        l_samples = np.sign(samples) * ((1 + 255)**np.abs(samples) - 1) / 255
        return (l_samples * 32768).astype(np.int16)

    def __del__(self):
        self.stream.stop_stream()
        self.stream.close()
        self.p.terminate()


class DTMFGenerator:
    def __init__(self, sample_rate=8000, duration=0.1):
        self.sample_rate = sample_rate
        self.duration = duration
        self.dtmf_freqs = {
            '1': (697, 1209), '2': (697, 1336), '3': (697, 1477),
            '4': (770, 1209), '5': (770, 1336), '6': (770, 1477),
            '7': (852, 1209), '8': (852, 1336), '9': (852, 1477),
            '*': (941, 1209), '0': (941, 1336), '#': (941, 1477),
            'A': (697, 1633), 'B': (770, 1633), 'C': (852, 1633), 'D': (941, 1633)
        }

    def generate(self, digit):
        if digit not in self.dtmf_freqs:
            raise ValueError(f"Invalid DTMF digit: {digit}")

        f1, f2 = self.dtmf_freqs[digit]
        num_samples = int(self.sample_rate * self.duration)
        samples = []

        for i in range(num_samples):
            t = i / self.sample_rate
            sample = 0.5 * math.sin(2 * math.pi * f1 * t) + 0.5 * math.sin(2 * math.pi * f2 * t)
            samples.append(int(sample * 32767))  # Convert to 16-bit PCM

        return struct.pack(f"{len(samples)}h", *samples)


class DTMFDetector:
    def __init__(self, sample_rate=8000):
        self.sample_rate = sample_rate
        self.dtmf_freqs = {
            697: ['1', '2', '3', 'A'],
            770: ['4', '5', '6', 'B'],
            852: ['7', '8', '9', 'C'],
            941: ['*', '0', '#', 'D'],
            1209: ['1', '4', '7', '*'],
            1336: ['2', '5', '8', '0'],
            1477: ['3', '6', '9', '#'],
            1633: ['A', 'B', 'C', 'D']
        }

    def detect(self, audio_data):
        # Convert audio data to list of samples
        samples = struct.unpack(f"{len(audio_data)//2}h", audio_data)

        # Perform Goertzel algorithm for each DTMF frequency
        detected_freqs = []
        for freq in self.dtmf_freqs.keys():
            if self._goertzel(samples, freq):
                detected_freqs.append(freq)

        # Determine the digit based on detected frequencies
        row_freq = next((f for f in detected_freqs if f < 1000), None)
        col_freq = next((f for f in detected_freqs if f > 1000), None)

        if row_freq and col_freq:
            row_digits = set(self.dtmf_freqs[row_freq])
            col_digits = set(self.dtmf_freqs[col_freq])
            digit = list(row_digits.intersection(col_digits))[0]
            return digit

        return None

    def _goertzel(self, samples, target_freq, threshold=1e5):
        n = len(samples)
        k = int(0.5 + n * target_freq / self.sample_rate)
        omega = 2 * math.pi * k / n
        cos_omega = math.cos(omega)
        # sin_omega = math.sin(omega)
        coeff = 2 * cos_omega

        q0, q1, q2 = 0, 0, 0
        for sample in samples:
            q0 = coeff * q1 - q2 + sample
            q2 = q1
            q1 = q0

        magnitude = q1 * q1 + q2 * q2 - q1 * q2 * coeff
        return magnitude > threshold


class VoIPClient:
    def __init__(self, username, password, domain, proxy):
        self.username = username
        self.password = password
        self.domain = domain
        self.proxy = proxy
        self.sip_client = SIPClient(username, password, domain, proxy)
        self.rtp_client = None
        self.call_in_progress = False
        self.registered = False
        self.audio_codec = AudioCodec()
        self.codec_payload_type = 8
        self.call_ended_event = threading.Event()


    def register(self):
        if self.sip_client.register():
            self.registered = True
            logger.info(f"Registered successfully as {self.username}@{self.domain}")
        else:
            logger.info("Registration failed")

    def unregister(self):
        if self.sip_client.unregister():
            self.registered = False
            logger.info("Unregistered successfully")
        else:
            logger.info("Unregistration failed")

    def make_call(self, target):
        if not self.registered:
            logger.info("Please register first")
            return

        if self.call_in_progress:
            logger.info("A call is already in progress")
            return

        logger.info(f"Initiating call to {target}...")
        result = self.sip_client.invite(target)
        if result:
            call_id, local_rtp_port = result
            logger.info(f"Call established with {target} - Call-ID: {call_id}")
            try:
                logger.info(f'Trying to establish RTP on port {local_rtp_port}')
                self.rtp_client = RTPClient(self.sip_client.local_ip, local_rtp_port)
                # TODO: Set remote RTP endpoint to the actual IP and port received in the SDP
                self.rtp_client.set_remote_endpoint(self.sip_client.proxy, local_rtp_port)
                self.call_in_progress = True
                self.call_ended_event.clear()
                self._handle_call()
            except Exception as e:
                logger.error(f"Failed to establish RTP on port {local_rtp_port}: {e}")
        else:
            logger.info("Failed to establish call")

    def end_call(self):
        if not self.call_in_progress:
            logger.info("No call in progress")
            return

        if self.sip_client.bye():
            self.call_in_progress = False
            self.call_ended_event.set()
            logger.info("Call ended")
        else:
            logger.info("Failed to end call")

    def _handle_call(self):
        audio_thread = threading.Thread(target=self._audio_stream)
        audio_thread.start()

        self.call_ended_event.wait()

        audio_thread.join()

    def _audio_stream(self):
        while self.call_in_progress:
            local_audio = self.audio_codec.capture_audio()
            encoded_audio = self.audio_codec.encode(local_audio, 'alaw')
            self.rtp_client.send_rtp_packet(encoded_audio, self.codec_payload_type)

            remote_audio = self.rtp_client.receive_rtp_packet()
            if remote_audio:
                decoded_audio = self.audio_codec.decode(remote_audio, 'alaw')
                self.audio_codec.play_audio(decoded_audio)

    def _send_dtmf(self, digits):
        dtmf_gen = DTMFGenerator()
        for digit in digits:
            dtmf_signal = dtmf_gen.generate(digit)
            self.rtp_client.send_rtp_packet(dtmf_signal)
            time.sleep(0.1)  # Duration of DTMF tone



if __name__ == "__main__":
    
    client = VoIPClient(
        username=settings.SIP_USERNAME,
        password=settings.SIP_PASSWORD,
        domain=settings.SIP_DOMAIN,
        proxy=settings.SIP_DOMAIN
    )
    
    while True:
        command = input("Enter command (register [r], unregister [u], call [c], quit [q]): ")
        command.lower()
        if command.lower() in ('r', 'register'):
            client.register()
        elif command in ('u', 'unregister'):
            client.unregister()
        elif command in ('c', 'call'):
            target = settings.SIP_DESTINATION
            client.make_call(target)
        elif command in ('q', 'quit'):
            if client.registered:
                client.unregister()
            break
        else:
            logger.info("Invalid command")


"""

TODO: separar controle de respostar em uma classe dialog/transaction
TODO: last error 
TODO: Revisar dtmf
TODO: https://github.com/tobiw/voip-hpc/blob/master/sip.py


"""