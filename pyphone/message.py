
from dataclasses import dataclass, field
import uuid
import re
import socket
import random

PORT_RANGE = (5000, 6000)
COMPACT_HEADERS = {
    "v": "Via",
    "f": "From",
    "t": "To",
    "m": "Contact",
    "i": "Call-ID",
    "e": "Contact-Encoding",
    "l": "Content-Length",
    "c": "Content-Type",
    "s": "Subject",
    "k": "Supported",
}

@dataclass
class RequestLine:
    method: str
    uri: str
    version: str = "SIP/2.0"

    def __str__(self):
        return f"{self.method} {self.uri} {self.version}\r\n"

    @classmethod
    def parser(self, raw: str) -> "RequestLine":
        method, uri, version = raw.split(" ")
        return RequestLine(method, uri, version)


@dataclass
class ResponseLine:
    status_code: str
    reason_phrase: str
    version: str = "SIP/2.0"

    def __str__(self):
        return f"{self.version} {self.status_code} {self.reason_phrase}\r\n"

    @classmethod
    def parser(self, raw: str) -> "ResponseLine":
        version, status_code, reason_phrase = raw.split(" ", 2)
        return ResponseLine(version, status_code, reason_phrase)


@dataclass
class Header:
    via_uri: str
    from_uri: str
    to_uri: str
    call_id: str
    cseq: str
    cseq_method: str
    contact: str = None
    max_forwards: str = None
    content_type: str = None
    content_length: str = None
    extra_headers: list[tuple[str, str]]

    @classmethod
    def _call_id():
        return str(str(uuid.uuid4().hex()[:8]))

    @classmethod
    def _content_length(body: str):
        return str(len(body))

    def __str__(self):
        return (
            f"Via: {self.via_uri}\r\n"
            f"From: {self.from_uri}\r\n"
            f"To: {self.to_uri}\r\n"
            f"Call-ID: {self.call_id}\r\n"
            f"CSeq: {self.cseq} {self.cseq_method}\r\n"
            f"Contact: {self.contact}\r\n"
            if self.contact
            else f"Max-Forwards: {self.max_forwards}\r\n"
            if self.max_forwards
            else f"Content-Type: {self.content_type}\r\n"
            if self.content_type
            else f"Content-Length: {self.content_length}\r\n"
            if self.content_length
            else "".join(f"{k}: {v}\r\n" for k, v in self.extra_headers)
        )

    @classmethod
    def parser(self, raw: str) -> "Header":
        data = re.findall(r"(\w+): (.+)\r\n", raw)
        return Header(
            via_uri=data.get("Via"),
            from_uri=data.get("From"),
            to_uri=data.get("To"),
            call_id=data.get("Call-ID"),
            cseq=data.get("CSeq").split(" ")[0],
            cseq_method=data.get("CSeq").split(" ")[1],
            contact=data.get("Contact", None),
            max_forwards=data.get("Max-Forwards", None),
            content_type=data.get("Content-Type", None),
            content_length=data.get("Content-Length", None),
            extra_headers=[
                (k, v)
                for k, v in data
                if k
                not in (
                    "Via",
                    "From",
                    "To",
                    "Call-ID",
                    "CSeq",
                    "Contact",
                    "Max-Forwards",
                    "Content-Type",
                    "Content-Length",
                )
            ],
        )


@dataclass
class SDPSession:
    session_name: str = None
    version: int = None
    origin: str = None
    session_name: str = None
    connection: str = None
    time: str = None
    media: list[str] = field(default_factory=list)
    attributes: list[str] = field(default_factory=list)
    extra_sdp: list[str] = field(default_factory=list[tuple[str, str]])

    def add_media(self, media_type: str, port: int, protocol: str, fmt: list[int]):
        self.media.append(
            f"m={media_type} {port} {protocol}" + " ".join(str(x) for x in fmt)
        )

    def _session_id(self):
        return str(uuid.uuid4().hex()[:4])

    def _local_addr(self):
        return socket.gethostbyname(socket.gethostname())

    def _remote_addr(self):
        return socket.gethostbyname(socket.getfqdn())

    def _rtp_port(self):
        return random.randint(*PORT_RANGE)

    def __str__(self):
        # TODO: Refatorar para negociação de codecs
        if not self.version:
            self.version = 0
        if not self.origin:
            _id = self._session_id()
            self.origin = f"- {_id} {_id} IN IP4 {self._local_addr()}"
        if not self.session_name:
            self.session_name = "SDP"
        if not self.connection:
            self.connection = f"IN IP4 {self._local_addr()}"
        if not self.time:
            self.time = "0 0"
        if not self.media:
            self.media = [f"audio {self._rtp_port()} RTP/AVP 9 0 8 18 101"]
        if not self.attributes:
            self.attributes = [
                "rtpmap:0 PCMU/8000",
                "rtpmap:0 PCMA/8000",
                "rtpmap:101 telephone-event/8000",
                "fmtp:101 0-16",
                "sendrecv",
            ]
        return (
            f"v={self.version}\r\n"
            f"o={self.origin}\r\n"
            f"s={self.session_name}\r\n"
            f"c={self.connection}\r\n"
            f"t={self.time}\r\n"
            + "".join([f"m={x}\r\n" for x in self.media])
            + "".join([f"a={x}\r\n" for x in self.attributes])
            + "".join([f"{k}={v}\r\n" for k, v in self.extra_sdp])
            + "\r\n"
        )

    @classmethod
    def parser(raw: str) -> "SDPSession":
        data = re.findall(r"(\w+)=(.+)\r\n", raw)

        return SDPSession(
            session_name=data.get("s"),
            version=data.get("v"),
            origin=data.get("o"),
            connection=data.get("c"),
            time=data.get("t"),
            media=[x for x in data if x.startswith("m=")],
            attributes=[x for x in data if x.startswith("a=")],
            extra_sdp=[
                (k, v)
                for k, v in data
                if k
                not in (
                    "v",
                    "o",
                    "s",
                    "c",
                    "t",
                    "m",
                    "a",
                )
            ],
        )


@dataclass
class Message:
    first_line: RequestLine | ResponseLine
    header: Header
    body: SDPSession = None

    def __str__(self):
        return f"{self.first_line}{self.header}\r\n{self.body}" if self.body else ""

    @property
    def branch(self):
        return re.search(r"branch=(z9hG4bK[a-z-A-Z-0-9]+)", self.header.via_uri).group(1)
    
    @property
    def call_id(self):
        return self.header.call_id
    
    @property
    def local_tag(self):
        return re.search(r"tag=([a-z-A-Z-0-9]+)", self.header.from_uri).group(1)
    
    @property
    def remote_tag(self):
        return re.search(r"tag=([a-z-A-Z-0-9]+)", self.header.to_uri).group(1)
    
    @property
    def rport(self):
        return "rport" in self.header
    
    @property
    def contact_addr(self):
        return re.search(r"([0-9.]+)", self.header.contact).group(1)
    
    @property
    def via_addr(self):
        return re.search(r"([0-9.]+)", self.header.via_uri).group(1)
    
    def parser(raw: str) -> "Message":
        parts = re.split(r"\r\n\r\n", raw, maxsplit=1)
        _first_line = str(parts[0].split("\r\n")[0]).strip()
        _header = str(parts[0].split("\r\n")[1:]).strip()
        _body = str(parts[1] if len(parts) > 1 else "").strip()
        header = Header.parser(_header)
        body = SDPSession.parser(_body)
        if _first_line.startswith("SIP"):
            first_line = ResponseLine.parser(_first_line)
        else:
            first_line = RequestLine.parser(_first_line)
        return Message(first_line, header, body)

    def is_request(self):
        return isinstance(self.first_line, RequestLine)

    def is_response(self):
        return isinstance(self.first_line, ResponseLine)
