from enum import Enum
from typing import List
import uuid
import logging
from rich.logging import RichHandler

__all__ = [
    
]


logging.basicConfig(
    level="NOTSET",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)

logger = logging.getLogger("rich")

EOL = r'\r\n'
SIP_SCHEME = 'SIP'
SIP_VERSION = '2.0'
SIP_BRANCH = 'z9hG4bK'
SIP_MAX_FORWARDS = 70
SIP_CONTENT = "application"
SIP_CONTENT_TYPE = "sdp"

COMPACT_HEADERS = {
    "v": "via",
    "f": "from",
    "t": "to",
    "m": "contact",
    "i": "call-id",
    "e": "contact-encoding",
    "l": "content-length",
    "c": "content-type",
    "s": "subject",
    "k": "supported",
}

HEADERS = {
    "via": "Via",
    "from": "From",
    "to": "To",
    "contact": "Contact",
    "call-id": "Call-ID",
    "cseq": "CSeq",
    "max-forwards": "Max-Forwards",
    "content-length": "Content-Length",
    "content-type": "Content-Type",
    "authorization": "Authorization",
    "www-authenticate": "WWW-Authenticate",
    "proxy-authenticate": "Proxy-Authenticate",
}

SDP_HEADERS = {
    "version": "v",
    "origin": "o",
    "session_name": "s",
    "connection_info": "c",
    "bandwidth_info": "b",
    "time_description": "t",
    "media_description": "m",
    "attribute": "a",
    "email_address": "e",
    "phone_number": "p",
    "uri": "u",
    "repeat_time": "r",
    "time_zone": "z",
}


class SipMethod(Enum):
    REGISTER = "REGISTER"
    INVITE = "INVITE"
    ACK = "ACK"
    BYE = "BYE"
    CANCEL = "CANCEL"
    OPTIONS = "OPTIONS"
    PRACK = "PRACK"
    SUBSCRIBE = "SUBSCRIBE"
    NOTIFY = "NOTIFY"
    PUBLISH = "PUBLISH"
    INFO = "INFO"
    REFER = "REFER"
    MESSAGE = "MESSAGE"
    UPDATE = "UPDATE"

    def __str__(self) -> str:
        return self._value_

    def __repr__(self):
        return self.__str__()
    
    @classmethod
    def methods(cls) -> List[str]:
        return [method for method in cls]
    
    @classmethod
    def from_string(cls, method: str) -> 'SipMethod':
        return cls(method.upper())


class SipStatusCode(Enum):
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

    def __new__(cls, code, reason):
        obj = object.__new__(cls)
        obj._value_ = code
        obj.code = code
        obj.reason = reason
        return obj

    def __str__(self):
        return f'{self.code} {self.reason}'

    def __repr__(self):
        return self.__str__()

    def __contains__(self, code: int) -> bool:
        return code in [status.code for status in SipStatusCode]

    @classmethod
    def from_code(cls, code: int) -> 'SipStatusCode':
        for x in cls:
            if code == x.code:
                return x 
                



"""
Create class SipResponse/SipRequest for Sip Status Codes and Sip Methods

for 302 

class MovedTemporarily302(SipMessage):
    def __init__(self):
        super().__init__()
        self.method_line = "SIP/2.0 302 Moved Temporarily\r\n"

    def append_contact(self, contact, weight):
        def create_sip_uri(contact, weight):
            return "<sip:{}>;q={}".format(contact, weight)
        if self._data["contact"]:
            self._data["contact"] = self._data["contact"] + "," + create_sip_uri(contact, weight)
        else:
            self._data["contact"] = self._data["contact"] + create_sip_uri(contact, weight)

    def clean_contact(self):
        self._data["contact"] = ""
"""

class ProtocolType(Enum):
    TCP = "TCP"
    UDP = "UDP"
    TLS = "TLS"
    
    def __str__(self):
        return self._value_


class DialogState(Enum):
    INIT = "INIT"
    EARLY = "EARLY"
    CONFIRMED = "CONFIRMED"
    TERMINATED = "TERMINATED"

    def __str__(self):
        return self.value


class TransactionState(Enum):
    TRYING = "TRYING"
    PROCEEDING = "PROCEEDING"
    COMPLETED = "COMPLETED"
    TERMINATED = "TERMINATED"


class MediaType(Enum):
    AUDIO = "audio"
    VIDEO = "video"
    MESSAGE = "message"

    def __str__(self):
        return self.value


class MediaSessionType(Enum):
    SENDRECV = "sendrecv"
    SENDONLY = "sendonly"
    RECVONLY = "recvonly"
    INACTIVE = "inactive"

    def __str__(self):
        return self.value


class CodecType(Enum):
    PCMU = ('0', 'pcmu', '8000')
    PCMA = ('8', 'pcma', '8000')

    def __new__(self, code: str, description: str, rate: str):
        obj = object.__new__(self)
        obj.code = code
        obj.description = description
        obj.rate = rate
        obj._value_ = code
        return obj

    @classmethod
    def codecs(cls) -> List[str]:
        return [codec for codec in cls]

    def __str__(self) -> str:
        return f'{self.code} {self.description}/{self.rate}'


class DtmfPayloadType(Enum):
    RFC_2833 = ('101', 'telephone-event', '8000', '101 0-16')

    def __new__(self, code: str, description: str, rate: str, fmtp: str):
        obj = object.__new__(self)
        obj.code = code
        obj.description = description
        obj.rate = rate
        obj.fmtp = fmtp
        return obj

    def __str__(self) -> str:
        return f'{self.code} {self.description}/{self.rate}'


class MediaProtocolType(Enum):
    RTP_AVP = 'RTP/AVP'
    RTCP = 'RTCP'

    def __str__(self) -> str:
        return self.value


def generate_branch():
    return f"z9hG4bK-{uuid.uuid4()[0:8]}"

def generate_call_id(host: str = '0.0.0.0'):
    return f'{host}@{uuid.uuid4()}'

def generate_tag():
    return str(uuid.uuid4()[0:6])