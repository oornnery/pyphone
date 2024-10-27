import logging
from enum import Enum
from typing import Dict, List, AnyStr

from rich.console import Console
from rich.logging import RichHandler

cl = Console()

logging.basicConfig(
    level="NOTSET",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, console=cl)],
)

log = logging.getLogger("rich")


class SipStatusCode(Enum):
    """
    - https://en.wikipedia.org/wiki/List_of_SIP_response_codes
    - https://en.wikipedia.org/wiki/ISDN_User_Part
    - https://docs.asterisk.org/Configuration/Miscellaneous/Hangup-Cause-Mappings/
    """

    def __new__(cls, code, reason_phrase, rel):
        obj = object.__new__(cls)
        obj._value_ = code
        obj.code = code
        obj.reason_phrase = reason_phrase
        obj.rel = rel
        return obj

    def __str__(self) -> str:
        return self._value_

    TRYING = (100, "Trying", "")
    RINGING = (180, "Ringing", "")
    CALL_IS_BEING_FORWARDED = (181, "Call is being forwarded", "")
    QUEUED = (182, "Queued", "")
    SESSION_PROGRESS = (183, "Session Progress", "")
    EARLY_DIALOG_TERMINATED = (199, "Early Dialog Terminated", "")

    OK = (200, "OK", "")
    ACCEPTED = (202, "Accepted", "")
    NO_NOTIFICATION = (204, "No Notification", "")

    MULTIPLE_CHOICES = (300, "Multiple Choices", "")
    MOVED_PERMANENTLY = (301, "Moved Permanently", "")
    MOVED_TEMPORARILY = (302, "Moved Temporarily", "")
    USE_PROXY = (305, "Use Proxy", "")
    ALTERNATIVE_SERVICE = (380, "Alternative Service", "")

    BAD_REQUEST = (400, "Bad Request", "")
    UNAUTHORIZED = (401, "Unauthorized", "")
    FORBIDDEN = (403, "Forbidden", "")
    NOT_FOUND = (404, "Not Found", "")
    METHOD_NOT_ALLOWED = (405, "Method Not Allowed", "")
    NOT_ACCEPTABLE = (406, "Not Acceptable", "")
    PROXY_AUTHENTICATION_REQUIRED = (407, "Proxy Authentication Required", "")
    REQUEST_TIMEOUT = (408, "Request Timeout", "")
    CONFLICT = (409, "Conflict", "")
    GONE = (410, "Gone", "")
    LENGTH_REQUIRED = (411, "Length Required", "")
    CONDITIONAL_REQUEST_FAILED = (412, "Conditional Request Failed", "")
    REQUEST_ENTITY_TOO_LARGE = (413, "Request Entity Too Large", "")
    REQUEST_URI_TOO_LONG = (414, "Request-URI Too Long", "")
    UNSUPPORTED_MEDIA_TYPE = (415, "Unsupported Media Type", "")
    UNSUPPORTED_URI_SCHEME = (416, "Unsupported URI Scheme", "")
    UNKNOWN_RESOURCE_PRIORITY = (417, "Unknown Resource-Priority", "")
    BAD_EXTENSION = (420, "Bad Extension", "")
    EXTENSION_REQUIRED = (421, "Extension Required", "")
    SESSION_INTERVAL_TOO_SMALL = (422, "Session Interval Too Small", "")
    INTERVAL_TOO_BRIEF = (423, "Interval Too Brief", "")
    BAD_LOCATION_INFORMATION = (424, "Bad Location Information", "")
    USE_IDENTITY_HEADER = (428, "Use Identity Header", "")
    PROVIDE_REFERRER_IDENTITY = (429, "Provide Referrer Identity", "")
    FLOW_FAILED = (430, "Flow Failed", "")
    ANONYMITY_DISALLOWED = (433, "Anonymity Disallowed", "")
    BAD_IDENTITY_INFO = (436, "Bad Identity-Info", "")
    UNSUPPORTED_CERTIFICATE = (437, "Unsupported Certificate", "")
    INVALID_IDENTITY_HEADER = (438, "Invalid Identity Header", "")
    FIRST_HOP_LACKS_OUTBOUND_SUPPORT = (439, "First Hop Lacks Outbound Support", "")
    MAX_BREADTH_EXCEEDED = (440, "Max-Breadth Exceeded", "")
    BAD_INFO_PACKAGE = (469, "Bad Info Package", "")
    CONSENT_NEEDED = (470, "Consent Needed", "")
    TEMPORARILY_UNAVAILABLE = (480, "Temporarily Unavailable", "")
    CALL_TRANSACTION_DOES_NOT_EXIST = (481, "Call/Transaction Does Not Exist", "")
    LOOP_DETECTED = (482, "Loop Detected", "")
    TOO_MANY_HOPS = (483, "Too Many Hops", "")
    ADDRESS_INCOMPLETE = (484, "Address Incomplete", "")
    AMBIGUOUS = (485, "Ambiguous", "")
    BUSY_HERE = (486, "Busy Here", "")
    REQUEST_TERMINATED = (487, "Request Terminated", "")
    NOT_ACCEPTABLE_HERE = (488, "Not Acceptable Here", "")
    BAD_EVENT = (491, "Bad Event", "")
    REQUEST_PENDING = (493, "Request Pending", "")
    UNDECIPHERABLE = (494, "Undecipherable", "")
    SECURITY_AGREEMENT_REQUIRED = (494, "Security Agreement Required", "")

    SERVER_INTERNAL_ERROR = (500, "Server Internal Error", "")
    NOT_IMPLEMENTED = (501, "Not Implemented", "")
    BAD_GATEWAY = (502, "Bad Gateway", "")
    SERVICE_UNAVAILABLE = (503, "Service Unavailable", "")
    SERVER_TIMEOUT = (504, "Server Time-out", "")
    VERSION_NOT_SUPPORTED = (505, "Version Not Supported", "")
    MESSAGE_TOO_LARGE = (513, "Message Too Large", "")
    PUSH_NOTIFICATION_SERVICE_NOT_SUPPORTED = (
        555,
        "Push Notification Service Not Supported",
        "",
    )
    PRECONDITION_FAILURE = (580, "Precondition Failure", "")

    BUSY_EVERYWHERE = (600, "Busy Everywhere", "")
    DECLINE = (603, "Decline", "")
    DOES_NOT_EXIST_ANYWHERE = (604, "Does Not Exist Anywhere", "")
    UNWANTED = (607, "Unwanted", "")


class CodecType(Enum):
    PCMU = ('0', '0 pcmu/8000')
    PCMA = ('8', '8 pcma/8000')
    GSM = ('3', '3 gsm/8000')

    def __new__(self, code: str, description: str):
        obj = object.__new__(self)
        obj._value_ = code
        obj.description = description
        return obj


class DtmfPayloadType(Enum):
    RFC_2833 = ('101', 'telephone-event/8000', '101 0-16')

    def __new__(self, code: str, description: str, fmtp: str):
        obj = object.__new__(self)
        obj._value_ = code
        obj.description = description
        obj.fmtp = fmtp
        return obj


class MediaType(Enum):
    AUDIO = 'audio'
    VIDEO = 'video'
    MESSAGE = 'message'


class MediaSessionType(Enum):
    SENDRECV = 'sendrecv'
    SENDONLY = 'sendonly'
    RECVONLY = 'recvonly'


class MediaProtocolType(Enum):
    RTP = 'RTP'
    RTCP = 'RTCP'

class ProtocolType(Enum):
    UDP = "UDP"
    TCP = "TCP"
    TLS = "TLS"
    WS = "WS"

    def __str__(self) -> str:
        return self._value_


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

EOL = '\n\r'
SIP_SCHEME = 'SIP'
SIP_VERSION = '2.0'
SIP_BRANCH = 'z9hG4bK'
SIP_METHODS = [
    SipMethod.INVITE,
    SipMethod.ACK,
    SipMethod.BYE,
    SipMethod.CANCEL,
    SipMethod.REGISTER,
    SipMethod.OPTIONS,
    SipMethod.SUBSCRIBE,
    SipMethod.NOTIFY,
    SipMethod.UPDATE
    ]
SIP_MAX_FORWARDS = 70
SIP_CONTENT = "application"
SIP_CONTENT_TYPE = "sdp"
SIP_SUPPORTED = []
SIP_UNSUPPORTED = []
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

def parser_params_to_str(params: Dict[str, str]) -> str:
    if not params:
        return ''
    return ''.join([f';{k}={v}' for k, v in params.items()])


def parser_uri_to_str(address: str, user: str = None, port: int = None, params: Dict[str, str] = None, scheme: str = SIP_SCHEME) -> str:
    _user = (f'{scheme.lower()}:{user}@' if user else '')
    _port = (f':{port}' if port else '')
    _params = (parser_params_to_str(params) if params else '')
    return f'{_user}{address}{_port}{_params}'
