import binascii
from enum import Enum
import random
import re
import socket
import struct
import threading
import time
from typing import List


EOL = '\n\r'
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


class TransportProtocolType(Enum):
    def __str__(self):
        return self._value_

    def __repr__(self):
        return self.__str__()

    TLS = "TLS"
    TCP = "TCP"
    UDP = "UDP"


class MediaProtocolType(Enum):
    def __str__(self):
        return self._value_

    def __repr__(self):
        return self.__str__()

    RTP = "RTP"
    RTCP = "RTCP"


class MediaType(Enum):
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



if __name__ == "__main__":
    print(socket.SOCK_STREAM)