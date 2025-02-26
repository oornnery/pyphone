@dataclass
class Address:
    username: str
    domain: str
    port: int
    branch: str
    params: dict

@dataclass
class URI:
    scheme: str
    address: Address
    tag: str
    params: dict

class HeaderField:
    name: str
    value: str
    
    def __str__(self):
        return f"{self.name}: {self.value}"

class Method(Enum):
    ACK = "ACK"
    BYE = "BYE"
    CANCEL = "CANCEL"
    INVITE = "INVITE"
    OPTIONS = "OPTIONS"
    REGISTER = "REGISTER"


class Status(Enum):
    TRYING = (100, "Trying")
    RINGING = (180, "Ringing")
    SESSION_IN_PROGRESS = (183, "Session in Progress")
    OK = (200, "OK")
    BAD_REQUEST = (400, "Bad Request")
    UNAUTHORIZED = (401, "Unauthorized")
    FORBIDDEN = (403, "Forbidden")
    NOT_FOUND = (404, "Not Found")
    METHOD_NOT_ALLOWED = (405, "Method Not Allowed")
    NOT_ACCEPTABLE = (406, "Not Acceptable")
    REQUEST_TIMEOUT = (408, "Request Timeout")
    REQUEST_ENTITY_TOO_LARGE = (413, "Request Entity Too Large")
    REQUEST_URI_TOO_LONG = (414, "Request-URI Too Long")
    UNSUPPORTED_MEDIA_TYPE = (415, "Unsupported Media Type")
    UNSUPPORTED_URI_SCHEME = (416, "Unsupported URI Scheme")
    BAD_EXTENSION = (420, "Bad Extension")
    EXTENSION_REQUIRED = (421, "Extension Required")
    TEMPORARILY_UNAVAILABLE = (480, "Temporarily Unavailable")
    CALL_OR_TRANSACTION_DOES_NOT_EXIST = (481, "Call/Transaction Does Not Exist")
    ADDRESS_INCOMPLETE = (484, "Address Incomplete")
    AMBIGUOUS = (485, "Ambiguous")
    BUSY_HERE = (486, "Busy Here")
    REQUEST_TERMINATED = (487, "Request Terminated")
    NOT_ACCEPTABLE_HERE = (488, "Not Acceptable Here")
    REQUEST_PENDING = (491, "Request Pending")
    SERVER_INTERNAL_ERROR = (500, "Server Internal Error")
    NOT_IMPLEMENTED = (501, "Not Implemented")
    SERVICE_UNAVAILABLE = (503, "Service Unavailable")
    SERVER_TIMEOUT = (504, "Server Timeout")
    MESSAGE_TOO_LARGE = (513, "Message Too Large")
    BUSY_EVERYWHERE = (600, "Busy Everywhere")
    DECLINE = (603, "Decline")
    GENERIC = (0, "")
    
    def __new__(cls, code, phrase):
        obj = object.__new__(cls)
        obj._value_ = code
        obj.phrase = phrase
        return obj
    
    def __call__(self, code, phrase):
        return self.__class__(code, phrase)

def sip_options_callback(data, addr=None):
    print("\nSIP OPTIONS callback\n")
    if addr:
        print(f"Received response from {addr}: \n{data.decode()}\n")
    else:
        print(f"Received response: {data.decode()}\n")

# Configuration for sending SIP OPTIONS packets
cfg = ConnCfg(
    remote_addr="demo.mizu-voip.com",
    remote_port=37075,
    protocol="UDP"
)

handler = ConnectionHandler(cfg, sip_options_callback)
handler.start()

# Create SIP OPTIONS packet
sip_options_packet = (
    "OPTIONS sip:demo.mizu-voip.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK776asdhds\r\n"
    "Max-Forwards: 70\r\n"
    "To: <sip:demo.mizu-voip.com>\r\n"
    "From: <sip:client@127.0.0.1>;tag=1928301774\r\n"
    "Call-ID: a84b4c76e66710@127.0.0.1\r\n"
    "CSeq: 63104 OPTIONS\r\n"
    "Contact: <sip:client@127.0.0.1>\r\n"
    "Accept: application/sdp\r\n"
    "Content-Length: 0\r\n\r\n"
).encode()

# Send SIP OPTIONS packet
handler.send(sip_options_packet)

# Wait for responses
print("Waiting for responses...\n")

input("Press Enter to finish...\n")
# Finalize the test
handler.stop()
print("Test finished.\n")
