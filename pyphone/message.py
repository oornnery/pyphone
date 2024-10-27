#### SDP MESSAGE ####


'''
Session Initiation Protocol (INVITE)
    Request-Line: INVITE sip:c89e8bc576a8042f9ef14265d887@10.14.11.146:10060 SIP/2.0
        Method: INVITE
        Request-URI: sip:c89e8bc576a8042f9ef14265d887@10.14.11.146:10060
        [Resent Packet: False]
    Message Header
        Via: SIP/2.0/UDP sip.t1-n34.prod.n2p.io:6070;branch=z9hG4bKa072.958f57874d45e949b09bf1baee6cbbd8.0;rport
        From: "DirectCall Fabio Souza" <sip:1139959137@10.95.24.210>;tag=2a6c9ec2-02de-4865-83ed-1e24173cf2fd
        To: <sip:c89e8bc576a8042f9ef14265d887@10.95.17.192>
        Call-ID: d0c2bd2d-fbc8-4782-bf32-2c30c2d4d2dd
        [Generated Call-ID: d0c2bd2d-fbc8-4782-bf32-2c30c2d4d2dd]
        CSeq: 12422 INVITE
        Allow: OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, PUBLISH, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, MESSAGE, REFER
        Supported: timer, replaces, norefersub, histinfo
        Session-Expires: 1800
        Min-SE: 90
        P-Asserted-Identity: "DirectCall Fabio Souza" <sip:1139959137@10.95.24.210>
        Max-Forwards: 69
        User-Agent: Unite 3.0
        Content-Type: application/sdp
        Content-Length:   329
        Contact: <sip:btpsh-66e13c56-2da4a7-3bd28@sip.t1-n34.prod.n2p.io:6070>
    Message Body
        Session Description Protocol
        Session Description Protocol Version (v): 0
        Owner/Creator, Session Id (o): - 1781649977 1781649977 IN IP4 207.202.17.145
        Session Name (s): Asterisk
        Connection Information (c): IN IP4 207.202.17.145
        Time Description, active time (t): 0 0
        Media Description, name and address (m): audio 38942 RTP/AVP 0 8 9 18 101
        Media Attribute (a): maxptime:140
        Media Attribute (a): rtpmap:0 PCMU/8000
        Media Attribute (a): rtpmap:8 PCMA/8000
        Media Attribute (a): rtpmap:9 G722/8000
        Media Attribute (a): rtpmap:18 G729/8000
        Media Attribute (a): rtpmap:101 telephone-event/8000
        Media Attribute (a): fmtp:101 0-16
        Media Attribute (a): sendrecv
        Media Attribute (a): rtcp:38943
        Media Attribute (a): ptime:20
        [Generated Call-ID: d0c2bd2d-fbc8-4782-bf32-2c30c2d4d2dd]

'''

from pyphone.utils import EOL, SIPStatusCode, SIPMethod
from typing import Union, Dict, Any, Annotated, List, TypedDict
from enum import property, Enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from rich.panel import Panel



from pyphone.utils import (
    SIPStatusCode
)

# --- Enhanced Data Classes and Enums ---

class SIPParseError(Exception):
    """Custom exception for SIP parsing errors"""
    pass

class SIPValidationError(Exception):
    """Custom exception for SIP validation errors"""
    pass


class SIPMethod(Enum):
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

    @staticmethod
    def methods() -> List[str]:
        return [str(m) for m in SIPMethod]


class SIPMessage(ABC):
    def __init__(self):
        self.header: Dict[str, Any] = {}
        self.body: Dict[str, Any] = {}
        self.authentication: Dict[str, Any] = {}

    @abstractmethod
    def summary(self) -> str:
        """Generate raw summary of the SIP message"""
        pass

    @abstractmethod
    def parser(self, data: bytes) -> None:
        """Parse SIP message from data bytes"""
        pass
    
    def add_via():
        pass

    def add_from():
        pass

    def add_to():
        pass

    def add_call_id():
        pass

    def add_cseq():
        pass

    def add_contact():
        pass

    def add_user_agent():
        pass

    def add_content_type():
        pass

    def add_content_lenght():
        pass


class SIPRequest(SIPMessage):
    request_line: Dict[str, Any]
    headers: Dict[str, Any]
    body: Dict[str, Any]
    raw: bytes
    method: SIPMethod
    destination: str
    authentication: Dict[str, Any]
    status_code: SIPStatusCode
    
    def _generate_base_header(self,
            method: SIPMethod,
            from_uri: str,
            to_uri: str,
            contact_uri: str
        ) -> SIPMessage:
        """Generate base SIP message with common headers"""
        msg = SIPRequest()
        
        return msg

    def _gen_base_sdp():
        pass
    
    def _gen_register():
        """Generate register message"""

    def _gen_invite():
        """Generate INVITE message"""
    
    def _gen_ack():
        """Generate ACK message"""

    def _gen_bye():
        """Generate BYE message"""

    def _gen_cancel():
        """Generate CANCEL message"""

    def _gen_options():
        """Generate OPTIONS message"""

    def _gen_prack():
        """Generate PRACK message"""

    def _gen_subscribe():
        """Generate SUBSCRIBE message"""

    def _gen_notify():
        """Generate NOTIFY message"""

    def _gen_publish():
        """Generate PUBLISH message"""

    def _gen_info():
        """Generate INFO message"""

    def _gen_refer():
        """Generate REFER message"""

    def _gen_message():
        """Generate MESSAGE message"""

    def _gen_update():
        """Generate UPDATE message"""


class SIPResponse(SIPMessage):
    request_line: Dict[str, Any]
    headers: Dict[str, Any]
    body: Dict[str, Any]
    raw: bytes
    method: SIPMethod
    destination: str
    authentication: Dict[str, Any]
    status_code: SIPStatusCode
    
    @classmethod
    def build(status_code: SIPStatusCode):
        pass
    

    
# https://www.cs.columbia.edu/sip/compact.html
# https://www.cs.columbia.edu/sip/features.html
# TODO: implement supported https://datatracker.ietf.org/doc/html/rfc3261#section-20.37
# TODO: Implement allow events SUBSCRIBE


HEADER = {
    'via': [], # Via: SIP/2.0/UDP <local_address>:<port>;branch=<branch>.0;<params>
    'from': str, # From: "<user>" <sip:<username>@<local_address>>;tag=<tag>
    'to': str, # To: <sip:<destination>@<domain>>;tag=<tag>
    'call-id': str, # Call-ID: <id>
    'cseq': str, # CSeq: <id> <method>
    'allow': str, # Allow: <methods>
    'supported': str, # Supported: <supported>
    'session-expires': str, # Session-Expires: <exp>
    'max-forwards': str, # Max-Forwards: <max>
    'user-agent': str, # User-Agent: <user-agent>
    'allow-events': str, # Allow-Events: <events>
    'event': str, # Event: <event>
    'content-type': str, # Content-Type: application/sdp
    'content-leght': str, # Content-Length:   329
    'contact': str, # Contact: <sip:<username>@<domain>:<port>>
    'route': List[str],
    'record-route': List[str],
}



BODY = {
    'v': str, # v=0
    'o': str, # o=- 1781649977 1781649977 IN IP4 207.202.17.145
    's': str, # s=Asterisk
    'c': str, # c=IN IP4 207.202.17.145
    't': str, # t=0 0
    'm': str , # m=audio 38942 RTP/AVP 0 8 9 18 101
    'a': List[str] # a=rtpmap:0 PCMU/8000
}


class SIPHeader:
    """
    https://datatracker.ietf.org/doc/html/rfc3261
    """
    def __init__(self,
            via_uri: list[str] = None, # SIP/2.0/UDP 10.14.11.146:10060;rport=1024;received=187.75.34.66;branch=z9hG4bK8cafcde14db593eecde1f
            from_uri: str = None, # From: "1001" <sip:1001@pabx.org:5060>;tag=3882100124
            to_uri: str = None, # To: <sip:1002@pabx.org:5060>
            call_id: str = None, # Call-ID: 0_3882207522@10.14.11.146
            cseq: int = None, # CSeq: 1 INVITE
            contact_uri: str = None, # Contact: <sip:1001@10.14.11.146:10060>;expires=60
            content_type: str = None, # Content-Type: application/sdp
            content_encoding: str = None, # Content-Encoding: gzip
            allow: str = None, # Allow: INVITE, INFO, PRACK, ACK, BYE, CANCEL, OPTIONS, NOTIFY, REGISTER, SUBSCRIBE, REFER, PUBLISH, UPDATE, MESSAGE
            max_forwards: int = None, # Max-Forwards: 70
            user_agent: str = None, # User-Agent: PyPhone 0.1
            server: str = None, # Server: PyPhone 0.1
            allow_events: str = None, # Allow-Events: talk,hold,conference,refer,check-sync
            supported: str = None, # Supported: replaces,timer,norefersub,100rel,path,outbound
            session_expires: int = None, # Session-Expires: 1800
            route: list[str] = None, # Route: <sip:10.14.11.146:5060;lr>
            recorde_route: list[str] = None, # Record-Route: <sip:10.14.11.146:5060;lr>
            content_length: int = None, # Content-Length: 0
            generic_headers: list[tuple[str, str]] = None, # Dict of other headers
            ):
            self.via_uri = via_uri
            self.from_uri = from_uri
            self.to_uri = to_uri
            self.call_id = call_id
            self.cseq = cseq
            self.contact_uri = contact_uri
            self.content_type = content_type
            self.content_encoding = content_encoding
            self.allow = allow
            self.max_forwards = max_forwards
            self.user_agent = user_agent
            self.server = server
            self.allow_events = allow_events
            self.supported = supported
            self.session_expires = session_expires
            self.route = route
            self.recorde_route = recorde_route
            self.content_length = content_length
            self.generic_headers = generic_headers

    def __str__(self):
        sip = [
            *(f"Via: {via}" for via in self.via_uri if via),
            (f"From: {self.from_uri}" if self.from_uri else None),
            (f"To: {self.to_uri}" if self.to_uri else None),
            (f"Call-ID: {self.call_id}" if self.call_id else None),
            (f"CSeq: {self.cseq}" if self.cseq else None),
            (f"Contact: {self.contact_uri}" if self.contact_uri else None),
            (f"Content-Type: {self.content_type}" if self.content_type else None),
            (f"Content-Encoding: {self.content_encoding}" if self.content_encoding else None),
            (f"Allow: {self.allow}" if self.allow else None),
            (f"Allow-Events: {self.allow_events}" if self.allow_events else None),
            (f"Max-Forwards: {self.max_forwards}" if self.max_forwards else None),
            (f"User-Agent: {self.user_agent}" if self.user_agent else None),
            (f"Server: {self.server}" if self.server else None),
            (f"Supported: {self.supported}" if self.supported else None),
            (f"Session-Expires: {self.session_expires}" if self.session_expires else None),
            *(f"Route: {route}" for route in self.route if route),
            *(f"Record-Route: {recorde_route}" for recorde_route in self.recorde_route if recorde_route),
            (f"Content-Length: {self.content_length}" if self.content_length else None),
            *(f"{g[0]}: {g[1]}" for g in self.generic_headers if self.generic_headers != []),
        ]
        return f'{EOL}'.join([_ for _ in sip if _]) + EOL

    def __repr__(self):
        return self.__str__()

    @classmethod
    def parser(cls, message: str) -> 'SIPHeader':
        lines = message.strip().split('\r\n')
        
        _via = [] # Via
        _from = None # From
        _to = None # To
        _call_id = None # Call-ID
        _cseq = None # CSeq
        _ctt_uri = None # Contact
        _cont_tp = None # Content-Type
        _cont_enc = None # Content-Encoding
        _max_fw = None # Max-Forword
        _user_ag = None # User-Agent
        _server = None # Server
        _allow = None # Allow
        _allow_ev = None # Allow-Events
        _supptd = None # Supported
        _sessn_exp = None # Session-Expires
        _route = [] # Route
        _rec_route = [] # Record-Route
        _cont_len = 0 #  Content-Lenght
        _generic_head = []
        for _l in lines:
            _l = _l.split(': ', maxsplit=1)
            if not _l or len(_l) < 2 or '=' in _l[0]:
                continue
            match _l[0]:
                case 'Via' | 'v':
                    _via.append(_l[1])
                case 'From':
                    _from = _l[1]
                case 'To':
                    _to = _l[1]
                case 'Call-ID':
                    _call_id = _l[1]
                case 'CSeq':
                    _cseq = _l[1]
                case 'Contact':
                    _ctt_uri = _l[1]
                case 'Content-Type':
                    _cont_tp = _l[1]
                case 'Content-Length':
                    _cont_len = int(_l[1])
                case 'Allow':
                    _allow = _l[1]
                case 'Max-Forwards':
                    _max_fw = _l[1]
                case 'User-Agent':
                    _user_ag = _l[1]
                case 'Server':
                    _server = _l[1]
                case 'Allow-Events':
                    _allow_ev = _l[1]
                case 'Supported':
                    _supptd = _l[1]
                case 'Session-Expires':
                    _sessn_exp = _l[1]
                case 'Route':
                    _route.append(_l[1])
                case 'Record-Route':
                    _rec_route.append(_l[1])
                case _:
                    _generic_head.append((_l[0], _l[1]))

        return cls(
            via_uri = _via,
            from_uri = _from,
            to_uri = _to,
            call_id = _call_id,
            cseq = _cseq,
            contact_uri = _ctt_uri,
            content_type = _cont_tp,
            content_encoding = _cont_enc,
            max_forwards = _max_fw,
            user_agent = _user_ag,
            server = _server,
            allow = _allow,
            allow_events = _allow_ev,
            supported = _supptd,
            session_expires = _sessn_exp,
            route = _route,
            recorde_route = _rec_route,
            content_length = _cont_len,
            generic_headers = _generic_head,
        )


class SDPBody:
    """
    https://datatracker.ietf.org/doc/html/rfc2327
    """
    
    def __init__(self,
                # Session description
                protocol_version: Annotated[int, 'v=0'] = 0,
                originator_information: Annotated[str, 'o=root 42852867 42852867 IN IP4 10.130.130.114'] = None,
                session_name: Annotated[str, 's=call'] = None,
                session_information: Annotated[str, 'i='] = None,
                uri: Annotated[str, 'u=call@10.130.130.114'] = None,
                email_address: Annotated[str, 'e=mjh@isi.edu'] = None,
                phone_number: Annotated[str, 'p=+1 617 253 6011'] = None,
                # Times description
                time_zone_adjustment: Annotated[str, 'z=2882844526 -1h 2898848070 0'] = None,
                session_time: Annotated[tuple[str, str], 't=3034423619 3042462419'] = None,
                repeat_times: Annotated[list[tuple[str]], 'r=604800 3600 0 90000'] = [],
                # Media description
                media_information: Annotated[list[tuple[str]], 'm=audio 61896 RTP 0 8 3 101'] = [],
                media_title: Annotated[str, 'i='] = None,
                connection_information: Annotated[str, 'c=IN IP4 10.130.130.114'] = None,
                bandwith_information: Annotated[str, 'b=X-YZ:128'] = None,
                encryption_key: Annotated[str, 'k=base64:'] = None,
                media_attributes: Annotated[list[tuple[str]], 'a=rtpmap:0 pcmu/8000 a=rtpmap:8 pcma/8000 a=rtpmap:101 telephone-event/8000 a=fmtp:101 0-16 a=ptime:20 a=sendrecv'] = []
            ):
        # Session description
        self.protocol_version = protocol_version
        self.originator_information = originator_information
        self.session_name = session_name
        self.session_information = session_information
        self.uri = uri
        self.email_address = email_address
        self.phone_number = phone_number
        # Times description
        self.time_zone_adjustment = time_zone_adjustment
        self.session_time = session_time
        self.repeat_times = repeat_times
        # Media description
        self.media_information = media_information
        self.media_title = media_title
        self.connection_information = connection_information
        self.bandwith_information = bandwith_information
        self.encryption_key = encryption_key
        self.media_attributes = media_attributes
    
    def __str__(self) -> str:
        sdp = [
            (f'v={self.protocol_version}' if self.protocol_version else None),
            (f'o={self.originator_information}' if self.originator_information else None),
            (f's={self.session_name}' if self.session_name else None),
            (f'i={self.session_information}' if self.session_information else None),
            (f'u={self.uri}' if self.uri else None),
            (f'e={self.email_address}' if self.email_address else None),
            (f'p={self.phone_number}' if self.phone_number else None),
            (f'z={self.time_zone_adjustment}' if self.time_zone_adjustment else None),
            *(f't={t}' for t in self.session_time if self.session_time),
            (f'r={' '.join([r for r in self.repeat_times if self.repeat_times])}'),
            (f'm={' '.join([m for m in self.media_information if self.media_information])}'),
            (f'i={self.media_title}' if self.media_title else None),
            (f'c={self.connection_information}' if self.connection_information else None),
            (f'b={self.bandwith_information}' if self.bandwith_information else None),
            (f'k={self.encryption_key}' if self.encryption_key else None),
            *(f'a={a}' for a in self.media_attributes if self.media_attributes),
        ]
        return f'{EOL}'.join([_ for _ in sdp if _]) + EOL

    def __repr__(self) -> str:
        return self.__str__()

    @classmethod
    def parser(cls, sdp_str: str) -> 'SDPBody':
        lines = sdp_str.strip().split('\r\n')
        _v = 0
        _o = None
        _s = None
        _i = None
        _u = None
        _e = None
        _p = None
        _c = None
        _b = None
        _k = None
        _z = []
        _t = []
        _r = []
        _m = []
        _a = []
        for _l in lines:
            if not _l:
                continue
            match _l[:2]:
                case 'v=':
                    _v = _l[2:]
                case 'o=':
                    _o = _l[2:]
                case 's=':
                    _s = _l[2:]
                case 'i=':
                    _i = _l[2:]
                case 'u=':
                    _u = _l[2:]
                case 'e=':
                    _e = _l[2:]
                case 'p=':
                    _p = _l[2:]
                case 'c=':
                    _c = _l[2:]
                case 'b=':
                    _b = _l[2:]
                case 'k=':
                    _k = _l[2:]
                case 'z=':
                    _z.append((_l[2:]))
                case 't=':
                    _t.append(_l[2:])
                case 'r=':
                    _r.append((_l[2:]))
                case 'm=':
                    _m.append((_l[2:]))
                case 'a=':
                    _a.append((_l[2:]))
                case _:
                    print(f'Unknown SDP: {_l}')

        return cls(
            protocol_version=_v,
            originator_information=_o,
            session_name=_s,
            session_information=_i,
            uri=_u,
            email_address=_e,
            phone_number=_u,
            time_zone_adjustment=_z,
            session_time=_t,
            repeat_times=_r,
            media_information=_m,
            connection_information=_c,
            bandwith_information=_b,
            encryption_key=_k,
            media_attributes=_a,
        )



class SIPRequest(SIPMessage):
    def __init__(self, method: SIPMethod, uri: str, header: SIPHeader, sdp: SDPBody = None):
        self.method = method
        self.uri = uri
        self.header = header
        self.sdp = sdp
        super().__init__()
        
    def __str__(self):
        req = [
            f'{self.method} {self.uri} SIP/2.0',
            self.header,
            (self.sdp if self.sdp else None),
        ]
        return f'{EOL}'.join([str(_) for _ in req if _])

    def __rich__(self):
        return Panel(self.__str__(), title='SIP Request', highlight=True, expand=False)

    def to_bytes(self):
        return str(self).encode()


class SIPResponse(SIPMessage):
    def __init__(self, status_code: SIPStatusCode, uri: str, header: SIPHeader, sdp: SDPBody = None):
        self.status_code = status_code
        self.uri = uri
        self.header = header
        self.sdp = sdp
        super().__init__()

    def __str__(self):
        req = [
            f'SIP/2.0 {self.status_code}',
            self.header,
            (self.sdp if self.sdp else None),
        ]
        return f'{EOL}'.join([str(_) for _ in req if _])

    def __rich__(self):
        return Panel(self.__str__(), title='SIP Request', highlight=True, expand=False)

    def to_bytes(self):
        return str(self).encode()