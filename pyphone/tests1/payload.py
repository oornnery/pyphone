from typing import List
from pyphone.core.utils import (
    EOL,
    cl,
    MediaType,
    MediaProtocolType,
    MediaSessionType,
    CodecType,
    DtmfPayloadType,
    parser_uri_to_str
)

from rich.panel import Panel

__all__ = [
    'Body',
    'MediaDescription',
    'SessionDescription',
    'TimeDescription',
    'SessionBandwidth',
    'SessionEncryption',
    'MediaType',
    'MediaProtocolType',
    'MediaSessionType',
    'CodecType',
    'DtmfPayloadType',
]

class SessionDescription:
    def __init__(self,
            username: str,
            address: str,
            address_type: str = 'IP4',
            network_type: str = 'IN',
            uri: str = None,
            session_version: int = None,
            session_id: int = None,
            session_name: str = None,
            session_email: str = None,
            session_phone: str = None,
            version: str = 0,
        ):
        self.username = username
        self.session_id = session_id
        self.session_version = session_version
        self.session_name = session_name
        self.uri = uri
        self.address = address
        self.address_type = address_type
        self.network_type = network_type
        self.version = version
        self.session_email = session_email
        self.session_phone = session_phone

    def __str__(self) -> str:
        sdp = f'v={self.version}{EOL}'
        sdp += f"o={self.username} {self.session_id} {self.session_version} {self.network_type} {self.address_type} {self.address}{EOL}"
        sdp += f"s={self.session_name}{EOL}"
        sdp += f"c={self.network_type} {self.address_type} {self.address}{EOL}"
        sdp += f'u={self.uri}{EOL}'
        if self.session_email:
            sdp += f'e={self.session_email}{EOL}'
        if self.session_phone:
            sdp += f'p={self.session_phone}{EOL}'
        return sdp


class TimeDescription:
    def __init__(self, start_time: str = '0', stop_time: str = '0'):
        self.start_time = start_time
        self.stop_time = stop_time

    def __str__(self) -> str:
        return f"t={self.start_time} {self.stop_time}{EOL}"


class SessionBandwidth:
    def __init__(self, bandwidth: str, bandwidth_type: str = 'BANDWIDTH'):
        self.bandwidth = bandwidth
        self.bandwidth_type = bandwidth_type
    
    def __str__(self) -> str:
        return f"b={self.bandwidth_type}:{self.bandwidth}{EOL}"


class SessionEncryption:
    def __init__(self, method: str, encryption: str):
        self.method = method
        self.encryption = encryption

    def __str__(self) -> str:
        return f"k={self.method}:{self.encryption}{EOL}"


class MediaDescription:
    """
    Media Description section

    Media name and Transport address - m=audio 61896 RTP 0 8 3 101

    audio = Media type of stream. This can also be video, message, audio etc.
    61896 = The port number on which the media stream will be transmitted.
    RTP = The protocol which will be used to stream the media, in this case Real Time Protocol.
    0 = The code specifying the codec, in this case codec 0 = G.711 PCMU.
    8 = The code specifying the codec, in this case codec 8 = G.711 PCMA.
    3 = The code specifying the codec, in this case codec 3 = GSM.
    101 = DTMF payload type number the SIP phone supports.
    Session attribute lines
    a=rtpmap:0 pcmu/8000
    a=rtpmap:8 pcma/8000
    a=rtpmap:3 gsm/8000
    For each Codec being advertised in the above SDP capture, details about Media Attributes Fieldname, Media format and Media type is given separately. Note that the codec’s are listed depending on priority set by the user from the phone set’s configuration options.

    a=rtpmap:101 telephone-event/8000
    a=fmtp:101 0-16
    The above fields describe the DTMF the phone supports (telephone-events). Such phone supports DTMF payload type number 101, and DTMF tones events from 0 to 16 with a sample rate of 8000 Hertz. Note that as a DTMF standard, all SIP entities should at least support DTMF events from 0 to 15, which are 0-9 (numbers), 10 = *, 11 = # and 12 -15 are A-D.

    a=ptime:20
    Samples per packet / packetization time. Field is optional but it is recommended for the encoding / packetization of audio or video stream. If no ptime is specified, it means that the remote SIP entity uses whatever packetization time it prefers.

    a=sendrecv
    sendrecv = Session is send and receive, therefore the SIP phone is ready to send media streams and receive also. This can be also be sendonly or recvonly, for example when a phone is placed on hold and will only receive media streams, i.e. music on hold from an IP PBX or VoIP provider.
    """
    def __init__(self, 
        port: int,
        media_type: MediaType = MediaType.AUDIO,
        protocol: MediaProtocolType = MediaProtocolType.RTP,
        codec_type: List[CodecType] = [CodecType.PCMU, CodecType.PCMA],
        dtmf_payload_type: DtmfPayloadType = DtmfPayloadType.RFC_2833,
        packet_time: int = 20,
        media_session_type: MediaSessionType = MediaSessionType.SENDRECV
        ):
        self.media_type = media_type
        self.port = port
        self.protocol = protocol
        self.codec_type = codec_type
        self.dtmf_payload_type = dtmf_payload_type
        self.packet_time = packet_time
        self.media_session_type = media_session_type

    def __str__(self) -> str:
        codec_type = ' '.join([c.value for c in self.codec_type])

        sdp = f"m={self.media_type.value} {self.port} {self.protocol.value} {codec_type} {self.dtmf_payload_type.value}{EOL}"
        for codec in self.codec_type:
            sdp += f"a=rtpmap:{codec.value} {codec.description}{EOL}"
        sdp += f"a=rtpmap:{self.dtmf_payload_type.value} {self.dtmf_payload_type.description}{EOL}"
        sdp += f"a=fmtp:{self.dtmf_payload_type.value} {self.dtmf_payload_type.description}{EOL}"
        sdp += f"a=ptime:{self.packet_time}{EOL}"
        sdp += f"a={self.media_session_type.value}{EOL}"

        return sdp.strip()


class Body:
    """
    https://www.3cx.com/blog/voip-howto/sdp-voip/
    https://www.3cx.com/blog/voip-howto/sdp-voip2/
    
    SDP Capture in an INVITE SIP message
    
    Below is a capture of a SDP message sent from a SIP phone to an IP PBX it is registered to when trying to make a call:
    
    v=0
    o=root 42852867 42852867 IN IP4 10.130.130.114
    s=call
    c=IN IP4 10.130.130.114
    t=0 0
    m=audio 61896 RTP 0 8 3 101
    a=rtpmap:0 pcmu/8000
    a=rtpmap:8 pcma/8000
    a=rtpmap:3 gsm/8000
    a=rtpmap:101 telephone-event/8000
    a=fmtp:101 0-16
    a=ptime:20
    a=sendrecv
    """
    def __init__(self):
        self._session_description: SessionDescription = None
        self._time_description: TimeDescription = None
        self._media_description: MediaDescription = None
        self._session_bandwidth: SessionBandwidth = None
        self._session_encryption: SessionEncryption = None

    def __str__(self) -> str:        
        body = [
            self._session_description,
            self._time_description,
            self._media_description,
            self._session_bandwidth,
            self._session_encryption
            ]
        return "".join([str(b) for b in body if b])

    def __rich__(self) -> Panel:
        return Panel(self.__str__(), title="Body", highlight=True, expand=False)
    
    def to_bytes(self) -> bytes:
        return str(self).encode()

    @property
    def session_description(self) -> SessionDescription:
        return self._session_description

    @session_description.setter
    def session_description(self, session_description: SessionDescription):
        self._session_description = session_description
    
    @property
    def time_description(self) -> TimeDescription:
        return self._time_description

    @time_description.setter
    def time_description(self, time_description: TimeDescription):
        self._time_description = time_description
    
    @property
    def media_description(self) -> MediaDescription:
        return self._media_description

    @media_description.setter
    def media_description(self, media_description: MediaDescription):
        self._media_description = media_description
    
    @property
    def session_bandwidth(self) -> SessionBandwidth:
        return self._session_bandwidth

    @session_bandwidth.setter
    def session_bandwidth(self, session_bandwidth: SessionBandwidth):
        self._session_bandwidth = session_bandwidth
    
    @property
    def session_encryption(self) -> SessionEncryption:
        return self._session_encryption

    @session_encryption.setter
    def session_encryption(self, session_encryption: SessionEncryption):
        self._session_encryption = session_encryption



class SdpPayload:
    __payload = ''
    
    def __init__(self):
        pass


def example():
    b = Body()
    b.session_description = SessionDescription(
        username='root',
        session_id=42852867,
        session_version=42852867,
        uri=parser_uri_to_str(username='root', address='10.130.130.114'),
        address='10.130.130.114',
    )
    b.time_description = TimeDescription(
        start_time=0,
        stop_time=0
    )
    b.media_description = MediaDescription(
        media_type=MediaType.AUDIO,
        port=61896,
        protocol=MediaProtocolType.RTP,
        codec_type=[CodecType.PCMU, CodecType.PCMA],
        dtmf_payload_type=DtmfPayloadType.RFC_2833,
        packet_time=20,
        media_session_type=MediaSessionType.SENDRECV
    )
    cl.print(b)
    cl.print(len(b.to_bytes()))
    cl.print(b.to_bytes())

if __name__ == "__main__":
    from rich import print
    print(example())
    
