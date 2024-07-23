import time
import sys
import dotenv
import pjsua2 as pj
import logging


from enum import Enum, IntEnum
from dataclasses import dataclass, field
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
# from rich import print


console = Console()
env = dotenv.dotenv_values(".env")



# @dataclass
# class UaConfig:
#     maxCalls: Optional[int] = 2
#     userAgent: Optional[str] = "pyphone"
#     threadCnt: Optional[int] = 0
#     mainThreadOnly: Optional[bool] = False
#     nameserver: Optional[List[str]] = []
#     outboundProxies: Optional[List[str]] = []
#     stunServer: Optional[List[str]] = []
#     stunTryIpv6: Optional[bool] = False
#     stunIgnoreFailure: Optional[bool] = True
#     natTypeInSdp: Optional[int] = 2
#     mwiUnsolicitedEnabled: Optional[bool] = False
#     enableUpnp: Optional[bool] = False
#     upnpIfName: Optional[str] = ""

# @dataclass
# class LogConfig:
#     msgLogging: int
#     level: int
#     consoleLevel: int
#     decor: int
#     filename: str
#     fileFlags: int
#     writer: 'LogWriter'  # Assuming LogWriter is another dataclass or custom class

# @dataclass
# class MediaConfig:
#     clockRate: int
#     sndClockRate: int
#     channelCount: int
#     audioFramePtime: int
#     maxMediaPorts: int
#     hasIoqueue: bool
#     threadCnt: int
#     quality: int
#     ptime: int
#     noVad: bool
#     ilbcMode: int
#     txDropPct: int
#     rxDropPct: int
#     ecOptions: int
#     ecTailLen: int
#     sndRecLatency: int
#     sndPlayLatency: int
#     jbInit: int
#     jbMinPre: int
#     jbMaxPre: int
#     jbMax: int
#     jbDiscardAlgo: 'pjmedia_jb_discard_algo'
#     sndAutoCloseTime: int
#     vidPreviewEnableNative: bool


USE_THREADS = True

# Configuração de logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('pjsua2')


class SIP_TRANSPORT(IntEnum):
    UDP = pj.PJSIP_TRANSPORT_UDP
    TCP = pj.PJSIP_TRANSPORT_TCP
    TLS = pj.PJSIP_TRANSPORT_TLS


class UaConfig(pj.UaConfig):
    def __init__(self):
        super().__init__()
        if USE_THREADS:
            self.threadCnt = 1
            self.mainThreadCnt = False
        else:
            self.threadCnt = 0
            self.mainThreadCnt = True
        self.userAgent = f"pyphone-pjsua2"
        self.maxCalls = 4


class LogConfig(pj.LogConfig):
    def __init__(self):
        super().__init__()
       #self.logConfig.writer = self.logger
        self.filename = "logs/pyphone.log"
        self.fileFlags = pj.PJ_O_APPEND
        self.level = 5
        self.consoleLevel = 5


class MediaConfig(pj.MediaConfig):
    def __init__(self):
        super().__init__()
        self.clockRate = 16000
        self.channelCount = 1
        self.ptime = 20
        self.threadCnt = 1
        self.quality = 10
        self.ecTailLen = 0
        self.threadPrio = 0


class EpConfig(pj.EpConfig):
    def __init__(self):
        super().__init__()
        self.uaConfig = UaConfig()
        self.logConfig = LogConfig()
        self.medConfig = MediaConfig()


class TransportConfig(pj.TransportConfig):
    def __init__(self):
        super().__init__()
        self.port = 10060
        self.randomizePort = True
        self.publicAddress = "0.0.0.0"
        self.boundAddress = "0.0.0.0"
        # self.qosType = 1
        # self.qosParams = pj.QosParams()


class Endpoint(pj.Endpoint):
    def __init__(self, *args):
        super().__init__(*args)
        self.libCreate()
        self.libInit(
            prmEpConfig=EpConfig()
        )

        self.codecSetPriority("PCMU/8000", 255)
        self.codecSetPriority("PCMA/8000", 254)
        # Create SIP transport. Error handling sample is shown

        # Configuração de transporte

        self.transportCreate(
            SIP_TRANSPORT.UDP, 
            TransportConfig()
            )
        # start the library
        self.libStart()


class AuthCredInfo(pj.AuthCredInfo):
    def __init__(self, username: str, password: str, *args):
        super().__init__(*args)
        self.scheme = "digest"
        self.username = username
        self.realm = "*"
        self.username = username
        self.data = password


class AccountConfig(pj.AccountConfig):
    def __init__(self, username: str, password: str, domain: str, *args):
        super().__init__(*args)
        # Basic settings
        self.priority = 0
        self.idUri = f"sip:{username}@{domain}"
        self.regConfig.registrarUri = f"sip:{username}@{domain}"
        self.regConfig.registerOnAdd = True
        
        # Create the account
        self.sipConfig.authCreds.append(
            AuthCredInfo(
                username=username,
                password=password
            )
        )
        
        # self.sipConfig.proxies = []
        self.sipConfig.outboundProxy = f"sip:{username}@{domain}"

        # SIP features
        # self.callConfig.prackUse = ...
        # self.callConfig.timerUse = ...
        # self.callConfig.timerSessExpiresSec = ...
        # self.presConfig.publishEnabled = ...
        # self.mwiConfig.enabled = ...
        # self.natConfig.contactRewriteUse = ... 
        # self.natConfig.viaRewriteUse = ... 
        # self.natConfig.sdpNatRewriteUse = ... 
        # self.natConfig.sipOutboundUse = ... 
        # self.natConfig.udpKaIntervalSec = ... 

        # # Media
        # self.mediaConfig.transportConfig.port = ...
        # self.mediaConfig.transportConfig.portRange = ...
        # self.mediaConfig.lockCodecEnabled = ...
        # self.mediaConfig.srtpUse = ...
        # self.mediaConfig.srtpSecureSignaling = ...
        # self.mediaConfig.ipv6Use = ... # pj.PJSUA_IPV6_ENABLED or pj.PJSUA_IPV6_DISABLED

        # # NAT
        # self.natConfig.sipStunUse = ... 
        # self.natConfig.mediaStunUse = ... 
        # `self.natConfig.iceEnabled = True` is setting the ICE (Interactive Connectivity
        # Establishment) feature to be enabled in the SIP account configuration. ICE is a technique
        # used in VoIP (Voice over Internet Protocol) communications to establish a connection between
        # two parties even when they are behind NAT (Network Address Translation) devices or
        # firewalls.
        # self.natConfig.iceEnabled = True
        # self.natConfig.iceAggressiveNomination = ...
        # self.natConfig.iceAlwaysUpdate = ...
        # self.natConfig.iceMaxHostCands = ...
        # self.natConfig.turnEnabled = ... 
        # self.natConfig.turnServer = ... 
        # self.natConfig.turnConnType = ... 
        # self.natConfig.turnUserName = ... 
        # self.natConfig.turnPasswordType = ...
        # self.natConfig.turnPassword = ... 


class Account(pj.Account):
    def __init__(self):
        super().__init__()

    def register(self, username, password, domain):
        self.create(
            AccountConfig(
                username=username,
                password=password,
                domain=domain
            )
        )


class VoIPManager(Endpoint):
    def __init__(self):
        super().__init__()

        # SIP account
        self.acc = Account()
        self.prm = pj.CallOpParam()
        self.call = pj.Call(self.acc)


    def register(self, username, password, domain):
        self.acc.register(
            username=username,
            password=password,
            domain=domain,
        )
    
    def set_presence_status(self):
        status = pj.PresenceStatus()
        status.status = pj.PJSUA_BUDDY_STATUS_ONLINE
        self.acc.setOnlineStatus(status)

    def unregister(self):
        self.acc.shutdown()

    def account_info(self):
        return self.acc.getInfo()
    
    def make_call(self, destination):
        prm = pj.CallOpParam(True)
        prm.opt.audioCount = 1
        prm.opt.videoCount = 0
        dest_uri = f"sip:{destination}@{env.get('DOMAIN')}"
        return self.call.makeCall(dest_uri, prm)

    def hangup(self):
        self.prm.statusCode = pj.PJSIP_SC_REQUEST_TERMINATED
        self.call.hangup(self.prm)

    def set_callback(self, callback_function):
        # Aqui você pode definir um callback para eventos específicos, como chamadas recebidas
        # Isso pode ser feito sobrescrevendo os métodos de callback na classe CallCallback
        pass
    
    def call_info(self):
        return self.call.getInfo()
    
    def quit(self):
        if self.call.getInfo().state != pj.PJSIP_INV_STATE_DISCONNECTED:
            self.hangup()
        # if self.acc.calls.count > 0:
        #     for call in self.acc.calls:
        #         call.hangup()
        if self.acc:
            self.unregister()
        self.ep.libDestroy()
        sys.exit(0)
    
# Exemplo de uso
if __name__ == "__main__":
    voip_manager = VoIPManager()
    voip_manager.register(env.get('USERNAME'), env.get('PASSWORD'), env.get('DOMAIN'))
    voip_manager.set_presence_status()

    def acc_info(vp: VoIPManager):
        console.print(
            Panel(
                Text(f"ID: {vp.acc.getInfo().id}\n\
                    URI: {vp.acc.getInfo().uri}\n\
                    Reg Configured: {vp.acc.getInfo().regIsConfigured}\n\
                    Reg Active: {vp.acc.getInfo().regIsActive}\n\
                    Reg Expires: {vp.acc.getInfo().regExpiresSec}\n\
                    Reg Status: {vp.acc.getInfo().regStatus}\n\
                    Reg Status Text: {vp.acc.getInfo().regStatusText}\n\
                    Reg Last Err: {vp.acc.getInfo().regLastErr}\n\
                    Online Status: {vp.acc.getInfo().onlineStatus}\n\
                    Online Status Text: {vp.acc.getInfo().onlineStatusText}"),
                title="Account Info",
                border_style="green",
            )
        )
    acc_info(voip_manager)

    # input("Pressione Enter para fazer uma chamada...")
    voip_manager.make_call(env.get('DESTINATION'))
    
    input("Pressione Enter para encerrar a chamada...")
    voip_manager.hangup()
    
    input("Pressione Enter para sair...")
    
    voip_manager.quit()
