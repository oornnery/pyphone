import time
import dotenv
import pjsua2 as pj

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

class Call(pj.Call):
    def __init__(self, acc, call_id=pj.PJSUA_INVALID_ID):
        pj.Call.__init__(self, acc, call_id)

    def onCallState(self, prm):
        ci = self.getInfo()
        logger.info(f"Call state: {ci.stateText}")
        if ci.state == pj.PJSIP_INV_STATE_CONFIRMED:
            self.setMediaState()

    def onCallMediaState(self, prm):
        logger.info("Media state changed")
        self.setMediaState()

    def setMediaState(self):
        logger.info("Setting media state")
        ci = self.getInfo()
        for mi in ci.media:
            if mi.type == pj.PJMEDIA_TYPE_AUDIO:
                aud_med = self.getAudioMedia(mi.index)
                if aud_med:
                    logger.info(f"Setting audio media at index {mi.index}")
                    ep.audDevManager().getCaptureDevMedia().startTransmit(aud_med)
                    aud_med.startTransmit(ep.audDevManager().getPlaybackDevMedia())


class VoIPManager:
    def __init__(self):
        # Create and initialize the library
        self.ep = pj.Endpoint()
        self.ep.libCreate()
        # Configure endpoint
        ep_cfg = pj.EpConfig()
        
        ua_cfg = pj.UaConfig()
        # System settings
        if USE_THREADS:
            ua_cfg.threadCnt = 1
            ua_cfg.mainThreadCnt = False
        else:
            ua_cfg.threadCnt = 0
            ua_cfg.mainThreadCnt = True
        
        # Agent settings
        version = self.ep.libVersion().full
        
        ua_cfg.userAgent = f"pyphone-{version}"
        ua_cfg.maxCalls = 4
        
        ep_cfg.uaConfig = ua_cfg
        # Logs
        #ep_cfg.logConfig.writer = self.logger
        ep_cfg.logConfig.filename = "logs/pyphone.log"
        ep_cfg.logConfig.fileFlags = pj.PJ_O_APPEND
        ep_cfg.logConfig.level = 5
        ep_cfg.logConfig.consoleLevel = 5

        # Network settings
        
        # Media setting
        media_cfg = pj.MediaConfig()
        media_cfg.clockRate = 16000
        media_cfg.channelCount = 1
        media_cfg.ptime = 20
        media_cfg.threadCnt = 1
        media_cfg.quality = 10
        media_cfg.ecTailLen = 0
        media_cfg.threadPrio = 0
        
        ep_cfg.medConfig = media_cfg
        
    
        # Init library
        self.ep.libInit(ep_cfg)
        
        # Ajuste das configurações do dispositivo de áudio
        aud_dev_manager = self.ep.audDevManager()
        dev_info = aud_dev_manager.getDevInfo(0)  # Assume que 0 é o ID do dispositivo padrão
        dev_info.input_latency = 100
        dev_info.output_latency = 100
        
        self.ep.audDevManager = aud_dev_manager
        
        # Set codec
        self.ep.codecSetPriority("PCMU/8000", 255)
        self.ep.codecSetPriority("PCMA/8000", 254)
        
        # Create SIP transport. Error handling sample is shown
        udp_config = pj.PJSIP_TRANSPORT_UDP
        tcp_config = pj.PJSIP_TRANSPORT_TCP
        tls_config = pj.PJSIP_TRANSPORT_TLS
        # Configuração de transporte
        sip_transport_config = pj.TransportConfig()
        # sip_transport_config.port = 5061  # Porta padrão para SIP
        sip_transport_config.randomizePort = True  # Não randomizar a porta
        sip_transport_config.publicAddress = "201.68.208.87"  # Endereço público
        sip_transport_config.boundAddress = "0.0.0.0"  # Endereço local
        # sip_transport_config.qosType = 1  # Exemplo de QoS
        # sip_transport_config.qosParams = pj.QosParams()  # Supondo que você tenha 
        
        self.transport = self.ep.transportCreate(
            udp_config, 
            sip_transport_config
            )
        # start the library
        self.ep.libStart()
        # SIP account
        self.acc = pj.Account()
        self.prm = pj.CallOpParam()
        self.call = Call(self.acc)


    def register(self, username, password, domain):
        # TODO: Mover para uma dataclass
        acc_cfg = pj.AccountConfig()
        
        # Basic settings
        acc_cfg.priority = 0
        acc_cfg.idUri = f"sip:{username}@{domain}"
        acc_cfg.regConfig.registrarUri = f"sip:{username}@{domain}"
        acc_cfg.regConfig.registerOnAdd = True
        
        # Create the account
        cred = pj.AuthCredInfo()
        cred.scheme = "digest"
        cred.username = username
        cred.realm = "*"
        cred.username = username
        cred.data = password
        acc_cfg.sipConfig.authCreds.append(cred)
        
        # acc_cfg.sipConfig.proxies = []
        acc_cfg.sipConfig.outboundProxy = f"sip:{username}@{domain}"

        # SIP features
        # acc_cfg.callConfig.prackUse = ...
        # acc_cfg.callConfig.timerUse = ...
        # acc_cfg.callConfig.timerSessExpiresSec = ...
        # acc_cfg.presConfig.publishEnabled = ...
        # acc_cfg.mwiConfig.enabled = ...
        # acc_cfg.natConfig.contactRewriteUse = ... 
        # acc_cfg.natConfig.viaRewriteUse = ... 
        # acc_cfg.natConfig.sdpNatRewriteUse = ... 
        # acc_cfg.natConfig.sipOutboundUse = ... 
        # acc_cfg.natConfig.udpKaIntervalSec = ... 

        # # Media
        # acc_cfg.mediaConfig.transportConfig.port = ...
        # acc_cfg.mediaConfig.transportConfig.portRange = ...
        # acc_cfg.mediaConfig.lockCodecEnabled = ...
        # acc_cfg.mediaConfig.srtpUse = ...
        # acc_cfg.mediaConfig.srtpSecureSignaling = ...
        # acc_cfg.mediaConfig.ipv6Use = ... # pj.PJSUA_IPV6_ENABLED or pj.PJSUA_IPV6_DISABLED

        # # NAT
        # acc_cfg.natConfig.sipStunUse = ... 
        # acc_cfg.natConfig.mediaStunUse = ... 
        # `acc_cfg.natConfig.iceEnabled = True` is setting the ICE (Interactive Connectivity
        # Establishment) feature to be enabled in the SIP account configuration. ICE is a technique
        # used in VoIP (Voice over Internet Protocol) communications to establish a connection between
        # two parties even when they are behind NAT (Network Address Translation) devices or
        # firewalls.
        # acc_cfg.natConfig.iceEnabled = True
        # acc_cfg.natConfig.iceAggressiveNomination = ...
        # acc_cfg.natConfig.iceAlwaysUpdate = ...
        # acc_cfg.natConfig.iceMaxHostCands = ...
        # acc_cfg.natConfig.turnEnabled = ... 
        # acc_cfg.natConfig.turnServer = ... 
        # acc_cfg.natConfig.turnConnType = ... 
        # acc_cfg.natConfig.turnUserName = ... 
        # acc_cfg.natConfig.turnPasswordType = ...
        # acc_cfg.natConfig.turnPassword = ... 
        
        self.acc.create(acc_cfg)
    
    def set_presence_status(self):
        status = pj.PresenceStatus()
        status.status = pj.PJSUA_BUDDY_STATUS_ONLINE
        self.acc.setOnlineStatus(status)

    def unregister(self):
        self.acc.shutdown()

    def account_info(self):
        return self.acc.getInfo()
    
    def make_call(self, destination):
        dest_uri = f"sip:{destination}@{env.get('DOMAIN')}"
        return self.call.makeCall(dest_uri, self.prm)

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
    input("Pressione Enter para fazer uma chamada...")
    voip_manager.make_call(env.get('DESTINATION'))
    
    input("Pressione Enter para encerrar a chamada...")
    voip_manager.hangup()
    
    input("Pressione Enter para sair...")
    
    voip_manager.quit()
