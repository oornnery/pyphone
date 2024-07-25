import time
import sys
import dotenv
import pjsua2 as pj
import logging
import random


from enum import Enum, IntEnum
from dataclasses import dataclass, field
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
# from rich import print


console = Console()
env = dotenv.dotenv_values(".env")

# Configuração de logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('pjsua2')

class LogLevelEnum(IntEnum):
    ERROR = 1
    WARNING = 2
    INFO = 3
    TRACER = 5


class SipTransportEnum(IntEnum):
    UDP = pj.PJSIP_TRANSPORT_UDP
    TCP = pj.PJSIP_TRANSPORT_TCP
    TLS = pj.PJSIP_TRANSPORT_TLS


class CodecEnum(Enum):
    PCMA = "PCMA/8000"
    PCMU = "PCMU/8000"


class LogFlagsEnum(IntEnum):
    APPEND = pj.PJ_O_APPEND


@dataclass
class CodecConfig:
    codec: CodecEnum
    priority: int


@dataclass
class EndpointConfig:
    user_agent: str = field(default="pyphone-pjsua2")
    max_calls: int = field(default=4)
    use_threads: bool = field(default=True)
    log_console_level: LogLevelEnum = field(default=LogLevelEnum.INFO)
    log_path: str = field(default="logs/pyphone.log")
    log_level: LogLevelEnum = field(default=LogLevelEnum.TRACER)
    log_flags: LogFlagsEnum = field(default=LogFlagsEnum.APPEND)
    med_clock_rate: int = field(default=16000)
    med_channel_count: int = field(default=1)
    med_ptime: int = field(default=20)
    med_quality: int = field(default=10)
    codec_list: List[CodecConfig] = field(default_factory=list)
    transport_port: int = field(default=5060)
    transport_random_port: bool = field(default=False)
    transport_protocol: SipTransportEnum = field(default=SipTransportEnum.UDP)
    transport_public_address: str = field(default="0.0.0.0")
    transport_bound_address: str = field(default="0.0.0.0")


class Endpoint(pj.Endpoint):
    def __init__(self, ep_cfg: EndpointConfig, *args):
        super().__init__(*args)
        self.libCreate()
        self.cfg = pj.EpConfig()
        # User agent configuration
        ua_cfg = pj.UaConfig()
        if ep_cfg.use_threads:
            ua_cfg.threadCnt = 1
            ua_cfg.mainThreadCnt = False
        else:
            ua_cfg.threadCnt = 0
            ua_cfg.mainThreadCnt = True
        ua_cfg.userAgent = ep_cfg.user_agent
        ua_cfg.maxCalls = ep_cfg.max_calls
        # Set configuration
        self.cfg.uaConfig = ua_cfg
        # Log configuration
        log_cfg = pj.LogConfig()
        #log_cfg.logConfig.writer = self.logger
        log_cfg.filename = ep_cfg.log_path
        log_cfg.fileFlags = ep_cfg.log_flags
        log_cfg.level = ep_cfg.log_level
        log_cfg.consoleLevel = ep_cfg.log_console_level
        # Set configuration
        self.cfg.logConfig = log_cfg
        # Media configuration
        med_cfg = pj.MediaConfig()
        med_cfg.clockRate = ep_cfg.med_clock_rate
        med_cfg.channelCount = ep_cfg.med_channel_count
        med_cfg.ptime = ep_cfg.med_ptime
        med_cfg.quality = ep_cfg.med_quality
        med_cfg.ecTailLen = 0
        med_cfg.threadCnt = 1
        med_cfg.threadPrio = 0
        # Set configuration
        self.cfg.medConfig = med_cfg
        # Init library        
        self.libInit(self.cfg)
        # Codec configuration
        for codec in ep_cfg.codec_list:
            self.codecSetPriority(codec.codec, codec.priority)
        # Create SIP transport.
        transport_cfg = pj.TransportConfig()
        transport_cfg.port = ep_cfg.transport_port
        transport_cfg.randomizePort = ep_cfg.transport_random_port
        transport_cfg.publicAddress = ep_cfg.transport_public_address
        transport_cfg.boundAddress = ep_cfg.transport_bound_address
        # transport_cfg.qosType = 1
        # transport_cfg.qosParams = pj.QosParams()
        # Create transport
        self.transportCreate(
            ep_cfg.transport_protocol, 
            transport_cfg
            )
        # start the library
        self.libStart()


@dataclass
class RegisterConfig:
    username: str
    password: str
    domain: str
    port: int = field(default=5060)
    priority: int = field(default=0)
    set_register: bool = field(default=True)
    # TODO: implementar outros campos da class AccountConfig
    
    def id_uri(self):
        return f"sip:{self.username}@{self.domain}"

    def registrar_uri(self):
        return f"sip:{self.username}"


class Account(pj.Account):
    def __init__(self):
        super().__init__()
        self.randId = random.randint(1, 9999)
        self.cfg =  pj.AccountConfig()
        self.buddyList = []

    def add_account(self, reg_cfg: RegisterConfig):
        self.cfg.priority = 0
        self.cfg.idUri = reg_cfg.id_uri()
        self.cfg.regConfig.registrarUri = reg_cfg.registrar_uri()
        self.cfg.regConfig.registerOnAdd = reg_cfg.set_register
        # Create auth credentials
        auth_cred = pj.AuthCredInfo()
        auth_cred.scheme = "digest"
        auth_cred.username = reg_cfg.username
        auth_cred.realm = "*"
        auth_cred.dataType = 0
        auth_cred.data = reg_cfg.password
        # Add auth credentials
        self.cfg.sipConfig.authCreds.append(auth_cred)


    def set_registration(self, status: bool = True):
        self.setRegistration(status)

    def set_presence_status(self):
        status = pj.PresenceStatus()
        status.status = pj.PJSUA_BUDDY_STATUS_ONLINE
        self.setOnlineStatus(status)

    def unset_registration(self):
        self.shutdown()

    def account_info(self):
        return self.acc.getInfo()

    def onRegState(self, prm):
        #TODO: implementar estado de registro
        #TODO: Exebir estado de registro na tela
        pass

    def onIncomingCall(self, prm):
        c = pj.Call(self, call_id=prm.callId)
        call_prm = pj.CallOpParam()
        call_prm.statusCode = 180
        c.answer(call_prm)
        ci = c.getInfo()
        #TODO: implementar recebimento de chamadas.


class Call(pj.Call):
    def __init__(self, acc, call_id=pj.PJSUA_INVALID_ID):
        super().__init__(acc, call_id)


    def on_call_media_state(self, prm):
        # Obter a mídia de áudio da chamada
        aud_med = self.get_audio_media(-1)

        # Verificar se a mídia de áudio é válida
        if aud_med is None:
            print("Failed to get audio media")
            return

        # Obter a mídia de áudio do dispositivo de captura (microfone)
        try:
            capture_med = Endpoint.instance().aud_dev_manager().get_capture_dev_media()
        except Exception as e:
            print(f"Failed to get capture device media: {e}")
            return

        # Conectar a mídia de captura à mídia da chamada
        print("Starting audio transmission from microphone...")
        capture_med.start_transmit(aud_med)
        print("Audio transmission started.")



class VoIPManager(Endpoint):
    def __init__(self):
        super().__init__()

        # SIP account
        self.acc = Account()
        self.prm = pj.CallOpParam()
        self.call = Call(self.acc)

    def make_call(self, destination):
        #TODO: Mover para class call
        prm = pj.CallOpParam(True)
        prm.opt.audioCount = 1
        prm.opt.videoCount = 0
        dest_uri = f"sip:{destination}@{env.get('DOMAIN')}"
        return self.call.makeCall(dest_uri, prm)

    def hangup(self):
        #TODO: Mover para class call
        self.prm.statusCode = pj.PJSIP_SC_REQUEST_TERMINATED
        self.call.hangup(self.prm)

    def set_callback(self, callback_function):
        # Aqui você pode definir um callback para eventos específicos, como chamadas recebidas
        # Isso pode ser feito sobrescrevendo os métodos de callback na classe CallCallback
        pass
    
    def call_info(self):
        #TODO: Mover para class call
        return self.call.getInfo()
    
    def quit(self):
        #TODO: Mover para endpoint
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
