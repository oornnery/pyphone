import time
import dotenv
import pjsua2 as pj

from dataclasses import dataclass, field
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()
env = dotenv.dotenv_values(".env")

USE_THREADS = False

@dataclass
class VoIPConfig:
    max_calls: int = 4
    user_agent: str = "pyphone"
    thread_cnt: int = 0
    main_thread_only: bool = True
    nameserver: List[str] = field(default_factory=list)
    outbound_proxies: List[str] = field(default_factory=list)
    stun_server: List[str] = field(default_factory=list)
    stun_try_ipv6: bool = False
    stun_ignore_failure: bool = True
    nat_type_in_sdp: int = 2
    mwi_unsolicited_enabled: bool = False
    enable_upnp: bool = False
    upnp_if_name: str = ""

@dataclass
class LogConfig:
    level: int = 5
    console_level: int = 5
    filename: str = "logs/pyphone.log"
    file_flags: int = pj.PJ_O_APPEND

@dataclass
class MediaConfig:
    clock_rate: int = 16000
    channel_count: int = 1
    ptime: int = 20
    quality: int = 8

class VoIPManager:
    def __init__(self, config: VoIPConfig, log_config: LogConfig, media_config: MediaConfig):
        # Create and initialize the library
        self.ep = pj.Endpoint()
        self.ep.libCreate()

        # Configure endpoint
        ep_cfg = pj.EpConfig()
        ep_cfg.uaConfig.maxCalls = config.max_calls
        ep_cfg.uaConfig.userAgent = f"{config.user_agent}-{self.ep.libVersion().full}"
        ep_cfg.uaConfig.threadCnt = config.thread_cnt
        ep_cfg.uaConfig.mainThreadOnly = config.main_thread_only
        ep_cfg.logConfig.level = log_config.level
        ep_cfg.logConfig.consoleLevel = log_config.console_level
        ep_cfg.logConfig.filename = log_config.filename
        ep_cfg.logConfig.fileFlags = log_config.file_flags
        ep_cfg.medConfig.clockRate = media_config.clock_rate
        ep_cfg.medConfig.channelCount = media_config.channel_count
        ep_cfg.medConfig.ptime = media_config.ptime
        ep_cfg.medConfig.quality = media_config.quality

        # Init library
        self.ep.libInit(ep_cfg)

        # Create SIP transport
        sip_transport_config = pj.TransportConfig()
        sip_transport_config.port = 0
        sip_transport_config.publicAddress = "0.0.0.0"
        self.transport = self.ep.transportCreate(pj.PJSIP_TRANSPORT_UDP, sip_transport_config)

        # Start the library
        self.ep.libStart()

        # SIP account
        self.acc = pj.Account()
        self.prm = pj.CallOpParam()
        self.call = pj.Call(self.acc)

    def register(self, username: str, password: str, domain: str):
        acc_cfg = pj.AccountConfig()
        acc_cfg.idUri = f"sip:{username}@{domain}"
        acc_cfg.regConfig.registrarUri = f"sip:{username}@{domain}"
        acc_cfg.regConfig.registerOnAdd = True
        cred = pj.AuthCredInfo()
        cred.scheme = "digest"
        cred.username = username
        cred.realm = "*"
        cred.username = username
        cred.data = password
        acc_cfg.sipConfig.authCreds.append(cred)
        acc_cfg.sipConfig.outboundProxy = f"sip:{username}@{domain}"
        self.acc.create(acc_cfg)

    def unregister(self):
        self.acc.shutdown()

    def account_info(self):
        return self.acc.getInfo()

    def make_call(self, destination: str):
        dest_uri = f"sip:{destination}@{env.get('DOMAIN')}:{env.get('PORT')}"
        return self.call.makeCall(dest_uri, self.prm)

    def hangup(self):
        self.prm.statusCode = pj.PJSIP_SC_REQUEST_TERMINATED
        self.call.hangup(self.prm)

    def call_info(self):
        return self.call.getInfo()

    def quit(self):
        if self.call.getInfo().state != pj.PJSIP_INV_STATE_DISCONNECTED:
            self.hangup()
        if self.acc:
            self.unregister()
        self.ep.libDestroy()
        sys.exit(0)

# Exemplo de uso
if __name__ == "__main__":
    voip_config = VoIPConfig()
    log_config = LogConfig()
    media_config = MediaConfig()
    voip_manager = VoIPManager(voip_config, log_config, media_config)
    voip_manager.register(env.get('USERNAME'), env.get('PASSWORD'), env.get('DOMAIN'))

    acc_info = voip_manager.account_info()
    print(acc_info)

    input("Pressione Enter para fazer uma chamada...")
    voip_manager.make_call(env.get('DESTINATION'))

    input("Pressione Enter para encerrar a chamada...")
    voip_manager.hangup()

    input("Pressione Enter para sair...")

    voip_manager.quit()
