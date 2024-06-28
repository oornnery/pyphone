import time
import dotenv
import pjsua2 as pj

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
# from rich import print


console = Console()
env = dotenv.dotenv_values(".env")


class VoIPManager:
    def __init__(self):
        # Create and initialize the library
        self.ep = pj.Endpoint()
        self.ep.libCreate()
        # Configure endpoint
        ep_cfg = pj.EpConfig()
        # System settings
        ep_cfg.uaConfig.threadCnt = 1 # If use threads
        ep_cfg.uaConfig.mainThreadCnt = False # If use main thread (1 thread)
        # Agent settings
        version = self.ep.libVersion().full
        ep_cfg.uaConfig.userAgent = f"pyphone-{version}"
        ep_cfg.uaConfig.maxCalls = 4
        # Logs
        #ep_cfg.logConfig.writer = self.logger
        ep_cfg.logConfig.filename = "logs/pyphone.log"
        ep_cfg.logConfig.fileFlags = pj.PJ_O_APPEND
        ep_cfg.logConfig.level = 5
        ep_cfg.logConfig.consoleLevel = 5

        # Network settings
        # ep_cfg.nameserver # list of nameservers
        # ep_cfg.stunServer # list of STUN servers
        # ep_cfg.uaConfig.stunIgnoreFailure = True # bool
        
        # Media setting
        ep_cfg.medConfig.maxMediaPorts = 254 # Max media ports
        ep_cfg.medConfig.clockRate = 16000 # Core clock rate
		ep_cfg.medConfig.sndClockRate = 0 # Send device clock rate (0: follow core)
		ep_cfg.medConfig.audioFramePtime = 20 # Core ptime
		ep_cfg.medConfig.ptime = 20 # RTP ptime
		ep_cfg.medConfig.quality = 8 # Media quality (1-10)
		ep_cfg.medConfig.noVad = True # VAD (Bool)
		ep_cfg.medConfig.ecTailLen	= 200 # Echo canceller tail length (ms, 0 to disable)
        
        # Init library
        self.ep.libInit(ep_cfg)
        
        # Set codec
        self.ep.codecSetPriority("PCMA/8000", 255)
        self.ep.codecSetPriority("PCMU/8000", 255)
        
        # Create SIP transport. Error handling sample is shown
        udp_config = pj.PJSIP_TRANSPORT_UDP
        tcp_config = pj.PJSIP_TRANSPORT_TCP
        tls_config = pj.PJSIP_TRANSPORT_TLS
        sip_transport_config = pj.TransportConfig()
        sip_transport_config.port = 10080
        # sip_transport_config.publicAddress = "0.0.0.0"
        self.transport = self.ep.transportCreate(
            udp_config, 
            sip_transport_config
            )
        # start the library
        self.ep.libStart()
        # SIP account
        self.acc = pj.Account()
        self.prm = pj.CallOpParam()
        self.call = pj.Call(self.acc)

    def register(self, username, password, domain):
        acc_cfg = pj.AccountConfig()
        # Basic settings
        acc_cfg.priority = 0
        acc_cfg.idUri = f"sip:{username}@{domain}"
        acc_cfg.regConfig.registrarUri = f"sip:{username}@{domain}"
        acc_cfg.regConfig.registerOnAdd = True
        acc_cfg.sipConfig.proxies = [] # list of proxy servers
        
        acc_cfg.natConfig.sdpNatRewriteUse = False
        acc_cfg.mediaConfig.transportConfig.port = 0
        acc_cfg.mediaConfig.transportConfig.portRange = 0
        
        # Network settings
        
        
        # Create the account
        cred = pj.AuthCredInfo()
        cred.scheme = "digest"
        cred.username = username
        cred.realm = "*"
        cred.username = username
        cred.data = password
        acc_cfg.sipConfig.authCreds.append(cred)
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
