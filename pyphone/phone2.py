import time
import dotenv
import pjsua2 as pj


env = dotenv.dotenv_values(".env")


class VoIPManager:
    def __init__(self):
        # Create and initialize the library
        self.ep = pj.Endpoint()
        version = self.ep.libVersion().full
        # Configure endpoint
        ep_cfg = pj.EpConfig()
        ep_cfg.uaConfig.userAgent = f"pyphone-{version}"
        ep_cfg.uaConfig.threadCnt = 1
        ep_cfg.uaConfig.mainThreadCnt = False
        # ep_cfg.uaConfig.writer = self.logger
        ep_cfg.uaConfig.filename = "logs/pyphone.log"
        ep_cfg.uaConfig.level = 5
        ep_cfg.uaConfig.consoleLevel = 5
        
        self.ep.libCreate()
        self.ep.libInit(ep_cfg)
        
        # Create SIP transport. Error handling sample is shown
        sip_transport_config = pj.TransportConfig()
        sip_transport_config.port = 5061
        udp_config = pj.PJSIP_TRANSPORT_UDP
        tcp_config = pj.PJSIP_TRANSPORT_TCP
        tls_config = pj.PJSIP_TRANSPORT_TLS
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
        acc_cfg.idUri = f"sip:{username}@{domain}"
        acc_cfg.regConfig.registrarUri = f"sip:{domain}"
        cred = pj.AuthCredInfo("digest", "*", username, 0, password)
        acc_cfg.sipConfig.authCreds.append(cred)
        # Create the account
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
    print(voip_manager.acc.getId())
    print(voip_manager.acc.getInfo().id)
    print(voip_manager.acc.getInfo().uri)
    print(voip_manager.acc.getInfo().regIsConfigured)
    print(voip_manager.acc.getInfo().regIsActive)
    print(voip_manager.acc.getInfo().regExpiresSec)
    print(voip_manager.acc.getInfo().regStatus)
    print(voip_manager.acc.getInfo().regStatusText)
    print(voip_manager.acc.getInfo().regLastErr)
    print(voip_manager.acc.getInfo().onlineStatus)
    print(voip_manager.acc.getInfo().onlineStatusText)
    
    input("Pressione Enter para fazer uma chamada...")
    voip_manager.make_call(env.get('DESTINATION'))
    time.sleep(10)
    
    input("Pressione Enter para encerrar a chamada...")
    voip_manager.hangup()
    
    input("Pressione Enter para sair...")
    
    voip_manager.quit()
