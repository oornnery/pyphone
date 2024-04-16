import pjsua2 as pj
import time
import dotenv

env = dotenv.dotenv_values(".env")


class Endpoint(pj.Endpoint):
    """
    This is high level Python object inherited from pj.Endpoint
    """
    instance = None
    def __init__(self):
        pj.Endpoint.__init__(self)
        Endpoint.instance = self


def validateUri(uri):
    return Endpoint.instance.utilVerifyUri(uri) == pj.PJ_SUCCESS

def validateSipUri(uri):
    return Endpoint.instance.utilVerifySipUri(uri) == pj.PJ_SUCCESS



class Call(pj.Call):
    """
    High level Python Call object, derived from pjsua2's Call object.
    """
    def __init__(self, acc, peer_uri='', ep=None, call_id = pj.PJSUA_INVALID_ID):
        pj.Call.__init__(self, acc, call_id)
        self.acc = acc
        self.peerUri = peer_uri
        self.connected = False
        self.ep = ep
        self.onhold = False

    def onCallState(self, prm):
        ci = self.getInfo()
        self.connected = ci.state == pj.PJSIP_INV_STATE_CONFIRMED

    def onCallMediaState(self, prm):
        ci = self.getInfo()
        for mi in ci.media:
            if mi.type == pj.PJMEDIA_TYPE_AUDIO and \
              (mi.status == pj.PJSUA_CALL_MEDIA_ACTIVE or \
               mi.status == pj.PJSUA_CALL_MEDIA_REMOTE_HOLD):
                m = self.getMedia(mi.index)
                am = pj.AudioMedia.typecastFromMedia(m)
                # connect ports
                Endpoint.instance.audDevManager().getCaptureDevMedia().startTransmit(am)
                am.startTransmit(Endpoint.instance.audDevManager().getPlaybackDevMedia())

                if mi.status == pj.PJSUA_CALL_MEDIA_REMOTE_HOLD and not self.onhold:
                    self.onhold = True
                elif mi.status == pj.PJSUA_CALL_MEDIA_ACTIVE and self.onhold:
                    self.onhold = False



class VoIPManager:
    def __init__(self):
        # Create and initialize the library
        ep_cfg = pj.EpConfig()
        self.ep = pj.Endpoint()
        self.ep.libCreate()
        self.ep.libInit(ep_cfg)
        # Create SIP transport. Error handling sample is shown
        sip_transport_config = pj.TransportConfig()
        sip_transport_config.port = 5060
        self.transport = self.ep.transportCreate(
            pj.PJSIP_TRANSPORT_UDP, 
            sip_transport_config
            )
        # start the library
        self.ep.libStart()
        # SIP account
        self.acc = pj.Account()

    def register(self, username, password, domain):
        acc_cfg = pj.AccountConfig()
        acc_cfg.idUri = f"sip:{username}@{domain}"
        acc_cfg.regConfig.registrarUri = f"sip:{domain}"
        cred = pj.AuthCredInfo("digest", "*", username, 0, password)
        acc_cfg.sipConfig.authCreds.append(cred)
        # Create the account
        self.acc.create(acc_cfg)
        status = pj.PresenceStatus()
        status.status = pj.PJSUA_BUDDY_STATUS_ONLINE
        self.acc.setOnlineStatus(status)

    def unregister(self):
        self.acc.shutdown()

    def account_info(self):
        return self.acc.getInfo()
    
    def make_call(self, destination):
        self.call = pj.Call(self.acc)
        prm = pj.CallOpParam(True)
        return self.call.makeCall(destination, prm)

    def hangup(self):
        self.call.hangup()

    def set_callback(self, callback_function):
        # Aqui você pode definir um callback para eventos específicos, como chamadas recebidas
        # Isso pode ser feito sobrescrevendo os métodos de callback na classe CallCallback
        pass
    
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
    voip_manager.make_call(f"sip:039959137@{env.get('DOMAIN')}")
    time.sleep(10)
    
    input("Pressione Enter para encerrar a chamada...")
    voip_manager.hangup()
    
    input("Pressione Enter para sair...")
    
    voip_manager.quit()
