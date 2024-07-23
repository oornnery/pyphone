import pjsua2 as pj
import time
import logging
import dotenv

env = dotenv.dotenv_values(".env")

# Configuração de logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('pjsua2')

ep = pj.Endpoint()


class MyAccount(pj.Account):
    def onIncomingCall(self, prm):
        call = Call(self, prm.callId)
        call_prm = pj.CallOpParam()
        call_prm.statusCode = 200
        call.answer(call_prm)

class Call(pj.Call):
    def __init__(self, acc, call_id=pj.PJSUA_INVALID_ID):
        pj.Call.__init__(self, acc, call_id)

    def onCallState(self, prm):
        ci = self.getInfo()
        logger.info(f"Call state: {ci.state}")
        if ci.state == pj.PJSIP_INV_STATE_CONFIRMED:
            self.setMediaState()

    def onCallMediaState(self, prm):
        logger.info("Media state changed")
        ci = self.getInfo()
        for mi in ci.media:
            if mi.type == pj.PJMEDIA_TYPE_AUDIO:
                aud_med = self.getAudioMedia(mi.index)
                if aud_med:
                    logger.info(f"Audio media found at index {mi.index}")
                    ep.audDevManager().getCaptureDevMedia().startTransmit(aud_med)
                    aud_med.startTransmit(ep.audDevManager().getPlaybackDevMedia())

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




def main(username: str, password: str, domain: str, port: str, destination: str = "") -> None:
    global ep

    # Criar e inicializar o endpoint
    ep.libCreate()

    # Configuração do endpoint
    ep_cfg = pj.EpConfig()
    ep_cfg.logConfig.level = 5
    ep_cfg.logConfig.consoleLevel = 5
    ep.libInit(ep_cfg)

    # Configuração de transporte
    transport_config = pj.TransportConfig()
    transport_config.port = 0
    transport_config.publicAddress = "0.0.0.0"
    ep.transportCreate(pj.PJSIP_TRANSPORT_UDP, transport_config)

    # Configuração de mídia
    media_config = pj.MediaConfig()
    media_config.clockRate = 16000
    media_config.quality = 10
    ep.mediaConfig = media_config

    # Iniciar a biblioteca
    ep.libStart()

    # Configuração da conta
    acc_cfg = pj.AccountConfig()
    acc_cfg.idUri = f"sip:{username}@{domain}:{port}"
    acc_cfg.regConfig.registrarUri = f"sip:{domain}:{port}"
    acc_cfg.sipConfig.authCreds.append(pj.AuthCredInfo("digest", "*", username, 0, password))

    # Configuração de NAT
    acc_cfg.natConfig.iceEnabled = True
    # acc_cfg.natConfig.stunServer.append("stun.example.com")

    # Criar e registrar a conta
    acc = MyAccount()
    acc.create(acc_cfg)

    # Fazer uma chamada
    call_uri = f"sip:{destination}@{domain}:{port}"
    call = Call(acc)
    call_param = pj.CallOpParam(True)
    call.makeCall(call_uri, call_param)

    # Manter o programa em execução
    while True:
        time.sleep(1)

if __name__ == "__main__":
    username = env.get('USERNAME')
    password = env.get('PASSWORD')
    domain = env.get('DOMAIN')
    port = env.get('PORT')
    destination = env.get('DESTINATION')

    main(username, password, domain, port, destination)    
