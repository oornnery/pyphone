import pjsua2 as pj
import time
import logging
import dotenv

env = dotenv.dotenv_values(".env")

# Configuração de logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('pjsua2')

ep = None  # Será inicializado na função main

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

def main(username: str, password: str, domain: str, port: str, destination: str = "") -> None:
    global ep

    # Criar e inicializar o endpoint
    ep = pj.Endpoint()
    ep.libCreate()

    # Configuração do endpoint
    ep_cfg = pj.EpConfig()
    ep_cfg.logConfig.level = 5
    ep_cfg.logConfig.consoleLevel = 5
    ep_cfg.medConfig.threadCnt = 1
    ep_cfg.medConfig.quality = 10
    ep_cfg.medConfig.clockRate = 16000
    ep_cfg.medConfig.ecTailLen = 0
    # Definir a prioridade da thread de mídia para o máximo
    ep_cfg.medConfig.threadPrio = 0  # 0 geralmente representa a prioridade mais alta
    ep.libInit(ep_cfg)

    # Configuração de transporte
    transport_config = pj.TransportConfig()
    transport_config.port = 10080
    transport_config.publicAddress = "0.0.0.0"
    ep.transportCreate(pj.PJSIP_TRANSPORT_UDP, transport_config)

    # Configuração de mídia
    media_config = pj.MediaConfig()
    media_config.clockRate = 16000
    media_config.quality = 10
    media_config.ptime = 40  # Aumentado para reduzir a chance de subexecuções
    ep.mediaConfig = media_config

    # Ajuste das configurações do dispositivo de áudio
    aud_dev_manager = ep.audDevManager()
    dev_info = aud_dev_manager.getDevInfo(0)  # Assume que 0 é o ID do dispositivo padrão
    dev_info.input_latency = 100
    dev_info.output_latency = 100
    ep.audDevManager = aud_dev_manager

    # Iniciar a biblioteca
    ep.libStart()

    # Configuração da conta
    acc_cfg = pj.AccountConfig()
    acc_cfg.idUri = f"sip:{username}@{domain}"
    acc_cfg.regConfig.registrarUri = f"sip:{domain}"
    acc_cfg.sipConfig.authCreds.append(pj.AuthCredInfo("digest", "*", username, 0, password))

    # Configuração de NAT
    acc_cfg.natConfig.iceEnabled = True
    # acc_cfg.natConfig.stunServer.append("stun.example.com")

    # Configuração de codecs
    codec_priorities = {
        "PCMU/8000": 255,  # G.711 µ-law
        "PCMA/8000": 254,  # G.711 A-law
        "speex/8000": 253,
        "speex/16000": 252,
        "speex/32000": 251,
        "iLBC/8000": 250,
        "GSM/8000": 249,
    }

    ep.codecSetPriority("PCMU/8000", 255)
    ep.codecSetPriority("PCMA/8000", 254)
    

    # Criar e registrar a conta
    acc = MyAccount()
    acc.create(acc_cfg)
    
    status = pj.PresenceStatus()
    status.status = pj.PJSUA_BUDDY_STATUS_ONLINE
    acc.setOnlineStatus(status)


    # for codec, priority in codec_priorities.items():
    #     try:
    #         acc.setCodecPriority(codec, priority)
    #         logger.info(f"Codec {codec} set to priority {priority}")
    #     except pj.Error as e:
    #         logger.warning(f"Failed to set priority for codec {codec}: {str(e)}")

    # Fazer uma chamada
    if destination:
        call_uri = f"sip:{destination}@{domain}:{port}"
        call = Call(acc)
        call_param = pj.CallOpParam(True)
        call.makeCall(call_uri, call_param)

    # Manter o programa em execução
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Encerrando o programa...")
    finally:
        ep.libDestroy()

if __name__ == "__main__":
    username = env.get('USERNAME')
    password = env.get('PASSWORD')
    domain = env.get('DOMAIN')
    port = env.get('PORT')
    destination = env.get('DESTINATION')

    main(username, password, domain, port, destination)
