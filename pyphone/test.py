import re
import logging
import pexpect
from rich import print
from rich.logging import RichHandler
from dataclasses import dataclass
from time import sleep

logging.basicConfig(
    level="NOTSET",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, omit_repeated_times=False)],
)

log = logging.getLogger("rich")

# Defina o padrão de timestamp
timestamp_pattern = r'\d{2}:\d{2}:\d{2}\.\d{3}'

sip: str
uri: str
call_id: str
sip_response: list[str]
call_in_progress: bool
codec_outgoing: str
codec_incoming: str
rtp_outgoing_ip: str
rtp_outgoing_port: str
rtp_incoming_ip: str
rtp_incoming_port: str



calls = []

# Função para analisar a linha e extrair informações relevantes
def parse_line(line):
    call_info = {
        
        'sip_response': []
    }
    if 'call uri:' in line:
        call_uri = re.search(r'call uri: (.*)', line)
        if call_uri:
            log.info(f'Call URI: {call_uri.groups()}')
    elif 'call id:' in line:
        call_id = re.search(r'call id: (.*)', line)
        if call_id:
            log.info(f'Call ID: {call_id.groups()}')
    elif 'call:' in line:
        # Chamada em andamento
        call_connecting = re.search(fr"'(sip:.*)'", line)
        if call_connecting:
            log.info(f'Call connecting: {call_connecting.groups()}')
        # Resposta SIP
        sip_response = re.search(fr'call: SIP Progress: (.*)', line)
        if sip_response:
            log.info(f'SIP response: {sip_response.groups()}')
        # Chamada finalizada
        call_terminate = re.search(fr"call: terminate call '(.*)' with (sip:.*)", line)
        if call_terminate:
            log.info(f'Call terminated: {call_terminate.groups()}')
        
    elif 'stream:' in line:
        # RTP outgoing
        rtp_outgoing_ip = re.search(fr'stream: audio: starting RTCP with remote (.*)', line)
        if rtp_outgoing_ip:
            log.info(f'RTCP outgoing IP: {rtp_outgoing_ip.groups()}')
        # RTP incoming
        rtp_incoming_ip = re.search(fr"stream: incoming rtp for 'audio' established, receiving from (.*)", line)
        if rtp_incoming_ip:
            log.info(f'RTCP incoming IP: {rtp_incoming_ip.groups()}')
    
    elif 'audio:' in line:
        # Codec outgoing
        codec_outgoing = re.search(fr'audio: Set audio decoder: (.*)', line)
        if codec_outgoing:
            log.info(f'Codec outgoing: {codec_outgoing.groups()}')
        # Codec incoming
        codec_incoming = re.search(fr'audio: Set audio encoder: (.*)', line)
        if codec_incoming:
            log.info(f'Codec incoming: {codec_incoming.groups()}')
    
    elif 'Call answered:' in line:
        call_answered = re.search(fr'(\d+@[\w.-]+): Call answered: (sip:\d+@[\w.-]+$)', line)
        if call_answered:
            log.info(f'Call answered: {call_answered.groups()}')
    
    elif 'Call established' in line:
        call_established = re.search(fr'(\d+@[\w.-]+): Call established: (sip:\d+@[\w.-]+$)', line)
        if call_established:
            log.info(f'Call established: {call_established.groups()}')
    
    elif 'session closed:' in line:
        # Session close
        session_close = re.search(fr'(sip:\d+@[\w.-]+): session closed: (.*)', line)
        if session_close:
            log.info(f'Session close: {session_close.groups()}')
    
    elif 'Call ended' in line:
        pass
    return call_info

def main():
    # Substitua 'seu_programa' pelo nome do programa que você deseja monitorar
    child = pexpect.spawn('baresip -T -v')

    # child.sendline('/dial 0916770737')
    # Lista para armazenar informações únicas
    unique_calls = []

    # Loop para ler a saída do programa linha por linha
    while True:
        try:
            line = child.readline().decode('utf-8').strip()
            if not line:
                continue
            
            # Analisar a linha para extrair informações relevantes
            call_info = parse_line(line)
            if call_info:
                # Verificar se já temos informações semelhantes armazenadas
                if call_info not in unique_calls:
                    unique_calls.append(call_info)
                    print(call_info)
            
        except pexpect.EOF:
            break

def main2():
    with open('pyphone/logs.log', 'r') as f:
        lines = f.readlines()
    for line in lines:
        call_info = parse_line(line)


if __name__ == "__main__":
    main2()