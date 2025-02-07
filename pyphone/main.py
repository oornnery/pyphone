from dataclasses import dataclass
from typing import List

from transport import TransportAddr, TransportConfig, Transport
from utils import console, log
from message import Message
from dialog import Dialog

from rich.panel import Panel


@dataclass
class UserAgent:
    username: str
    domain: str
    port: int = 5060
    login: str = None
    password: str = None
    transport: str = "udp"
    display_name: str = None
    contact: str = None
    expires: int = 3600
    realm: str = None
    conn_cfg: TransportConfig = None


class Session:
    def __init__(self, transport_cfg: TransportConfig):
        self.cfg = transport_cfg
        self._transport = Transport(transport_cfg, self.handle_data)
        self._dialogs: List[Dialog] = []
        self._running = False

    def handle_data(self, data: bytes, addr: TransportAddr):
        log.info(f"Received data from {addr}:\n")
        m = Message(data.decode())
        if m.is_request:
            self._on_request(m)
        else:
            self._on_response(m)

    def _on_request(self, m: Message):
        log.info(f"Received request: {m.ruri}")
        d = Dialog(m)
        self._dialogs.append(d)

    def _on_response(self, m: Message):
        log.info(f"Received response: {m.ruri}")
        for d in self._dialogs:
            if d.call_id == m.call_id:
                d.handle_dialog(m)
                break
        else:
            log.error(f"Received response for unknown dialog: {m.call_id}")
            # TODO: Implementar resposta 481 Dialog/Transaction not found.

    def _build_uri(
        self,
        addr: str,
        port: int = None,
        tag: str = None,
        branch: str = None,
        rport: bool = False,
        bracket: bool = False,
    ):
        uri = f"sip:{addr}"
        if port and port != 0:
            uri += f":{port}"
        if tag:
            uri += f";tag={tag}"
        if rport:
            uri += ";rport"
        if branch:
            uri += f";branch={branch}"
        # for k, v in extra_params.items() if extra_params else {}:
        #     if v:
        #         uri += f';{k}={v}'
        #         continue
        #     uri += f';{k}'
        if bracket:
            uri = f"<{uri}>"
        return uri

    def request(
        self,
        method: str,
        ua: UserAgent = None,
        dialog: Dialog = None,
        rport: bool = False,
        extra_headers: list[tuple[str, str]] = None,
    ):
        if not dialog:
            dialog = Dialog()

        method = method.upper()
        protocol = self.cfg.protocol.upper()
        req_uri = self._build_uri(addr=ua.domain, port=ua.domain)
        via_uri = self._build_uri(
            addr=self.cfg.local_addr[0],
            port=self.cfg.local_addr[1],
            branch=dialog.branch,
            rport=rport,
        )
        from_uri = self._build_uri(
            addr=ua.domain, port=ua.port, tag=dialog.local_tag, bracket=True
        )
        to_uri = self._build_uri(
            addr=ua.domain, port=ua.port, tag=dialog.remote_tag, bracket=True
        )
        call_id = dialog.call_id
        seq = dialog.seq
        method_seq = dialog.method_seq or method
        # extra_headers = extra_headers or []

        msg = (
            f"{method} {req_uri} SIP/2.0\r\n"
            f"Via: SIP/2.0/{protocol} {via_uri}\r\n"
            f"From: {from_uri}\r\n"
            f"To: {to_uri}\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: {seq} {method_seq}\r\n"
            f"Max-Forwards: 70\r\n"
            f"Content-Length: 0\r\n"
            # f'{k}: {v}\r\n' for k, v in extra_headers if extra_headers else []
            "\r\n"
        )

        dialog.new_transaction(Message(msg))
        self._dialogs.append(dialog)
        self._transport.send(msg, (ua.domain, ua.port))

    def start(self):
        self._transport.start()
        self._running = True

    def stop(self):
        self._transport.stop()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()
        self._running = False


# Exemplo de uso
if __name__ == "__main__":
    import re
    import time

    def split_sip_message(data) -> tuple[dict, dict]:
        parts = re.split(r"\r\n\r\n|\n\n", data, maxsplit=1)
        first_line = str(parts[0].split("\r\n")[0]).strip()
        _header = list(x for x in parts[0].split("\r\n")[1:])
        _body = list(x for x in (parts[1] if len(parts) > 1 else "").split("\r\n"))

        header = {}
        body = {}

        for i, line in enumerate(_header):
            values = line.split(":", 1)
            header[i] = [v.strip() for v in values if v]

        for i, line in enumerate(_body) if len(_body) > 1 else []:
            values = line.split("=", 1)
            if len(values) <= 1:
                continue
            body[i] = [v.strip() for v in values if v]

        return first_line, header, body

    # Criar conexão UDP
    cfg = TransportConfig(
        target_addr=("demo.mizu-voip.com", 37075),
        protocol="udp",
    )

    sdp = (
        "v=0\r\n"
        f"o=- 0 0 IN IP4 {cfg.local_addr[0]}\r\n"
        "s=session\r\n"
        f"c=IN IP4 {cfg.local_addr[0]}\r\n"
        "t=0 0\r\n"
        "m=audio 5002 RTP/AVP 9 0 8 18 101\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=rtpmap:0 PCMA/8000\r\n"
        "a=rtpmap:101 telephone-event/8000\r\n"
        "a=fmtp:101 0-16\r\n"
        "a=sendrecv\r\n"
    )

    with Session(cfg) as s:
        for x in range(5):
            s.request(
                method="OPTIONS",
                ua=UserAgent(
                    username="ping-pong",
                    domain="demo.mizu-voip.com",
                    port=37075,
                    transport="udp",
                ),
            )
            time.sleep(1)
