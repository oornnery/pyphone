from . import (
    SIPMethod,
    Message,
    Headers,
    Via,
    Address,
    From,
    To,
    CallID,
    CSeq,
    SIPRequest,
    SIPResponse,
    SIPStatus,
    Uri,
    SIPDialog,
    SIPTransaction,
    DigestAuth,
    SDP,
    Codec,
    DTMF,
    RTP,
    ConnectionHandler,
    ConnCfg,
)


class Pyphone:
    def __init__(self):
        self.conn_cfg = ConnCfg()
        self.conn = ConnectionHandler(self.conn_cfg, self.handle_connection)

    def handle_connection(self):
        pass

    def _create_invite(
        self, method: SIPMethod, uri: Uri, headers: Headers, body: str = None
    ):
        h = Headers()
        h.via_uri.append(
            headers["Via"]
            if "Via" in headers
            else Via(
                Address(self.conn_cfg.local_ip, self.conn_cfg.local_port),
                branch="",
                rport="",
                received="",
                transport="UDP",
            )
        )
        h.from_uri = (
            headers["From"]
            if "From" in headers
            else f"<sip:{self.conn_cfg.local_ip}:{self.conn_cfg.local_port}>"
        )
        h.to_uri = headers["To"] if "To" in headers else uri
        h.cseq = headers["CSeq"] if "CSeq" in headers else None
        h.call_id = headers["Call-ID"] if "Call-ID" in headers else None
        h.extra_headers.update(
            {
                k: v
                for k, v in headers.items()
                if k not in ["Via", "From", "To", "CSeq", "Call-ID"]
            }
        )

        request = SIPRequest(method, uri, h, body)
        return request
