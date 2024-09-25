from pyphone.core.message import SIPRequest, SIPResponse, SIPMethod, SIPStatusCode, SIPHeader, SIPBody, RequestLine, StatusLine
from pyphone.core.user import User
from pyphone.core.session import Session

class Dialog:
    def __init__(self, user: User, session: Session) -> None:
        self.user = user
        self.session = session

    def genate_register(self) -> SIPRequest:
        headers = SIPHeader()
        req_line = RequestLine(method=SIPMethod.REGISTER)        
        req = SIPRequest(
            request_line=req_line,
            header=headers,
        )        
        return req
    
    def generate_invite(self, response: SIPResponse = None) -> SIPRequest:
        headers = SIPHeader()
        body = SIPBody()
        req_line = RequestLine(method=SIPMethod.INVITE)        
        req = SIPRequest(
            request_line=req_line,
            header=headers,
            body=body
        )        
        return req

    def generate_ack(self, response: SIPResponse) -> SIPResponse:
        headers = SIPHeader()
        req_line = StatusLine(status_code=SIPStatusCode.OK)        
        req = SIPResponse(
            req_line=req_line,
            header=headers,
        )        
        return req

    def generate_trying(self, response: SIPResponse) -> SIPResponse:
        headers = SIPHeader()
        req_line = StatusLine(status_code=SIPStatusCode.TRYING)        
        req = SIPResponse(
            req_line=req_line,
            header=headers,
        )
        return req
    
    def generate_cancel(self, response: SIPResponse = None) -> SIPRequest:
        headers = SIPHeader()
        req_line = RequestLine(method=SIPMethod.CANCEL)        
        req = SIPRequest(
            request_line=req_line,
            header=headers,
        )        
        return req
        
    def generate_bye(self, response: SIPResponse = None) -> SIPRequest:
        headers = SIPHeader()
        req_line = RequestLine(method=SIPMethod.BYE)        
        req = SIPRequest(
            request_line=req_line,
            header=headers,
        )        
        return req
        
    def generate_info(self) -> SIPRequest:
        headers = SIPHeader()
        req_line = RequestLine(method=SIPMethod.INFO)        
        req = SIPRequest(
            request_line=req_line,
            header=headers,
        )        
        return req
        
    def generate_options(self) -> SIPRequest:
        headers = SIPHeader()
        req_line = RequestLine(method=SIPMethod.OPTIONS)        
        req = SIPRequest(
            request_line=req_line,
            header=headers,
        )        
        return req
        
    def generate_notify(self) -> SIPRequest:
        headers = SIPHeader()
        req_line = RequestLine(method=SIPMethod.NOTIFY)        
        req = SIPRequest(
            request_line=req_line,
            header=headers,
        )        
        return req
        
    def generate_subscribe(self) -> SIPRequest:
        headers = SIPHeader()
        req_line = RequestLine(method=SIPMethod.SUBSCRIBE)        
        req = SIPRequest(
            request_line=req_line,
            header=headers,
        )        
        return req
        
    def generate_update(self) -> SIPRequest:
        headers = SIPHeader()
        req_line = RequestLine(method=SIPMethod.UPDATE)        
        req = SIPRequest(
            request_line=req_line,
            header=headers,
        )        
        return req

    def process_dialog(self, message: SIPResponse) -> SIPRequest:        
        match message.status_line.status_code:
            case 100:
                return self.generate_ack(message)
            case 180:
                return self.generate_ack(message)
            case 487:
                return self.generate_ack(message)
            case 200:
                return self.generate_bye(message)
            case _:
                return self.generate_info(message)
