class SIPError(Exception):
    pass

class AuthenticationError(SIPError):
    pass

class TransactionError(SIPError):
    pass

class DialogError(SIPError):
    pass

class TransportError(SIPError):
    pass

class MediaError(SIPError):
    pass

# TODO: class CodecError ???

class SDPError(SIPError):
    pass

class DTMFError(SIPError):
    pass
