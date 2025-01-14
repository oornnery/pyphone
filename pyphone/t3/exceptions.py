# Custom Exceptions

class SIPError(Exception):
    '''Base exception for SIP-related errors.'''

class TransactionError(SIPError):
    '''Base exception for SIP transaction errors.'''

class DialogError(SIPError):
    """Exception for dialog-related errors"""

class ParsingError(SIPError):
    """Exception for parsing-related errors"""
