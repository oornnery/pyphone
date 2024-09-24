"""
	%% SIP Message Building Class
	class SipMessage {
		+SipUser user
		+String message
		+addVia()
		+addFrom()
		+addTo()
		+addContact()
		+addSupported()
		+addCallId()
		+addCSeq()
		+addUserAgent()
		+addMaxForwards()
		+addAllow()
		+addContentType()
		+addContentLength()
		+addVersion()
		+addOriginator()
		+addSessionName()
		+addInformation()
		+addUri()
		+addEmail()
		+addPhoneNumber()
		+addConnectionInfo()
		+addBandwidth()
		+addSessionTime()
		+addRepeatTimes()
		+addTimeZone()
		+addEncryptionKey()
		+addSessionAttributes()
		+addMediaAddress()
		+__str__()
	}

	%% Parser Class for SIP Messages
	class SipMessageParser {
		+SipMessage message
		+String getVia()
		+String getFrom()
		+String getTo()
		+String getContact()
		+String getSupported()
		+String getCallId()
		+String getCSeq()
		+String getUserAgent()
		+String getMaxForwards()
		+String getAllow()
		+String getContentType()
		+int getContentLength()
		+String getVersion()
		+String getOriginator()
		+String getSessionName()
		+String getInformation()
		+String getUri()
		+String getEmail()
		+String getPhoneNumber()
		+String getConnectionInfo()
		+int getBandwidth()
		+String getSessionTime()
		+String getRepeatTimes()
		+String getTimeZone()
		+String getEncryptionKey()
		+String getSessionAttributes()
		+String getMediaAddress()
		+String __str__()
	}
"""


class Message:
    _message = ""
    def __init__(self, user):
        self.user = user
    
    def add_via(self):
        pass

    def add_from(self):
        pass
    
    def add_to(self):
        pass
    
    def add_contact(self):
        pass

    def add_supported(self):
        pass
    
    def add_call_id(self):
        pass
    
    def add_ceq_id(self):
        pass
    
    def add_cseq_id(self):
        pass

    def add_user_agent(self):
        pass

    def add_max_forwards(self):
        pass
    
    def add_allow(self):
        pass
    
    def add_content_type(self):
        pass

    def add_content_length(self):
        pass
    
    def add_version(self):
        pass
    
    def add_originator(self):
        pass

    def add_session_name(self):
        pass

    def add_information(self):
        pass

    def add_uri(self):
        pass

    def add_email(self):
        pass

    def add_phone_number(self):
        pass

    def add_connection_info(self):
        pass

    def add_bandwidth(self):
        pass
    
    def add_session_time(self):
        pass

    def add_repeat_times(self):
        pass

    def add_time_zone(self):
        pass

    def add_encryption_key(self):
        pass

    def add_session_attributes(self):
        pass

    def add_media_address(self):
        pass

    def __str__(self):
        return ""

class ParserMessage:
    def __init__(self, message: str):
        self.message = message
        self._process_message()
    
    def get_via(self):
        pass

    def get_from(self):
        pass
    
    def get_to(self):
        pass
    
    def get_contact(self):
        pass

    def get_supported(self):
        pass
    
    def get_call_id(self):
        pass
    
    def get_ceq_id(self):
        pass
    
    def get_cseq_id(self):
        pass

    def get_user_agent(self):
        pass

    def get_max_forwards(self):
        pass
    
    def get_allow(self):
        pass
    
    def get_content_type(self):
        pass

    def get_content_length(self):
        pass
    
    def get_version(self):
        pass
    
    def get_originator(self):
        pass

    def get_session_name(self):
        pass

    def get_information(self):
        pass

    def add_uri(self):
        pass

    def get_email(self):
        pass

    def get_phone_number(self):
        pass

    def get_connection_info(self):
        pass

    def get_bandwidth(self):
        pass
    
    def get_session_time(self):
        pass

    def get_repeat_times(self):
        pass

    def get_time_zone(self):
        pass

    def get_encryption_key(self):
        pass

    def get_session_attributes(self):
        pass

    def get_media_address(self):
        pass

    def _process_message(self):
        pass

    def __str__(self):
        return self.message