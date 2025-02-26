import argparse
import logging
import os
import sys
import time
from enum import Enum
from dataclasses import dataclass
from typing import List, Tuple

class TransportCfg:
    ...

class UDP:
    ...

class Transport:
    ...


class SIPMessage:
    def __init__(
            self,
            start_line: str,
            header: str,
            body: str
            ):
        self.start_line = start_line
        self.header = header
        self.body = body
    
    @property
    def is_request(self):
        return self.start_line.startswith("SIP")

    @property
    def is_response(self):
        return not self.is_request
    
    def __build_header(headers: List[Tuple[str, str]]):
        return "".join(map(str, [f"{name}: {value}\r\n" for name, value in headers]))
    
    @classmethod
    def request(
        cls,
        method: str,
        uri: str,
        headers: List[tuple[str, str]],
        body: str
        ) -> 'SIPMessage':
        start_line = f"{method} {uri} SIP/2.0"
        header = cls.__build_header(headers)
        return cls(start_line, header, body)
    
    @classmethod
    def response(
        cls,
        status_code: str,
        reason_phrase: str,
        headers: List[tuple[str, str]],
        body: str
        ) -> 'SIPMessage':
        start_line = f"SIP/2.0 {status_code} {reason_phrase}"
        header = cls.__build_header(headers)
        return cls(start_line, header, body)
    
    @classmethod
    def parser_message(cls, message: str) -> 'SIPMessage':
        start_line, header, body = message.split("\r\n\r\n")
        return cls(start_line, header, body)
    
    def __str__(self):
        return f"{self.start_line}\r\n{self.header}\r\n\r\n{self.body if self.body else ''}"


class SIP:
    def __init__(self, uri: str, conn_cfg: TransportCfg):
        self.uri = uri
        self.conn_cfg = conn_cfg
        self._user_agent = None
        self._display_name = None
        self._contact = None

    @property
    def user_agent(self):
        return self._user_agent
    
    @user_agent.setter
    def user_agent(self, value):
        self._user_agent = value
    
    @property
    def display_name(self):
        return self._display_name
    
    @display_name.setter
    def display_name(self, value):
        self._display_name = value
        
    @property
    def contact(self):
        return self._contact
    
    @contact.setter
    def contact(self, value):
        self._contact = value
    
    def invite(self, to_uri: str, extra_headers: List[Tuple[str, str]] = None) -> SIPMessage:
        headers = [
            ("To", f"<sip:{to_uri}>"),
            ("From", f"<sip:{self.uri}>;tag={time.time()}"),
            ("Call-ID", f"{time.time()}@{self.uri}"),
            ("CSeq", f"{time.time()} INVITE"),
            ("Contact", f"<sip:{self.uri}>"),
            ("Accept", "application/sdp")
        ]
        if extra_headers:
            headers.extend(extra_headers)
        return SIPMessage.request("INVITE", f"sip:{to_uri}", headers, "")
    
    def options(
        self,
        extra_headers: List[Tuple[str, str]] = None
        ) -> SIPMessage:
        headers = [
            ("To", f"<sip:{self.uri}>"),
            ("From", f"<sip:{self.uri}>;tag={time.time()}"),
            ("Call-ID", f"{time.time()}@{self.uri}"),
            ("CSeq", f"{time.time()} OPTIONS"),
            ("Contact", f"<sip:{self.uri}>"),
            ("Accept", "application/sdp")
        ]
        if extra_headers:
            headers.extend(extra_headers)
        return SIPMessage.request("OPTIONS", f"sip:{self.uri}", headers, "")
    

class SDP:
    ...

class RTP:
    ...

class DTMF:
    ...

class Codec:
    ...

class UserAgent:
    ...

class Session:
    ...

class Pyphone:
    ...