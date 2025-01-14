from uuid import uuid4
from typing import Dict, List, Union
from abc import ABC
from pyphone.exceptions import ParsingError
from pyphone.logger import logger
from pyphone.utils import EOL, Method

# Headers fields

class AbstractHeader(ABC):
    MULTI_HEADERS_FIELDS = (
        'via', 'contact', 'route', 'record-route',
        'path', 'service-route', 'p-associated-uri'
    )
    COMPACT_HEADERS_FIELDS = {
        'v': 'via', 'f': 'from', 't': 'to', 'm': 'contact',
        'i': 'call_id', 's': 'subject', 'l': 'content_length',
        'c': 'content_type', 'k': 'supported', 'o': 'allow',
        'p': 'p_associated_uri'
    }
    SPECIAL_HEADERS_FIELDS = {
        'cseq': 'CSeq', 'call_id': 'Call-ID',
        'www_authenticate': 'WWW-Authenticate',
        'p_associated_uri': 'P-Associated-URI'
    }
    def __init__(self, key: str, value: str):
        self.key = key
        self.value = value
        self._normalize_key()
        
    def _normalize_key(self):
        """Normalize header name according to SIP specifications"""
        try:
            _key = self.key.lower().replace('-', '_')
            if _key in self.SPECIAL_HEADERS_FIELDS:
                self.key = self.SPECIAL_HEADERS_FIELDS[_key]
            # TODO: Implement compact headers
            else:
                self.key = '-'.join(
                    word.capitalize() for word in self.key.split('_')
                )
        except Exception as e:
            logger.error(f'Error normalizing header key {self.key}')
            raise ParsingError(f'Error normalizing header key: {e}')
    @staticmethod
    def _normalize_header_name(header_name: str) -> str:
        '''Converte para lowercase e substitui hífens '-' por underscores '_'.'''
        if header_name in Header.COMPACT_HEADERS:
            return Header.COMPACT_HEADERS[header_name]
        return header_name.lower().replace('-', '_')
    
    def __str__(self):
        return f'{self.key}: {self.value}{EOL}'


class Address:
    def __init__(
        self,
        host: str,
        port: int,
        user: str = None,
        display_name: str = None,
        params: Dict[str, str] = None
    ):
        self.user = user
        self.host = host
        self.port = port
        self.display_name = display_name
        self.params = params or {}
    
    def _validade_port(self):
        # TODO: Check if port in range 0-65535
        # TODO: Check if port is default port (22, 80, 443 etc).
        pass
    
    def _validate_host(self):
        # TODO: Check if host is valid.
        # TODO: Check if host is in DNS.
        pass

    @staticmethod
    def params_to_string(params: dict) -> str:
        return ''.join([f';{k}={v}' for k, v in params.items()])

    def __str__(self):
        _display = f'"{self.display_name}"' if self.display_name else ''
        _user = f'{self.user}@' if self.user else ''
        _params = self.params_to_string(self.params)
        return f'{_display}<sip:{self.user}{self.host}:{self.port}{_params}>'


class Via(AbstractHeader):
    def __init__(
        self,
        host: str,
        port: int,
        branch: str = None,
        protocol: str = 'UDP',
        scheme: str = 'SIP',
        version: str = '2.0',
    ):
        
        self.host = host
        self.port = port
        self.protocol = protocol
        self.scheme = scheme
        self.version = version
        self.branch = branch or self._generate_branch()
        value = f'{self.scheme}/{self.version} {self.host}:{self.port};branch={self.branch}'
        super().__init__('Via', value)

    @staticmethod
    def _generate_branch() -> str:
        """Generate unique branch ID"""
        return f'z9hG4bK{uuid4().hex[:10]}'
    

class From(AbstractHeader):
    def __init__(
        self,
        address: Address,
        tag: str = None
    ):
        self.address = address
        self.tag = tag
        value = f'{self.address};tag={self.tag}' if self.tag else self.address
        super().__init__('From', value)

    @staticmethod
    def _generate_tag() -> str:
        """Generate unique tag ID"""
        return uuid4().hex[:10]
    

class To(AbstractHeader):
    def __init__(
        self,
        address: Address,
        tag: str = None
    ):
        self.address = address
        self.tag = tag
        value = f'{self.address};tag={self.tag}' if self.tag else self.address
        super().__init__('To', value)


class CallId(AbstractHeader):
    def __init__(self, call_id: str = None):
        self.call_id = call_id
        if not self.call_id:
            self.call_id = self._generate_call_id()
        super().__init__('Call-ID', self.call_id)
    
    def _generate_call_id(self) -> str:
        return uuid4().hex[:10]


class CSeq(AbstractHeader):
    def __init__(self, method: Method, cseq: int = 1):
        self.method = method
        self.cseq = cseq
        super().__init__('CSeq', f'{self.cseq} {self.method}')


class Header:
    '''Armazenar e manipular headers SIP (AbstractHeader).'''
    MULTI_HEADERS = (
        'via',
        'contact',
        'route',
        'record-route',
        'path',
        'service-route',
        'p-associated-uri',
    )
    COMPACT_HEADERS = {
        'v': 'via',
        'f': 'from',
        't': 'to',
        'm': 'contact',
        'i': 'call_id',
        's': 'subject',
        'l': 'content_length',
        'c': 'content_type',
        'k': 'supported',
        'o': 'allow',
        'p': 'p_associated_uri',
    }
    
    def __init__(
        self,
        via_field: Via = None,
        from_field: From = None,
        to_field: To = None,
        call_id_field: CallId = None,
        cseq_field: CSeq = None,
        extras_fields: List[AbstractHeader] = None,
    ):
        self._headers = {}
        if via_field:
            self._headers['via'] = via_field
        if from_field:
            self._headers['from'] = from_field
        if to_field:
            self._headers['to'] = to_field
        if call_id_field:
            self._headers['call_id'] = call_id_field
        if cseq_field:
            self._headers['cseq'] = cseq_field
        if extras_fields:
            for field in extras_fields:
                self._headers.add(field)
    
    @staticmethod
    def _normalize_header_name(header_name: str) -> str:
        '''Converte para lowercase e substitui hífens '-' por underscores '_'.'''
        if header_name in Header.COMPACT_HEADERS:
            return Header.COMPACT_HEADERS[header_name]
        return header_name.lower().replace('-', '_')
    
    def __setitem__(self, key: str, value: AbstractHeader) -> Union[str, List[str], None]:
        '''
        Permite adicionar headers usando diferentes formatos:
            - sip['call_id'] = valor
            - sip['Call-ID'] = valor
            - sip['CalL-iD'] = valor
        '''
        normalized_name = self._normalize_header_name(key)
        if normalized_name in self.MULTI_HEADERS:
            if normalized_name not in self._headers:
                self._headers[normalized_name] = []
            if isinstance(value, (list, tuple)):
                self._headers[normalized_name].extend(value)
            else:
                self._headers[normalized_name].append(value)
        else:
            self._headers[normalized_name] = value
        return self._headers[normalized_name]
    
    def __getitem__(self, key: str) -> Union[str, List[str], None]:
        return self._headers.get(self._normalize_header_name(key), None)

    def __delitem__(self, key: str) -> None:
        del self._headers[self._normalize_header_name(key)]

    def __contains__(self, key: str) -> bool:
        return self._normalize_header_name(key) in self._headers

    def __len__(self) -> int:
        return len(self._headers)
    
    def __str__(self) -> str:
        lines = []
        for _, value in self._headers.items():
            if isinstance(value, (list, tuple)):
                for v in value:
                    lines.append(v)
            else:
                lines.append(value)
        return ''.join([f'{line}' for line in lines])

    def add(self, header: AbstractHeader) -> None:
        if isinstance(header, (list, tuple)):
            key = header[0].key
            self[key] = header
        else:
            self[header.key] = header
    
    def get(self, key: str) -> Union[str, List[str], None]:
        return self[key]
    
    @classmethod
    def from_string(cls, string: str) -> 'Header':
        h = cls()
        lines = [line.strip() for line in string.splitlines() if line.strip()]
        for line in lines:
            if ':' not in line:
                continue
            k, v = line.split(':', 1)
            h[k.strip()] = v.strip()
        return h
