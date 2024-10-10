import re

via_regex = re.compile(r'''
    Via:\s
    (?P<scheme>\w+)/(?P<version>\d+\.\d+)/(?P<protocol>\w+)
    \s
    (?P<address>[^:;]+)
    (?::(?P<port>\d+))?
    (?P<params>(?:;\S+)*)
''', re.VERBOSE)

def parse_params(params_str):
    if not params_str:
        return {}
    params = {}
    for param in params_str.strip(';').split(';'):
        if '=' in param:
            key, value = param.split('=', 1)
            params[key] = value
        else:
            params[param] = None
    return params

def parse_via_header(via_header):
    match = via_regex.match(via_header)
    if match:
        result = match.groupdict()
        result['params'] = parse_params(result['params'])
        return result
    return None

# Testes
headers = [
    'Via: SIP/2.0/UDP erlang.bell-telephone.com:5060;branch=z9hG4bK87asdks7;ttl=16;received=192.0.2.1;maddr=224.2.0.1',
    'Via: SIP/2.0/UDP erlang.bell-telephone.com;branch=z9hG4bK87asdks7;ttl=16;received=192.0.2.1;maddr=224.2.0.1',
    'Via: SIP/2.0/UDP erlang.bell-telephone.com;branch=z9hG4bK87asdks7;ttl=16;;received=192.0.2.1;maddr=224.2.0.1',
    'Via: SIP/2.0/UDP erlang.bell-telephone.com'
]


def parser_from_string(message: str) -> dict:
    if not message:
        return {}
    return dict((p.split('=') for p in [p for p in message.strip(';').split(';')] if '=' in p))


def parse_from_dict(params: dict) -> str:
    
    if not params:
        return ''
    return ''.join([f';{k}={v}' for k, v in params.items()])


def parser_uri_to_str(
        address: str,
        user: str = None,
        port: int = None,
        params: dict = None,
        scheme: str = 'SIP'
    ) -> str:
    _user = (f'{scheme.lower()}:{user}@' if user else '')
    _port = (f':{port}' if port else '')
    _params = (parse_from_dict(params) if params else '')
    return f'{_user}{address}{_port}{_params}'


class Header:
    """
    Constructor for Header.

    :param gen_via: Via header.
    :param gen_from: From header.
    :param gen_to: To header.
    :param gen_contact: Contact header.
    :param gen_call_id: CallId header.
    :param gen_cseq: CSeq header.
    :param gen_max_forwards: MaxForwards header.
    :param gen_user_agent: UserAgent header.
    :param gen_server: Server header.
    :param gen_expires: Expires header.
    :param gen_allow: Allow header.
    :param gen_supported: Supported header (Not implemented yet).
    :param gen_unsupported: Unsupported header (Not implemented yet).
    :param gen_content_type: ContentType header.
    :param gen_content_length: ContentLength header.
    :param gen_route: Route header (Not implemented yet).
    :param gen_record_route: RecordRoute header (Not implemented yet).
    :param gen_proxy_authenticate: ProxyAuthenticate header (Not implemented yet).
    :param gen_authorization: Authorization header (Not implemented yet).
    """

    _via: list = []
    _from: str = None
    _to: str = None
    _contact: list = []
    _call_id: str = None
    _cseq: str = None
    _max_forwards: str = None
    _user_agent: str = None
    _server: str = None
    _expires: str = None
    _allow: list = []
    _supported: str = None
    _unsupported: str = None
    _content_type: str = None
    _content_length: str = None
    _route: list = []
    _record_route: list = []
    _proxy_authenticate: str = None
    _authorization: str = None

    def gen_via(
        self,
        address: str,
        port: int = None,
        scheme: str = 'SIP',
        version: str = '2.0',
        protocol: str = 'UDP',
        params: dict = None
        ) -> str:
        _uri = parser_uri_to_str(address=address, port=port, params=params)
        return f'Via: {scheme.upper()}/{version}/{protocol} {_uri}'

    def gen_max_forwards(self, max_forwards: int = 70) -> str:
        return f'Max-Forwards: {max_forwards}'

    def gen_from(
        self,
        address: str,
        display_info: str = None,
        user: str = None,
        port: int = None,
        params: dict = None
        ) -> str:
        _display_info = f'"{display_info}" ' if display_info else ""
        _uri = parser_uri_to_str(address=address, user=user, port=port, params=params)
        return f'From: {_display_info}<{_uri}>'

    def gen_to(
        self,
        address: str,
        user: str = None,
        port: int = None,
        params: dict = None
        ) -> str:
        _uri = parser_uri_to_str(address=self.address, user=self.username, port=self.port, params=self.params)
        return f'To: <{_uri}>'

    def gen_contact(
        self,
        user: str,
        address: str,
        port: int = None
        ) -> str:
        _uri = parser_uri_to_str(address=address, user=user, port=port)
        return f'Contact: <{_uri}>'

    def gen_call_id(self, call_id: str) -> str:
        return f'Call-ID: {call_id}'

    def gen_cseq(self, cseq: int, method: str) -> str:
        return f'CSeq: {cseq} {method}'

    def gen_user_agent(self, user_agent: str = 'pyphone') -> str:
        return f'User-Agent: {user_agent}'

    def gen_server(self, server: str) -> str:
        return f'Server: {server}'

    def gen_expires(self, expires: int = 60) -> str:
        return f'Expires: {expires}'

    def gen_allow(self, allow_methods: list = ['INVITE', 'ACK', 'BYE', 'CANCEL', 'REGISTER', 'OPTIONS']) -> str:
        _allow = ', '.join([str(a) for a in allow_methods])
        return f'Allow: {_allow}'

    def gen_content_type(self, content: str = 'application', content_type: str = 'sdp') -> str:
        return f'Content-Type: {content}/{content_type}'

    def gen_content_length(self, content_length: int = 0) -> str:
        return f'Content-Length: {content_length}'


if __name__ == '__main__':
    h = Header()
    h.gen_max_forwards()



