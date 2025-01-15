import re
import pytest

from pyphone.utils import (
    REQUEST_LINE_PATTERN,
    RESPONSE_LINE_PATTERN,
    URI_PATTERN,
    ADDRESS_PATTERN,
    HEADER_PATTERN,
    BODY_PATTERN,
)


def test_request_line_pattern():
    pattern = re.compile(REQUEST_LINE_PATTERN)
    test_string = 'INVITE sip:user@example.com SIP/2.0'
    res = pattern.match(test_string)
    
    assert res.group('method') == 'INVITE'
    assert res.group('uri') == 'sip:user@example.com'
    assert res.group('scheme') == 'SIP'
    assert res.group('version') == '2.0'

def test_response_line_pattern():
    pattern = re.compile(RESPONSE_LINE_PATTERN)
    test_string = 'SIP/2.0 200 OK'
    res = pattern.match(test_string)
    
    assert res.group('scheme') == 'SIP'
    assert res.group('version') == '2.0'
    assert res.group('status_code') == '200'
    assert res.group('reason') == 'OK'



def test_uri_complete_pattern():
    pattern = re.compile(URI_PATTERN)
    test_string = '"Username" <sip:user@example.com:5060;transport=tcp;received=0.0.0.0>;tag=123456'
    
    res = pattern.match(test_string)
    assert res.group('display_info') == 'Username'
    assert res.group('uri') == '<sip:user@example.com:5060;transport=tcp;received=0.0.0.0>'
    assert res.group('user') == 'user'
    assert res.group('host') == 'example.com'
    assert res.group('port') == '5060'
    assert res.group('params') == 'transport=tcp;received=0.0.0.0'
    assert res.group('tag') == '123456'
    