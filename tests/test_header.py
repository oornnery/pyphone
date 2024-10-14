import pytest
from pyphone.client import (
    RequestLine,
    StatusLine,
    Via,
    )



def test_request_line_uri():
    h = RequestLine(method='INVITE', remote_username='1002', remote_address='proxy.example.com', remote_port=5060)
    assert str(h) == 'INVITE sip:1002@proxy.example.com:5060 SIP/2.0'


def test_status_line_uri():
    h = StatusLine(status_code=200, reason_phrase='OK')
    assert str(h) == 'SIP/2.0 200 OK'


def test_via_uri():
    h = Via(public_address='0.0.0.0', public_port=5060, branch='z9hG4bK-12345678')
    assert str(h) == 'Via: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bK-12345678'

# def test_from_uri():
#     uri = Uri(address='127.0.0.1', username='1001', port=5060, params={'tag': '12345678'})
#     assert uri == '"P2x9137" sip:1001@127.0.0.1:5060;tag=12345678'

# def test_to_uri():
#     uri = Uri(address='proxy.example.com', username='1002', port=5060)
#     assert uri == 'sip:1002@proxy.example.com:5060'


