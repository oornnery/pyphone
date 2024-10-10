import pytest
from pyphone.core.header import (
    Via
    )

# from pyphone.core.utils import (
#     ProtocolType,
# )

"""
parameters such as "maddr","ttl", "received", and "branch"
Via: SIP/2.0/UDP erlang.bell-telephone.com:5060;branch=z9hG4bK87asdks7
Via: SIP/2.0/UDP 192.0.2.1:5060;received=192.0.2.207;branch=z9hG4bK77asjd
Via: SIP / 2.0 / UDP first.example.com: 4000;ttl=16;maddr=224.2.0.1 ;branch=z9hG4bKa7c6a8dlze.1
"""

def test_create_via_complete():
    via = Via(address='erlang.bell-telephone.com', port=5060, params={'branch': 'z9hG4bK87asdks7', 'ttl': 16, 'received': '192.0.2.1', 'maddr': '224.2.0.1'})
    assert str(via) == 'Via: SIP/2.0/UDP erlang.bell-telephone.com:5060;branch=z9hG4bK87asdks7;ttl=16;received=192.0.2.1;maddr=224.2.0.1'


def test_parser_via():
    via = Via.parser('Via: SIP/2.0/UDP erlang.bell-telephone.com:5060;branch=z9hG4bK87asdks7;ttl=16;received=192.0.2.1;maddr=224.2.0.1')
    assert str(via) == 'Via: SIP/2.0/UDP erlang.bell-telephone.com:5060;branch=z9hG4bK87asdks7;ttl=16;received=192.0.2.1;maddr=224.2.0.1'