from message import MessageFactory, Method, Via, From, To, CallId, CSeq, HeaderField, StatusCode, Address


def test_message_factory():
    # Setup
    local_address = "0.0.0.0"
    local_port = 5060
    remote_address = "sip.example.com"
    remote_port = 5060
    
    # Test INVITE request
    print("Testing INVITE request creation:\n")
    invite_request = MessageFactory.create_request(
        method=Method.INVITE,
        host=remote_address, port=remote_port,
        via_field=Via(host=remote_address, port=remote_port),
        from_field=From(address=Address(host=local_address, port=local_port, user="alice")),
        to_field=To(address=Address(host=remote_address, port=remote_port, user="bob")),
        call_id_field=CallId(),
        cseq_field=CSeq(method=Method.INVITE),
        extra_headers_fields=[HeaderField("Contact", f"<sip:alice@{local_address}:{local_port}>")]
    )
    print(invite_request)
    print("\n" + "="*50 + "\n")

    # Test OPTIONS request
    print("Testing OPTIONS request creation:\n")
    options_request = MessageFactory.create_request(
        method=Method.OPTIONS,
        host=remote_address, port=remote_port,
        via_field=Via(host=remote_address, port=remote_port),
        from_field=From(address=Address(host=local_address, port=local_port, user="alice")),
        to_field=To(address=Address(host=remote_address, port=remote_port, user="bob")),
        call_id_field=CallId(),
        cseq_field=CSeq(method=Method.OPTIONS),
        extra_headers_fields=[HeaderField("Accept", "application/sdp")]
    )
    print(options_request)
    print("\n" + "="*50 + "\n")

    # Test 200 OK response to INVITE
    print("Testing 200 OK response to INVITE:\n")
    invite_response = MessageFactory.create_response(
        original_request=invite_request,
        status_code=StatusCode.OK,
        extra_headers_fields=[HeaderField("Contact", f"<sip:bob@{remote_address}:{remote_port}>")]
    )
    print(invite_response)
    print("\n" + "="*50 + "\n")

    # Test 200 OK response to OPTIONS
    print("Testing 200 OK response to OPTIONS:\n")
    options_response = MessageFactory.create_response(
        original_request=options_request,
        status_code=StatusCode.OK,
        extra_headers_fields=[
            HeaderField("Allow", "INVITE, ACK, CANCEL, OPTIONS, BYE"),
            HeaderField("Accept", "application/sdp"),
            HeaderField("Accept-Encoding", "gzip"),
            HeaderField("Accept-Language", "en")
        ]
    )
    print(options_response)

# Run the tests
test_message_factory()