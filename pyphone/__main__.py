

def sip_options_callback(data, addr=None):
    print("\nSIP OPTIONS callback\n")
    if addr:
        print(f"Received response from {addr}: \n{data.decode()}\n")
    else:
        print(f"Received response: {data.decode()}\n")

# Configuration for sending SIP OPTIONS packets
cfg = ConnCfg(
    remote_addr="demo.mizu-voip.com",
    remote_port=37075,
    protocol="UDP"
)

handler = ConnectionHandler(cfg, sip_options_callback)
handler.start()

# Create SIP OPTIONS packet
sip_options_packet = (
    "OPTIONS sip:demo.mizu-voip.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK776asdhds\r\n"
    "Max-Forwards: 70\r\n"
    "To: <sip:demo.mizu-voip.com>\r\n"
    "From: <sip:client@127.0.0.1>;tag=1928301774\r\n"
    "Call-ID: a84b4c76e66710@127.0.0.1\r\n"
    "CSeq: 63104 OPTIONS\r\n"
    "Contact: <sip:client@127.0.0.1>\r\n"
    "Accept: application/sdp\r\n"
    "Content-Length: 0\r\n\r\n"
).encode()

# Send SIP OPTIONS packet
handler.send(sip_options_packet)

# Wait for responses
print("Waiting for responses...\n")

input("Press Enter to finish...\n")
# Finalize the test
handler.stop()
print("Test finished.\n")
