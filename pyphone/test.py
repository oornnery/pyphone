import pjsua2 as pj
env = dotenv.dotenv_values(".env")

# Create endpoint instance
ep = pj.Endpoint()

# Create media endpoint
media_cfg = pj.MediaConfig()
media_cfg.clockRate = 16000
media_cfg.channelCount = 1
media_cfg.ptime = 20
media_endpoint = ep.create_media_endpoint()
media_endpoint.create_audio_media_transport(media_cfg)

# Create transport configuration
transport_cfg = pj.TransportConfig()
transport_cfg.port = 0  # Use any available port

# Create UDP transport
transport = ep.create_transport(pj.TransportType.UDP, transport_cfg)

# Start the endpoint
ep.lib_start()

# Create account configuration
acc_cfg = pj.AccountConfig()
acc_cfg.id = "sip:alice@pjsip.org"
acc_cfg.reg_uri = "sip:pjsip.org"
acc_cfg.auth_cred = [ pj.AuthCred("*", "alice", "secret") ]

# Create account
acc = ep.create_account(acc_cfg)

# Make call
call = acc.make_call("sip:bob@pjsip.org", pj.CallOpParam())

# Open audio file
wav_file = pj.WavFileMedia("audio.wav")

# Start transmitting audio
media_endpoint.start_transmit(wav_file)

# Create audio file
wav_file = pj.WavFileWriter("audio.wav")

# Start receiving audio
media_endpoint.start_receive(wav_file)

# Destroy endpoint
ep.lib_destroy()
ep = None
