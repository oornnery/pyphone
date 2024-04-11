# $Id: call.py 2171 2008-07-24 09:01:33Z bennylp $
#
# SIP call sample.
#
# Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
#
import sys
import socket
import re
import netifaces
import pjsua as pj
from rich.console import Console
from rich.panel import Panel
from rich import print

# Subclass to extend the Account and get notifications etc.

class MyAccountCallback(pj.AccountCallback):
    
    def __init__(self, account=None):
        pj.AccountCallback.__init__(self, account)
    
    def on_reg_state(self, acc, status):
        if status.is_final():
            if status.is_confirmed():
                print("Call confirmed")
            else:
                print("Call failed")

    def on_incoming_call(self, acc, call):
        global current_call
        current_call = call
        print("Incoming call")
        call.answer_with_video()
        print("Call answered")

    def on_outgoing_call(self, acc, call):
        global current_call
        current_call = call
        print("Outgoing call")
        call.answer_with_video()
        print("Call answered")

class MyCallCallback(pj.CallCallback):
    
    def __init__(self, call=None):
        pj.CallCallback.__init__(self, call)

    def on_call_media_state(self, call):
        global current_call
        if current_call == call:
            print("Call media state changed")

    def on_call_state(self, call):
        global current_call
        if current_call == call:
            print("Call state changed")

    def on_call_media_state(self, call):
        global current_call
        if current_call == call:
            print("Call media state changed")


console = Console()

LOG_LEVEL= 3
current_call = None
transport = None
acc = None
lib = None


# Logging callback
def log_cb(level, str, len):
    console.print(
        Panel(
            str.decode('utf-8'),
            title="Log",
            border_style="green",
        )
    )

def quit():
    global current_call
    global transport
    global acc
    global lib
    if current_call:
        current_call.hangup(487)
        current_call = None
    if transport:
        transport = None
    if acc:
        acc.delete()
        acc = None
    if lib:
        # Shutdown the library
        lib.destroy()
        lib = None
    sys.exit(0)


try:
    # Create library instance
    lib = pj.Lib()
    # Init library with default config and some customized
    # logging config.
    lib.init(
        log_cfg=pj.LogConfig(level=LOG_LEVEL, callback=log_cb)
        )

    # Create UDP transport which listens to any available port
    transport = lib.create_transport(
        pj.TransportType.UDP, 
        pj.TransportConfig(0)
        )
    # Start the library
    lib.start()

    lib.set_codec_priority('PCMA/8000/1', 0)
    lib.set_codec_priority('PCMU/8000/1', 32)
    
    # Create local account
    acc = lib.create_account(pj.AccountConfig(
        "proxy2.idtbrasilhosted.com", 
        "062099137", 
        "fabio.2626",
        ),
        cb=MyAccountCallback()
        )
    # Set presence to available
    acc.set_presence_status(True, activity=pj.PresenceActivity.UNKNOWN)
    # Loop
    print("\nEnter SIP URI or 'q' to quit")
    while True:
        uri = input('>> ')
        # quit
        if uri == "q":
            break
        # make call
        if uri == 'c':
            if current_call:
                current_call.hangup(487)
                current_call = None
            print("Enter SIP URI to call")
            call_uri = input('>> ')
            if call_uri == "":
                continue
            lck = lib.auto_lock()
            try:
                print("Making call to", call_uri)
                current_call = acc.make_call(
                    re.sub(r'^<sip:([a-zA-Z0-9]+)@(.*)>$', rf'<sip:{call_uri}@\2>', acc.info().uri),
                    )
                
                # while True:
                #     print(current_call.info().state_text)
                #     if current_call.info().state == pj.CallState.DISCONNECTED:
                #         break
                
            except pj.Error as e:
                current_call = None
                print("Exception: " + str(e))
            del lck
        # hangup
        if uri == 'h':
            if current_call:
                current_call.hangup(487)
                current_call = None
            continue
        # status
        if uri == 's':
            print('Status: \n')
            data=[
                ('URI', acc.info().uri),
                ('Reg Status', acc.info().reg_status),
                ('Reg Reason', acc.info().reg_reason),
                ('Reg Active', acc.info().reg_active),
                ('Reg Expires', acc.info().reg_expires),
                ('Online Status', acc.info().online_status),
                ('Online Text', acc.info().online_text),
            ]
            console.print(
                Panel(
                    ''.join([f'[bold]{i[0]}[/bold]: {i[1]}\n' for i in data]),
                    title="Status",
                    border_style="green",
                )
            )
        if uri == 'ci':
            if current_call:
                data = [
                    ('Role', current_call.info().role),
                    ('Account', current_call.info().account),
                    ('URI', current_call.info().uri),
                    ('Contact', current_call.info().contact),
                    ('Remote uri', current_call.info().remote_uri),
                    ('Remote contact', current_call.info().remote_contact),
                    ('SIP Call Id', current_call.info().sip_call_id),
                    ('State', current_call.info().state),
                    ('State text', current_call.info().state_text),
                    ('Last code', current_call.info().last_code),
                    ('Last reason', current_call.info().last_reason),
                    ('Media state', current_call.info().media_state),
                    ('Media dir', current_call.info().media_dir),
                    ('Conf slot', current_call.info().conf_slot),
                    ('Call time', current_call.info().call_time),
                    ('Total time', current_call.info().total_time),
                ]
                console.print(
                    Panel(
                        ''.join([f'[bold]{i[0]}[/bold]: {i[1]}\n' for i in data]),
                        title="Call Info",
                        border_style="green",
                    )
                )
except pj.Error as e:
    print("Exception: " + str(e))
    quit()
except KeyboardInterrupt:
    console.print("\nInterrupted")
    quit()
finally:
    console.print("\nInterrupted")
    quit()
        
