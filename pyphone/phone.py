#!/usr/bin/env python3
import sys
import re
import threading
import pjsua as pj

import dotenv

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich import print


# Create output console
console = Console()
# Load environment variables
env = dotenv.dotenv_values(".env")


LOG_LEVEL= 3
current_call = None
transport = None
acc = None
lib = None




# Subclass to extend the Account and get notifications etc.
# Callback to receive events from Call
class MyCallCallback(pj.CallCallback):

    def __init__(self, call=None):
        pj.CallCallback.__init__(self, call)

    # Notification when call state has changed
    def on_state(self):
        global current_call
        print("Call with", self.call.info().remote_uri, end=' ')
        print("is", self.call.info().state_text, end=' ')
        print("last code =", self.call.info().last_code, end=' ') 
        print(f"{self.call.info().last_reason}")
        
        if self.call.info().state == pj.CallState.DISCONNECTED:
            current_call = None
            print('Current call is', current_call)

    # Notification when call's media state has changed.
    def on_media_state(self):
        if self.call.info().media_state == pj.MediaState.ACTIVE:
            # Connect the call to sound device
            call_slot = self.call.info().conf_slot
            pj.Lib.instance().conf_connect(call_slot, 0)
            pj.Lib.instance().conf_connect(0, call_slot)
            print("Media is now active")
        else:
            print("Media is inactive")

class MyAccountCallback(pj.AccountCallback):
    sem = None

    def __init__(self, account):
        pj.AccountCallback.__init__(self, account)

    def wait(self):
        self.sem = threading.Semaphore(0)
        self.sem.acquire()

    def on_reg_state(self):
        if self.sem and self.account.info().reg_status >= 200:
                self.sem.release()

# Logging callback
def log_cb(level, str, len):
    console.print(
        Panel(
            str.decode('utf-8'),
            title="Log",
            border_style="green",
        )
    )


def start_service(username: str, password: str, domain: str, port: int = 5060):
    # sourcery skip: extract-method, remove-unnecessary-cast
    global transport
    global acc
    global lib
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
            pj.TransportConfig(int(port))
            )
        # Set codec priorities
        lib.set_codec_priority('PCMA/8000/1', 0)
        lib.set_codec_priority('PCMU/8000/1', 32)
        # Start the library
        lib.start()
        # Create local account
        acc = lib.create_account(
            pj.AccountConfig(
                domain=domain,
                username=username,
                password=password
            ))
        acc_cb = MyAccountCallback(acc)
        acc.set_callback(acc_cb)
        acc_cb.wait()
        # Set presence to available
        acc.set_presence_status(True, activity=pj.PresenceActivity.UNKNOWN)
    
    except pj.Error as e:
        console.print(Panel(f"Exception: {e}", title="Error", border_style="red"))
        quit()

def call(uri: str):
    """Send call"""
    global current_call
    global transport
    global acc
    global lib
    
    if not acc:
        console.print(Panel("No Account SIP", title="Error", border_style="red"))
        return
    
    try:
        lck = lib.auto_lock()
        call_uri = re.sub(r'^<sip:([a-zA-Z0-9]+)@(.*)>$', rf'<sip:{uri}@\2>', acc.info().uri)
        print("Making call to", call_uri)
        current_call = acc.make_call(
            call_uri,
            cb=MyCallCallback(),
            )
    except pj.Error as e:
        console.print(Panel(f"Exception: {e}", title="Error", border_style="red"))
        current_call = None
    finally:
        del lck

def hangup(code=487):
    """Call hangup"""
    global current_call
    global transport
    global acc
    global lib
    if not current_call:
        console.print(Panel("No call", title="Error", border_style="red"))
        return
    try:
        current_call.hangup(code)
    except pj.Error as e:
        console.print(Panel(f"Exception: {e}", title="Error", border_style="red"))
    finally:
        current_call = None

def quit():
    global current_call
    global transport
    global acc
    global lib
    console.print(Panel("Quitting", title="Status", border_style="green"))
    if current_call:
        hangup()
    transport = None
    if acc:
        acc.delete()
        acc = None
    if lib:
        # Shutdown the library
        lib.destroy()
        lib = None
    sys.exit(0)

def account_info():
    """Print account info"""
    global acc
    if not acc:
        console.print(Panel("No Account SIP", title="Error", border_style="red"))
        return

    ua = acc.info()
    data=[
        ('URI', ua.uri),
        ('Reg Status', ua.reg_status),
        ('Reg Reason', ua.reg_reason),
        ('Reg Active', ua.reg_active),
        ('Reg Expires', ua.reg_expires),
        ('Online Status', ua.online_status),
        ('Online Text', ua.online_text),
    ]
    console.print(
        Panel(
            ''.join([f'[bold]{i[0]}[/bold]: {i[1]}\n' for i in data]),
            title="Status",
            border_style="green",
        )
    )

def current_call_info():
    """Print current call info"""
    global current_call
    
    if not current_call:
        console.print(Panel("No call", title="Error", border_style="red"))
        return
    
    ci = current_call.info()
    data = [
        ('Role', ci.role),
        ('Account', ci.account),
        ('URI', ci.uri),
        ('Contact', ci.contact),
        ('Remote uri', ci.remote_uri),
        ('Remote contact', ci.remote_contact),
        ('SIP Call Id', ci.sip_call_id),
        ('State', ci.state),
        ('State text', ci.state_text),
        ('Last code', ci.last_code),
        ('Last reason', ci.last_reason),
        ('Media state', ci.media_state),
        ('Media dir', ci.media_dir),
        ('Conf slot', ci.conf_slot),
        ('Call time', ci.call_time),
        ('Total time', ci.total_time),
    ]
    console.print(
        Panel(
            ''.join([f'[bold]{i[0]}[/bold]: {i[1]}\n' for i in data]),
            title="Call Info",
            border_style="green",
        )
    )


def main(username: str, password: str, domain: str, port: int = 5060):
    global current_call
    global acc
    options = [
        'c - call',
        'h - hangup',
        's - status',
        'ci - call info',
        'a - Help', 
        'q - quit',
    ]
    def menu():
        console.print(Panel('\n'.join(options), title="Commands", border_style="green"))
    
    try:
        console.print(Panel("Starting", title="Status", border_style="green"))
        console.print(Panel(f"{username}\n{password}\n{domain}\n{port}", title="Status", border_style="green"))
        
        start_service(username, password, domain, port)
        # Loop
        
        while True:
            console.clear()
            menu()
            ask = Prompt.ask('>> ', choices=[x.split('-')[0].strip() for x in options], default='a')
            # quit
            if ask == "q":
                break
            if ask == "a":
                menu()
            # make call
            if ask == 'c':
                if current_call:
                    console.print(Panel("Call in progress", title="Error", border_style="red"))
                    continue
                call_uri = Prompt.ask("Call URI: ")
                if call_uri == "":
                    continue
                call(call_uri)
            # hangup
            if ask == 'h':
                hangup()
            # status
            if ask == 's':
                account_info()
            if ask == 'ci':
                current_call_info()
            input("\nPress ENTER to continue...")
    except pj.Error as e:
        console.print(Panel(f"Exception: {e}", title="Error", border_style="red"))
        quit()
    except KeyboardInterrupt:
        console.print("\nInterrupted")
        quit()
    # finally:
    #     console.print("\nInterrupted")
    #     quit()
        

if __name__ == "__main__":
    main(
        username=env.get('USERNAME'),
        password=env.get('PASSWORD'),
        domain=env.get('DOMAIN'),
        port=env.get('PORT', 5060),
    )