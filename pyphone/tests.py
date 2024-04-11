import re

print( re.sub(r'^<sip:([a-zA-Z0-9]+)@(.*)>$', r'<sip:AAA@\2>', '<sip:062099137@proxy2.idtbrasilhosted.com>'))