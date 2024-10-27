from pyVoIP.credentials import CredentialsManager
from pyVoIP.VoIP.call import VoIPCall
from pyVoIP.VoIP.error import InvalidStateError
from pyVoIP.VoIP.phone import VoIPPhone, VoIPPhoneParameter

class Call(VoIPCall):

  def ringing(self, invite_request):
      try:
          self.answer()
          self.hangup()
      except InvalidStateError:
          pass

if __name__ == "__main__":
    cm = CredentialsManager()
    cm.add(
        username='062099137',
        password='fabio.2626'
    )
    params = VoIPPhoneParameter(
        server='proxy2.idtbrasilhosted.com',
        port=5060,
        user='062099137',
        credentials_manager=cm, 
        # call_class=Call
        )
    phone = VoIPPhone(params)
    phone.start()
    c = phone.call('039959137')
    input('Press enter to disable the phone')
    c.hangup()
    phone.stop()