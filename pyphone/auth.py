import re
import hashlib


#### AUTH ####

class Digest:
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.nonce = ""
        self.realm = ""
        self.algorithm = "MD5"

    def parse_challenge(self, auth_header: str):
        """Parse WWW-Authenticate header"""
        parts = re.findall(r'(\w+)="([^"]+)"', auth_header)
        for key, value in parts:
            if key.lower() == 'realm':
                self.realm = value
            elif key.lower() == 'nonce':
                self.nonce = value
            elif key.lower() == 'algorithm':
                self.algorithm = value

    def generate_response(self, method: str, uri: str) -> str:
        """Generate Authorization header value"""
        ha1 = hashlib.md5(f"{self.username}:{self.realm}:{self.password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{self.nonce}:{ha2}".encode()).hexdigest()

        return (f'Digest username="{self.username}", realm="{self.realm}", '
                f'nonce="{self.nonce}", uri="{uri}", response="{response}", '
                f'algorithm={self.algorithm}')

