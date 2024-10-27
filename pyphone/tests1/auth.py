import hashlib
import base64

class DigestAuth:
    def __init__(self, username: str, realm: str, nonce: str, uri: str, method: str = "INVITE"):
        self.username = username
        self.realm = realm
        self.nonce = nonce
        self.uri = uri
        self.method = method

    def generate_response(self, password: str) -> str:
        # Método para gerar o response de acordo com o RFC 2617 (Digest Access Authentication)
        ha1 = hashlib.md5(f"{self.username}:{self.realm}:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"{self.method}:{self.uri}".encode()).hexdigest()
        return hashlib.md5(f"{ha1}:{self.nonce}:{ha2}".encode()).hexdigest()

    def __str__(self):
        # Exemplo de geração da string Authorization para Digest
        auth_response = self.generate_response("password")  # "password" precisa ser fornecida ou gerada
        return (f'Digest username="{self.username}", realm="{self.realm}", '
                f'nonce="{self.nonce}", uri="{self.uri}", response="{auth_response}"')

# Classe para autenticação Basic (Base64)
class BasicAuth:
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password

    def __str__(self):
        # Base64 encode de "username:password"
        credentials = f"{self.username}:{self.password}".encode()
        base64_credentials = base64.b64encode(credentials).decode()
        return f"Basic {base64_credentials}"

# Classe para autenticação Bearer (Token OAuth2)
class BearerAuth:
    def __init__(self, token: str):
        self.token = token

    def __str__(self):
        return f"Bearer {self.token}"
