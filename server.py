from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import json
from urllib.parse import parse_qs
import os
import mimetypes
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64

class KeyManager:
    def __init__(self, keys_dir):
        print("Initializing KeyManager...", file=sys.stderr)
        self.keys_dir = Path(keys_dir)
        self.private_key_path = self.keys_dir / 'local.pem'
        self.public_key_path = self.keys_dir / 'local.pub'
        os.makedirs(self.keys_dir, exist_ok=True)
        print("Created keys directory", file=sys.stderr)
        self._ensure_keypair()
    
    def _ensure_keypair(self):
        if not self.private_key_path.exists():
            print("Generating new keypair...", file=sys.stderr)
            # Generate key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Save private key
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            self.private_key_path.write_bytes(pem)
            
            # Save public key
            public_key = private_key.public_key()
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.public_key_path.write_bytes(pem)
            print("Keypair generated", file=sys.stderr)
    
    def sign_message(self, message):
        private_key = serialization.load_pem_private_key(
            self.private_key_path.read_bytes(),
            password=None,
            backend=default_backend()
        )
        signature = private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, message, signature_b64, public_key_pem):
        try:
            signature = base64.b64decode(signature_b64)
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
            public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

class MessageManager:
    def __init__(self, messages_dir, key_manager):
        self.messages_dir = Path(messages_dir)
        self.key_manager = key_manager
        os.makedirs(self.messages_dir, exist_ok=True)
    
    def save_message(self, content, author, type='message'):
        timestamp = datetime.now().isoformat()
        filename = f"{datetime.now():%Y%m%d_%H%M%S}_{author}.txt"
        signature = self.key_manager.sign_message(content)
        
        message = f"""Date: {timestamp}
Author: {author}
Type: {type}
Signature: {signature}

{content}"""
        
        path = self.messages_dir / filename
        path.write_text(message)
        return filename
    
    def read_messages(self):
        messages = []
        for file in sorted(self.messages_dir.glob('*.txt')):
            content = file.read_text()
            messages.append(self._parse_message(content))
        return messages
    
    def _parse_message(self, content):
        headers, body = content.split('\n\n', 1)
        header_dict = {}
        for line in headers.split('\n'):
            key, value = line.split(': ', 1)
            header_dict[key.lower()] = value
        return {
            'date': header_dict['date'],
            'author': header_dict['author'],
            'type': header_dict['type'],
            'signature': header_dict.get('signature'),
            'content': body.strip()
        }

class ChatRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=os.path.dirname(os.path.abspath(__file__)), **kwargs)
    
    def do_GET(self):
        if self.path == '/messages':
            self._send_json(self.server.message_manager.read_messages())
        elif self.path == '/verify_username':
            self._send_json({'username': self._get_username()})
        elif self.path == '/':
            self.path = '/index.html'
            return super().do_GET()
        else:
            return super().do_GET()
    
    def do_POST(self):
        content_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_len).decode() if content_len else ''
        
        if self.path == '/messages':
            try:
                if self.headers.get('Content-Type') == 'application/json':
                    data = json.loads(body)
                else:
                    data = parse_qs(body)
                    data = {
                        'content': data.get('content', [''])[0],
                        'author': self._get_username(),
                        'type': 'message'
                    }
                
                if not self._validate_message(data):
                    self._send_error(400, "Invalid message format")
                    return
                
                filename = self.server.message_manager.save_message(**data)
                self._send_json({'status': 'success', 'id': filename})
            except Exception as e:
                self._send_error(400, str(e))
    
    def _send_json(self, data):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def _send_error(self, code, message):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'error': message}).encode())
    
    def _get_username(self):
        return 'anonymous'  # Default username
    
    def _validate_message(self, data):
        required_fields = ['content', 'author', 'type']
        if not all(field in data for field in required_fields):
            return False
        
        valid_types = ['message', 'username_change', 'system', 'error']
        if data['type'] not in valid_types:
            return False
        
        if not self._validate_username(data['author']):
            return False
        
        return True
    
    def _validate_username(self, username):
        import re
        return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))

def run_server(host='', port=8000):
    server_address = (host, port)
    httpd = HTTPServer(server_address, ChatRequestHandler)
    httpd.message_manager = MessageManager('messages', KeyManager('keys'))
    print(f"Starting server on port {port}...", file=sys.stderr)
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()
