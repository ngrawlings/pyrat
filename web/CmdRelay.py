from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import requests
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# In-memory dictionary to store channel data
channels = {}

class HTTPCommandRelayServer(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        path_parts = parsed_path.path.split('/')

        if len(path_parts) == 3 and path_parts[1] == 'get':
            channel_id = path_parts[2]
            if channel_id in channels:
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(channels[channel_id].encode())
            else:
                self.send_response(404)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'Channel not found')

    def do_POST(self):
        parsed_path = urlparse(self.path)
        path_parts = parsed_path.path.split('/')

        if len(path_parts) == 4 and path_parts[1] == 'set' and path_parts[2] == 'channel':
            channel_id = path_parts[3]
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            channels[channel_id] = post_data

            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Channel set successfully')

        elif len(path_parts) == 4 and path_parts[1] == 'delete' and path_parts[2] == 'channel':
            channel_id = path_parts[3]
            if channel_id in channels:
                del channels[channel_id]
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'Channel deleted successfully')
            else:
                self.send_response(404)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'Channel not found')

        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Invalid path')

#def run(server_class=HTTPServer, handler_class=RequestHandler, port=8000):
#    server_address = ('', port)
#    httpd = server_class(server_address, handler_class)
#    print(f'Starting server on port {port}...')
#    httpd.serve_forever()

#run()

class HTTPCommandRelayClient:
    def __init__(self, server_url):
        self.server_url = server_url

    def get_channel(self, channel_id):
        url = f"{self.server_url}/get/{channel_id}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            return None

    def set_channel(self, channel_id, data):
        url = f"{self.server_url}/set/channel/{channel_id}"
        response = requests.post(url, data=data)
        if response.status_code == 200:
            return True
        else:
            return False

    def delete_channel(self, channel_id):
        url = f"{self.server_url}/delete/channel/{channel_id}"
        response = requests.post(url)
        if response.status_code == 200:
            return True
        else:
            return False


def get_channel(server_url, channel_id, enc_keys):  
    try: 

        client = HTTPCommandRelayClient(server_url)

        res = client.get_channel(channel_id)
        key_index, payload = res.split(':') 

        key = enc_keys[int(key_index)].key
        iv = enc_keys[int(key_index)].vector

        decoded_data = base64.b64decode(payload)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_cmd = cipher.decrypt(decoded_data)
        unpadded_cmd = unpad(decrypted_cmd, AES.block_size)

        hashed_cmd = unpadded_cmd[:32]
        cmd = unpadded_cmd[32:].decode('utf-8')

        if hashed_cmd == hashlib.sha256(cmd.encode()).digest():
            # Successful retrived command, delete channel
            client.delete_channel(channel_id)
            return cmd
        
    except Exception as e:
        pass
    
    return None

import random

def set_channel(server_url, channel_id, enckeys, keyindex, cmd):
    try:
        if keyindex == -1:
            keyindex = random.randint(0, len(enckeys) - 1)

        key = enckeys[keyindex].key
        iv = enckeys[keyindex].vector

        cipher = AES.new(key, AES.MODE_CBC, iv)

        hashed_cmd = hashlib.sha256(str(cmd).encode()).digest()
        encrypted_data = cipher.encrypt(pad(hashed_cmd+cmd.encode(), AES.block_size))
        encoded_data = base64.b64encode(encrypted_data).decode('utf-8')

        client = HTTPCommandRelayClient(server_url)
        return client.set_channel(channel_id, str(keyindex) + ":" + encoded_data)

    except Exception as e:
        pass

    return False