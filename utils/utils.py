import os
import hashlib
import datetime
import json
from utils.EncryptedSocket import EncryptionParams

def load_config(file_path):
    connections = []
    relays = []
    http_fallbacks = []
    enc_keys = []

    with open(file_path, 'r') as file:
        data = json.load(file)

        tunnel_mode = data['tunnel_mode']

        for connection in data['connections']:
            host = connection['host']
            port = int(connection['port'])
            socket_mode = connection['socket_mode']
            connections.append((host, port, socket_mode))

        if 'relays' in data:
            for relay in data['relays']:
                host1 = relay['host1']
                port1 = int(relay['port1'])
                host2 = relay['host2']
                port2 = int(relay['port2'])
                relays.append((host1, port1, host2, port2))

        if 'http_fallback' in data:
            for fallback in data['http_fallback']:
                url = fallback['url']
                channel = fallback['channel']
                status_channel = fallback['status_channel']
                http_fallbacks.append((url, channel, status_channel))

        for item in data['keys']:
            key = item['key']
            iv = item['iv']
            encryption_param = EncryptionParams(key, iv)
            enc_keys.append(encryption_param)

    return tunnel_mode, connections, relays, http_fallbacks, enc_keys

def get_file_list(directory):
    file_list = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_name = os.path.basename(file_path)
            creation_date = datetime.datetime.fromtimestamp(os.path.getctime(file_path)).timestamp()
            modified_date = datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).timestamp()
            sha256_hash = calculate_sha256_checksum(file_path)
            file_size = os.path.getsize(file_path)
            file_info = {
                'name': file_name,
                'creation_date': creation_date,
                'modified_date': modified_date,
                'sha256_hash': sha256_hash,
                'file_size': file_size
            }
            file_list.append(file_info)
    return file_list

def calculate_sha256_checksum(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()
