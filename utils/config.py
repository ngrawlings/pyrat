import json
from utils.EncryptedSocket import EncryptionParams

_heart_beat_channel = None

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
            on_connect = connection['on_connect'] if 'on_connect' in connection else None
            connections.append((host, port, socket_mode, on_connect))

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

        if 'heart_beat_channel' in data:
            global _heart_beat_channel
            _heart_beat_channel = data['heart_beat_channel']

    return tunnel_mode, connections, relays, http_fallbacks, enc_keys

def get_heart_beat_channel():
    global _heart_beat_channel
    return _heart_beat_channel