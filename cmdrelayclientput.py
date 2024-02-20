import datetime
from web.CmdRelay import HTTPCommandRelayClient
from utils.config import load_config
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
import base64
import string
import random
import json
import time

# Create the argument parser
parser = argparse.ArgumentParser(description='Command Line Arguments')
parser.add_argument('--url', required=True, type=str, help='URL argument')
parser.add_argument('--keyindex', required=True, type=int, help='Key Index argument')
parser.add_argument('--config', required=True, type=str, help='Config file to load')
parser.add_argument('--cmd', type=str, help='Command to post')
parser.add_argument('--channel', required=True, type=str, help='Command to specific channel')

# Parse the command line arguments
args = parser.parse_args()

# Access the parsed arguments
url = args.url
keyindex = args.keyindex

_, _, _, _, enc_keys = load_config(args.config)

# Use the parsed arguments in your code
client = HTTPCommandRelayClient(url)

if (args.cmd is None):
    print("Deleting channel " + str(args.channel))
    res = client.delete_channel(args.channel)
else:
    key = enc_keys[keyindex].key
    iv = enc_keys[keyindex].vector

    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    cmd = json.dumps(args.cmd)
    cmd.timestamp = int(datetime.utcnow().timestamp())
    cmd = json.dumps(cmd)

    hashed_cmd = hashlib.sha256(str(cmd).encode()).digest()
    encrypted_data = cipher.encrypt(pad(hashed_cmd+cmd.encode(), AES.block_size))
    encoded_data = base64.b64encode(encrypted_data).decode('utf-8')

    print("Posting command to channel " + str(args.channel) + ": " + str(keyindex) + ":" + encoded_data)

    res = client.set_channel(args.channel, str(keyindex) + ":" + encoded_data)

if res is True:
    print('Success')
else:
    print('Failure')
