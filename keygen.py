import sounddevice as sd
import hashlib
import configparser
import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument("--count", help="Keys", required=True, type=int)
parser.add_argument("--tunnel_mode", help="Specify the tunnel mode", required=True)
parser.add_argument("--output", help="Output File", required=True)
parser.add_argument("--seed_type", help="Specify the seed type (audio/keyboard)", required=True)
args = parser.parse_args()

config = {
    "tunnel_mode": args.tunnel_mode,
    "connections": [],
    "relays": [],
    "keys": []
}

# Set the duration to listen to the microphone (in seconds)
duration = [60, 50, 40, 30, 20, 10, 9, 8, 7, 6, 5, 4, 3, 2]

# Set the sample rate and number of channels
sample_rate = 44100
channels = 1
entropy = b""

count = 0

# Initialize the SHA256 hash object
sha256_hash = hashlib.sha256()

def hash_pcm_data(indata, frames, time, status):
    global sha256_hash
    # Update the hash object with the PCM data chunk
    sha256_hash.update(indata.tobytes())

def genKeyboardSeededHash():
    global entropy, sha256_hash
    # Get keyboard input
    data = input("Enter keyboard entropy: ")
    entropy += data.encode()
    # Update the hash object with the keyboard input
    sha256_hash.update(entropy)
    return sha256_hash.hexdigest()

def genAudioSeededHash():
    global count
    # Start listening to the microphone
    
    d = 1
    if count < len(duration):
        d = duration[count]

    count = count + 1

    with sd.InputStream(callback=hash_pcm_data, channels=channels, samplerate=sample_rate):
        sd.sleep(int(d * 1000))

    # Get the final hash value
    return sha256_hash.hexdigest()

def calculate_merkle_hash(data):
    hash_value = hashlib.sha256(str(data).encode()).digest()
    double_hash_value = hashlib.sha256(hash_value).digest()
    return double_hash_value[-16:].hex()

print("Enter the connections for the tunnel")
while True:
    mode = input("Enter mode: ")
    host = input("Enter host: ")
    port = input("Enter port: ")
    
    config["connections"].append({"socket_mode": mode, "host": host, "port": port})
    
    add_another = input("Add another entry? (y/n): ")
    if add_another.lower() != "y":
        break

host_relay = input("Host a relay? (yes/NO): ")
if host_relay == 'yes':

    print("Enter the relay connections")
    while True:
        host1 = input("Enter host 1: ")
        port1 = input("Enter port 1: ")
        host2 = input("Enter host 2: ")
        port2 = input("Enter port 2: ")
        
        config["relays"].append({"host1": host1, "port1": port1, "host2": host2, "port2": port2})
        
        add_another = input("Add another entry? (y/n): ")
        if add_another.lower() != "y":
            break


for i in range(args.count):
    if args.seed_type == "keyboard":
        key = genKeyboardSeededHash()
    elif args.seed_type == "audio":
        key = genAudioSeededHash()

    iv = calculate_merkle_hash(key)
    config["keys"].append({"key": key, "iv": iv})
    print(str(i+1))

# Write config object as JSON to a file
with open(args.output, 'w') as f:
    json.dump(config, f)

print(config)

