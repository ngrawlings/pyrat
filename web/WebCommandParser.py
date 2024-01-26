import sys
import threading
import time
from web.CmdRelay import get_channel
import json

class WebCommandParser(threading.Thread):
    def __init__(self, url, channel, enc_keys):
        super().__init__()
        self.url = url
        self.channel = channel
        self.enc_keys = enc_keys
        self._stop_event = threading.Event()

    def run(self):
        while not self._stop_event.is_set():
            cmd = get_channel(self.url, self.channel, self.enc_keys)
            if cmd is not None:
                print("Executing command: " + cmd)

                try:
                    cmd_json = json.loads(cmd)
                    
                    if cmd_json["cmd"] == "exit":
                        sys.exit()

                except json.JSONDecodeError:
                    print("Invalid JSON format")

            time.sleep(60)  # Sleep for 1 minute

    def stop(self):
        self._stop_event.set()
