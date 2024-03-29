import os
import threading
import time
from web.CmdRelay import get_channel, set_channel
import json
import traceback

class WebCommandParser(threading.Thread):
    def __init__(self, url, channel, enc_keys, web_log_queue):
        super().__init__()
        self.url = url
        self.channel = channel
        self.enc_keys = enc_keys
        self._stop_event = threading.Event()
        self.web_log_queue = web_log_queue
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
                file.write(error + "\n")
        except:
            pass

        try:
            if self.status_channel is not None:
                self.web_log_queue('Error: '+error)
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

    

