import threading
import time
import datetime
from web.CmdRelay import set_channel

class HeartBeatThread(threading.Thread):
    def __init__(self, url, channel, enc_keys):
        super().__init__()
        self.url = url
        self.channel = channel
        self.enc_keys = enc_keys
        self._stop_event = threading.Event()

    def run(self):
        while not self._stop_event.is_set():
            try:
                current_time = datetime.datetime.now()
                current_time_str = current_time.strftime("%Y-%m-%d %H:%M:%S")
                set_channel(self.url, self.channel, self.enc_keys, -1, current_time_str)
                time.sleep(60)
            except Exception as e:
                print(e)

    def stop(self):
        self._stop_event.set()
