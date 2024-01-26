import threading
import time
import datetime
from web.CmdRelay import set_channel

class HeartBeatThread(threading.Thread):
    def __init__(self, channel, enc_keys):
        super().__init__()
        self.channel = channel
        self.enc_keys = enc_keys
        self._stop_event = threading.Event()

    def run(self):
        while not self._stop_event.is_set():
            current_time = datetime.datetime.now()
            current_time_str = current_time.strftime("%Y-%m-%d %H:%M:%S")
            set_channel(self.enc_keys, self.channel, -1, current_time_str)
            time.sleep(60)

    def stop(self):
        self._stop_event.set()
