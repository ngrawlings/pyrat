import threading
import time
import datetime
from web.CmdRelay import set_channel
import random, string

class HeartBeatThread(threading.Thread):
    def __init__(self, url, channel, enc_keys):
        super().__init__()
        self.url = url
        self.channel = channel
        self.enc_keys = enc_keys
        self._stop_event = threading.Event()

    def run(self):
        def randomword(length):
           letters = string.ascii_lowercase
           return ''.join(random.choice(letters) for i in range(length))

        while not self._stop_event.is_set():
            try:
                random_str = randomword(16)
                current_time = datetime.datetime.now()
                current_time_str = current_time.strftime("%Y-%m-%d %H:%M:%S")
                if not set_channel(self.url, self.channel, self.enc_keys, -1, f"{random_str} {current_time_str}"):
                    print("Heartbeat failed")
                time.sleep(60)
            except Exception as e:
                print(e)

    def stop(self):
        self._stop_event.set()
