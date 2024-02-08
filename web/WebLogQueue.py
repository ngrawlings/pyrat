import threading
from web.CmdRelay import set_channel
import time

class WebLogQueue:
    def __init__(self, url, status_channel, enc_keys):
        self.queue = []
        self.flush_thread = threading.Thread(target=self.flush_queue, daemon=True)
        self.flush_thread.start()

        self.url = url
        self.status_channel = status_channel
        self.enc_keys = enc_keys

    def log(self, output):
        if len(self.queue) > 0:
            self.queue.append(output)
        else:
            if not set_channel(self.url, self.status_channel, self.enc_keys, -1, output):
                self.queue.append(output)

    def flush_queue(self):
        while True:
            if self.queue:
                for output in self.queue:
                    if set_channel(self.url, self.status_channel, self.enc_keys, -1, output):
                        self.queue.remove(output)
            time.sleep(10)
