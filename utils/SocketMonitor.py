import time
import threading
from utils.Socket import Socket

class SocketMonitor:
    def __init__(self):
        self.sockets = {}
        self.stop_event = threading.Event()

    def track_socket(self, socket:Socket):
        self.sockets[socket] = time.time()

    def check_activity(self):
        current_time = time.time()
        for socket, last_activity_time in self.sockets.items():
            packets_received = socket.packet_counter
            if packets_received > 0:
                if last_activity_time < current_time - 3600:
                    # Socket has been inactive for more than 1 hour, close it
                    socket.close()
                    del self.sockets[socket]
            else:
                if last_activity_time < current_time - 300:
                    # Socket has been inactive for more than 5 minutes, close it
                    socket.close()
                    del self.sockets[socket]

    def run_check_activity_thread(self):
        while not self.stop_event.is_set():
            self.check_activity()
            time.sleep(60)  # Sleep for 1 minute

    def start(self):
        thread = threading.Thread(target=self.run_check_activity_thread)
        thread.start()

    def stop(self):
        self.stop_event.set()

    