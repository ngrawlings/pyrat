from utils.Socket import Socket
import threading
from queue import Queue
import socket
import threading
from queue import Queue

class PacketRelay:
    def __init__(self, address1, port1, address2, port2):
        self.address1 = address1
        self.port1 = port1
        self.address2 = address2
        self.port2 = port2
        self.cache1 = Queue()
        self.cache2 = Queue()
        self.connected1 = False
        self.connected2 = False
        self.lock = threading.Lock()
        self.sockets = []

    def start(self):
        self._run = True
        self.sockets = []
        thread1 = threading.Thread(target=self.listen, args=(self.address1, self.port1, self.cache1, self.cache2, self.connected1))
        thread2 = threading.Thread(target=self.listen, args=(self.address2, self.port2, self.cache2, self.cache1, self.connected2))
        thread1.start()
        thread2.start()

    def listen(self, address, port, cache, other_cache, connected):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sockets.append(sock)
        print(f"Relay: Listening on {address}:{port}")
        sock.bind((address, port))
        sock.listen(1)  # Listen for incoming connections
        conn, addr = sock.accept()  # Accept the connection
        connected = True
        
        while not other_cache.empty():
            packet = other_cache.get()
            self.forward_packet(packet)

        while self._run:
            data = conn.recv(1024)  # Receive data from the client
            packet = (data, addr)
            with self.lock:
                if connected:
                    self.forward_packet(packet)
                else:
                    cache.put(packet)

    def forward_packet(self, packet):
        data, addr = packet
        if addr[0] == self.address1 and addr[1] == self.port1:
            self.send_packet(data, addr, self.address2, self.port2)
        elif addr[0] == self.address2 and addr[1] == self.port2:
            self.send_packet(data, addr, self.address1, self.port1)

    def send_packet(self, data, source_addr, dest_address, dest_port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(data, (dest_address, dest_port))

    def stop(self):
        self._run = False
        for sock in self.sockets:
            sock.close()

    def is_running(self):
        thread1 = threading.Thread(target=self.listen, args=(self.address1, self.port1, self.cache1, self.cache2, self.connected1))
        thread2 = threading.Thread(target=self.listen, args=(self.address2, self.port2, self.cache2, self.cache1, self.connected2))
        return thread1.is_alive() and thread2.is_alive()

