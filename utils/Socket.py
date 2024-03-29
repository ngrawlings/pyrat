import socket
import binascii
import traceback
import time

class Socket:
    _listening = False
    _remote_address = ''

    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.last_received_time = None
        self.packet_counter = 0

    def settimeout(self, timeout):
        self.socket.settimeout(timeout)

    def bind(self, host, port):
        self.socket.bind((host, port))

    def listen(self, backlog=5):
        self._listen = True
        self.socket.listen(backlog)

    def connect(self, host, port):
        self._remote_address = F"{host}:{port}"
        self.socket.connect((host, port))

    def send(self, data):
        total_sent = 0
        while total_sent < len(data):
            sent = self.socket.send(data[total_sent:])
            if sent == 0:
                raise RuntimeError("Socket connection broken")
            total_sent += sent

    def recv(self, buffer_len):
        data = self.socket.recv(buffer_len)
        if not data:
            raise RuntimeError("Socket connection broken")
        self.last_received_time = time.time()
        self.packet_counter += 1
        return data

    def safeRecv(self, length):
        data = b''
        while len(data) < length:
            chunk = self.socket.recv(length - len(data))
            if not chunk:
                raise RuntimeError("Socket connection broken")
            data += chunk
        self.last_received_time = time.time()
        self.packet_counter += 1
        return data

    def accept(self, sever_socket):
        self.socket, self.remote_address = sever_socket.socket.accept()
        self._remote_address = F"{self.remote_address[0]}:{self.remote_address[1]}"

    def close(self):
        self.socket.close()

    def is_connected(self):
        return self.socket.fileno() != -1

    def get_remote_address(self):
        return self._remote_address

    def get_last_received_time(self):
        return self.last_received_time

    def get_packet_counter(self):
        return self.packet_counter
    
    
