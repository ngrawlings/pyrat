from utils.EncryptedSocket import EncryptedSocket, EncryptionParams
from utils.Socket import Socket
from typing import List
from socket import socket
import threading
from queue import Queue
import binascii

class Mode:
    CLIENT = "client"
    SERVER = "server"
    INVERTED_SERVER = "inverted"

class Tunnel:
    def __init__(self, encryption_keys: List[EncryptionParams], enc_mode: str, socket_mode: str):
        self.encrypted_socket = EncryptedSocket(encryption_keys)
        self.socket = Socket()
        self.enc_mode = enc_mode
        self.socket_mode = socket_mode
        self._run = True
        self.enc_socket_queue = Queue()
        self.socket_queue = Queue()
    
    def connect(self, key_index, local_address, local_port, enc_address, enc_port):
        self.key_index = key_index
        self.local_address = local_address
        self.local_port = local_port
        self.enc_address = enc_address
        self.enc_port = enc_port

        self.connection_thread = threading.Thread(target=self.connection_thread)
        self.connection_thread.start()

    def close(self):
        print("Closing Tunnel")
        self._run = False
        self.encrypted_socket.close()
        self.socket.close()
        if self.server_socket is not None:
            self.server_socket.close()

    def status(self):
        encrypted_socket_state = 1 if self.encrypted_socket.is_connected() else 0
        socket_state = 1 if self.socket.fileno() != -1 else 0
        return encrypted_socket_state, socket_state
    
    def connection_thread(self):
        print("Starting tunnel connection thread", self.enc_mode, self.socket_mode)
        if self.enc_mode == 1:
            print("Connecting encrypted socket", self.enc_address, self.enc_port)
            self.encrypted_socket.connect(self.enc_address, self.enc_port, self.key_index)
        elif self.enc_mode == 2:
            print("Connecting encrypted socket as server", self.enc_address, self.enc_port)
            self.encrypted_socket.connectAsServer(self.enc_address, self.enc_port)
        else:
            print("Binding encrypted socket", self.enc_address, self.enc_port)
            self.server_socket = Socket()
            self.server_socket.bind(self.enc_address, self.enc_port)
            self.server_socket.listen()
            self.encrypted_socket.accept(self.server_socket)

        if self.socket_mode == 1:
            print("Connecting socket", self.local_address, self.local_port)
            self.socket.connect(self.local_address, self.local_port)
            print("Connected socket", self.local_address, self.local_port)
        else:
            print("Binding socket", self.local_address, self.local_port)
            self.server_socket = Socket()
            self.server_socket.bind(self.local_address, self.local_port)
            self.server_socket.listen()
            self.socket.accept(self.server_socket)
            print("Accepted socket connection from", self.socket.get_remote_address())
        
        # Launch threads for monitoring encrypted socket and socket
        self.encrypted_thread = threading.Thread(target=self.monitor_encrypted_socket)
        self.socket_thread = threading.Thread(target=self.monitor_socket)
        
        self.encrypted_thread.start()
        self.socket_thread.start()

    def monitor_encrypted_socket(self):
        print("Monitoring encrypted socket")
        while self._run:
            if self.socket.is_connected():
                while not self.socket_queue.empty():
                    self.socket.send(self.socket_queue.get())

            data = self.encrypted_socket.receive()
            if self.socket.is_connected():
                self.socket.send(data)
            else:
                print("Queueing packet: ", binascii.hexlify(data).decode())
                self.socket_queue.queue_packet(data)
    
    def monitor_socket(self):
        print("Monitoring socket")
        while self._run:
            if self.encrypted_socket.is_connected():
                while not self.enc_socket_queue.empty():
                    self.encrypted_socket.send(self.enc_socket_queue.get())

            data = self.socket.recv(1024)
            if self.encrypted_socket.is_connected():
                self.encrypted_socket.send(data)
            else:
                print("Queueing packet: ", binascii.hexlify(data).decode())
                self.enc_socket_queue.queue_packet(data)
