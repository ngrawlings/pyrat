from typing import List
from utils.Socket import Socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket

VERSION = 1

class EncryptionParams:
    def __init__(self, key:str, vector:str):
        self.key = bytes.fromhex(key)
        self.vector =  bytes.fromhex(vector)

class EncryptedSocket(Socket):
    def __init__(self, encryption_keys: List[EncryptionParams]):
        super().__init__()
        self.encryption_keys = encryption_keys
        self.recv_cipher = None
        self.send_cipher = None

    def _init_aes_instances(self):
        encryption_key = self.encryption_keys[self.key_index].key
        encryption_vector = self.encryption_keys[self.key_index].vector
        self.recv_cipher = AES.new(encryption_key, AES.MODE_CBC, encryption_vector)
        self.send_cipher = AES.new(encryption_key, AES.MODE_CBC, encryption_vector)

    def _calculate_checksum(self, data):
        salted_data = self.encryption_keys[self.key_index].vector + data
        checksum = sum(salted_data) % 0xFFFFFFFF
        checksum_bytes = checksum.to_bytes(4, byteorder='big')
        
        return checksum_bytes

    def accept(self, sever_socket):
        super().accept(sever_socket)
        self.socket.send(b'\x01')
        self.version = int.from_bytes(self.safeRecv(4), byteorder='big')
        self.key_index = int.from_bytes(self.safeRecv(4), byteorder='big')

        if self.key_index >= len(self.encryption_keys):
            self.close()
            return

        print("New connection:")
        print(" Version: " + str(self.version))
        print(" Key Index: " + str(self.key_index)) 
        self._init_aes_instances()

    def connectAsServer(self, address, port, timeout=900):
        self.socket.settimeout(timeout)

        try:
            super().connect(address, port)

            self.socket.send(b'\x01')
            self.version = int.from_bytes(self.safeRecv(4), byteorder='big')
            self.key_index = int.from_bytes(self.safeRecv(4), byteorder='big')

            if self.key_index >= len(self.encryption_keys):
                print(f"Invalid key index {self.key_index} ({self.version})")
                self.close()
                return
            
            print("New connection:")
            print(" Version: " + str(self.version))
            print(" Key Index: " + str(self.key_index)) 
            self._init_aes_instances()
        except socket.timeout:
            return False
        
        return True

    def connect(self, address, port, key_index=0):
        self.key_index = key_index
        self._init_aes_instances()
        super().connect(address, port)
        version = self.safeRecv(1)
        print("Server Version: " + str(int.from_bytes(version, byteorder='big')))
        super().send(VERSION.to_bytes(4, byteorder='big'))
        super().send(key_index.to_bytes(4, byteorder='big'))

    def receive(self):
        packet_length_bytes = super().safeRecv(4)
        packet_length = int.from_bytes(packet_length_bytes, byteorder='big')
  
        encrypted_data = b''
        while len(encrypted_data) < packet_length:
            encrypted_data += super().safeRecv(packet_length - len(encrypted_data))
        
        decrypted_data = self.recv_cipher.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_data, AES.block_size)

        checksum = decrypted_data[:4]
        data = decrypted_data[4:]

        calculated_checksum = self._calculate_checksum(data)

        if checksum != calculated_checksum:
            raise Exception("Checksum does not match")

        return data

    def send(self, data):
        checksum = self._calculate_checksum(data)
        data_with_checksum = checksum + data

        encrypted_data = self.send_cipher.encrypt(pad(data_with_checksum, AES.block_size))

        packet_length = len(encrypted_data).to_bytes(4, byteorder='big')

        super().send(packet_length + encrypted_data)
        
    
    
    
