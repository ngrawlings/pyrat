import socket
import select
import traceback

# Create a TCP/IP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind the socket to a specific address and port
host = '0.0.0.0'
port = 44220 
server_socket.bind((host, port))

# Listen for incoming connections
server_socket.listen(5)

# List to keep track of connected sockets
sockets_list = [server_socket]

print(f"Server listening on {host}:{port}")

# List to cache received packets
packet_cache = []

# Counter to keep track of connected clients
connected_clients = 0

def broadcast_message(sender_socket, message):
    # Iterate over all connected sockets (except the server socket and the sender socket)
    for socket in sockets_list:
        if socket != server_socket and socket != sender_socket:
            try:
                # Send the message to the socket
                socket.send(message)
            except:
                # If there is an error, remove the socket from the list
                socket.close()
                sockets_list.remove(socket)

while True:
    # Use select to monitor sockets for incoming data
    read_sockets, _, _ = select.select(sockets_list, [], [])

    for socket in read_sockets:
        if socket == server_socket:
            if connected_clients < 2:
                # Accept new connection
                client_socket, client_address = server_socket.accept()
                sockets_list.append(client_socket)
                connected_clients += 1
                print(f"New connection from {client_address[0]}:{client_address[1]}")
                
                # Send cached packets to the newly connected client
                for packet in packet_cache:
                    if len(packet) > 0:
                        client_socket.send(packet)

                packet_cache.clear()
                
                # Clear the packet cache
                packet_cache = []
            else:
                # Reject the connection or handle it in some other way
                client_socket, client_address = server_socket.accept()
                client_socket.send("Connection limit reached. Please try again later.".encode())
                client_socket.close()

        else:
            # Receive data from a connected socket
            try:
                data = socket.recv(1024)
                if data:
                    print(f"Received data: {len(data)} bytes from {socket.getpeername()[0]}:{socket.getpeername()[1]}")
                    # Cache the received packet
                    if len(data) > 0:
                        packet_cache.append(data)
                    # Broadcast the received data to all other connected sockets
                    broadcast_message(socket, data)
                else:
                    # If there is no data, remove the socket from the list
                    socket.close()
                    sockets_list.remove(socket)
                    connected_clients -= 1
            except Exception:
                traceback.print_exc()
                # If there is an error, remove the socket from the list
                socket.close()
                sockets_list.remove(socket)
                
                packet_cache.clear()
                for socket in sockets_list:
                    if socket != server_socket:
                        socket.close()
                        sockets_list.remove(socket)

                connected_clients = 0
