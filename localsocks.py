import socket
import select
import threading
import socks

def handle_client(client_socket):
    print(f"New connection from {client_socket.getpeername()}")

    # Create a new connection to the SOCKS server
    socks_socket = socks.socksocket()
    socks_socket.set_proxy(socks.SOCKS5, '127.0.0.1', 9050)
    socks_socket.connect(("n3uehcdyj7b4pfnvjwykziuhqtxxjsd2xvtn7wyp25cjfnzlem7hevyd.onion", 44123))

    # Set up the event loop for the client socket and SOCKS socket
    inputs = [client_socket, socks_socket]
    outputs = []

    while True:
        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for sock in readable:
            if sock is client_socket:
                # Data received from the client socket
                data = sock.recv(4096)
                if data:
                    # Forward the data to the SOCKS socket
                    socks_socket.sendall(data)
                else:
                    # Connection closed by the client
                    print(f"Connection closed by {sock.getpeername()}")
                    inputs.remove(sock)
                    sock.close()
                    socks_socket.close()
                    return
            elif sock is socks_socket:
                # Data received from the SOCKS socket
                data = sock.recv(4096)
                if data:
                    # Forward the data to the client socket
                    client_socket.sendall(data)
                else:
                    # Connection closed by the SOCKS server
                    print("Connection closed by SOCKS server")
                    inputs.remove(sock)
                    sock.close()
                    client_socket.close()
                    return

            for sock in exceptional:
                # Error on a connection
                print(f"Error on connection with {sock.getpeername()}")
                inputs.remove(sock)
                sock.close()
                client_socket.close()
                socks_socket.close()
                return

def main():
    # Set up the listening socket
    listen_address = '0.0.0.0'  # Change this to your desired listening address
    listen_port = 44123  # Change this to your desired listening port

    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind((listen_address, listen_port))
    listen_socket.listen(5)

    print(f"Listening on {listen_address}:{listen_port}")

    while True:
        client_socket, client_address = listen_socket.accept()

        # Launch a new thread for each client connection
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()

if __name__ == '__main__':
     main()