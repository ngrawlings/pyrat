import socket

def test_tcp_port(host, port):
    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set a timeout for the connection
        sock.settimeout(5)
        
        # Connect to the host and port
        sock.connect((host, port))
        
        # Close the connection
        sock.close()
        
        # Print success
        print("Success")
        
    except socket.error:
        # Print failed
        print("Failed")

# Usage example
test_tcp_port("localhost", 8080)
