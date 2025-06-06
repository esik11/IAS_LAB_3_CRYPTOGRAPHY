import socket
import ssl
import threading
import datetime
import pprint

def get_cipher_info(conn):
    """Get detailed cipher and TLS information"""
    cipher = conn.cipher()
    return {
        'Cipher Suite': cipher[0],
        'TLS Version': cipher[1],
        'Secret Bits': cipher[2]
    }

def handle_client(conn, addr):
    try:
        # Get connection information
        cipher_info = get_cipher_info(conn)
        print("\n=== New Client Connection ===")
        print(f"Time: {datetime.datetime.now()}")
        print(f"Client Address: {addr}")
        print("\nSecurity Information:")
        pprint.pprint(cipher_info)
        print("\nPeer Certificate:")
        try:
            cert = conn.getpeercert()
            if cert:
                pprint.pprint(cert)
            else:
                print("No client certificate provided")
        except ssl.SSLError:
            print("No client certificate provided")
        
        # Handle messages from client
        while True:
            try:
                # Receive data from client
                data = conn.recv(1024).decode()
                if not data:
                    break
                
                # Parse received message
                try:
                    received_dict = eval(data)  # Safe in this context as we trust the client
                    print(f"\nReceived Message from {addr}:")
                    pprint.pprint(received_dict)
                except:
                    print(f"\nReceived raw message from {addr}: {data}")
                
                # Send response with connection info
                response = {
                    "message": f"Server received: {received_dict.get('message', data)}",
                    "connection_info": cipher_info,
                    "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                conn.send(str(response).encode())
                print(f"Response sent to {addr}")
                
            except ConnectionError:
                break
            
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        print(f"\n=== Connection Closed: {addr} ===\n")

def start_server():
    # Create SSL context using TLS 1.3
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    
    # Set cipher suites (only secure ones)
    context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
    
    # Load certificate and private key
    context.load_cert_chain('server.crt', 'server.key')
    
    # Create socket and bind
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(('localhost', 8443))
        server.listen(5)
        print("=== TLS 1.3 Server ===")
        print(f"Started at: {datetime.datetime.now()}")
        print("Listening on: localhost:8443")
        print("Security: TLS 1.3 Only")
        print("Waiting for connections...\n")
        
        # Wrap socket with SSL context
        with context.wrap_socket(server, server_side=True) as secure_server:
            while True:
                conn, addr = secure_server.accept()
                # Handle each client in a separate thread
                client_thread = threading.Thread(target=handle_client, args=(conn, addr))
                client_thread.start()

if __name__ == '__main__':
    start_server() 