import socket
import ssl
import datetime
import pprint
import json

def get_connection_info(secure_client):
    """Get detailed connection information"""
    cipher = secure_client.cipher()
    return {
        'Cipher Suite': cipher[0],
        'TLS Version': cipher[1],
        'Secret Bits': cipher[2],
        'Server Hostname': secure_client.server_hostname,
        'Server Certificate': secure_client.getpeercert()
    }

def send_receive_message(secure_client):
    """Handle sending and receiving a single message"""
    # Get user input
    user_message = input("\nEnter your message (or 'quit' to exit): ")
    if user_message.lower() == 'quit':
        return False
        
    # Prepare message with metadata
    message = {
        "message": user_message,
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    print(f"\nSending message: {message}")
    secure_client.send(str(message).encode())
    
    # Receive and display response
    response = secure_client.recv(4096).decode()
    print("\n=== Server Response ===")
    try:
        response_dict = eval(response)  # Safe in this context as we trust the server
        print("\nMessage:", response_dict['message'])
        print("\nServer Connection Info:")
        pprint.pprint(response_dict['connection_info'])
        print("\nServer Time:", response_dict['time'])
    except:
        print("Raw response:", response)
    
    return True

def start_client():
    print("=== TLS 1.3 Client ===")
    print(f"Started at: {datetime.datetime.now()}")
    
    # Create SSL context using TLS 1.3
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    
    # Set cipher suites (only secure ones)
    context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
    
    # Load trusted certificates
    context.load_verify_locations('server.crt')
    print("\nLoaded server certificate")
    
    try:
        # Create socket and wrap with SSL
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            with context.wrap_socket(client, server_hostname='localhost') as secure_client:
                # Connect to server
                print("\nConnecting to server...")
                secure_client.connect(('localhost', 8443))
                print("Connected successfully!")
                
                # Get and display connection information
                print("\n=== Connection Details ===")
                conn_info = get_connection_info(secure_client)
                print("\nSecurity Information:")
                pprint.pprint(conn_info)
                
                # Enter message loop
                print("\n=== Start Messaging ===")
                print("You can now send messages to the server.")
                print("Type 'quit' to exit the program.")
                
                while True:
                    if not send_receive_message(secure_client):
                        break
                
    except Exception as e:
        print(f"\nError: {e}")
    
    print("\n=== Connection Closed ===")

if __name__ == '__main__':
    start_client() 