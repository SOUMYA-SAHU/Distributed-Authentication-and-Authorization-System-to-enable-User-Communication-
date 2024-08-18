
import socket
import time
from peer_functions import login, verify_initiator, update_logout, key_generation
from peer_functions import retrieve_listener_details_auth_key, retrieve_listener_details_username

server_list = {'US':('192.168.165.86',12341), 'IN':('192.168.165.152',12340,12342)}
# server_list = {'US':('127.0.0.1',12341), 'IN':('127.0.0.1',12340,12342)}

def main():
    country = input("Enter country (US, IN-default): ").upper()
    country = country if country in server_list.keys() else 'IN'
    SERVER_HOST = (server_list[country])[0]  # The server's SERVER_HOST name or IP address '10.86.4.96'
    SERVER_PORT = (server_list[country])[1]  # The port used by the US server
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_HOST, SERVER_PORT))
    # auth_keys=["100","200","300","400","500"]
    f=0
    # authentication first - login - auth key generation
    key=key_generation(s)
    auth_key=login(s=s, key=key)

    while True:
        if f==0:
            choice=(input("a. Listen for connections \nb. Initiate a connection \nc. Exit \nEnter choice: ")).lower()
        if(choice=='a' or f==1):  # server
            # Configuration
            f=0
            HOST, PORT = retrieve_listener_details_auth_key(s=s, key=key, auth_key=auth_key)
            if PORT==0:
                print("The person you are trying to connect is either offline or not registered!")
                continue
            # Create a socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind((HOST, PORT))
            server_socket.listen()

            print("Server is listening on {}:{}".format(HOST, PORT))
            
            client_socket, addr = server_socket.accept()
            print("Connection from", addr)
            
            # Verification of the connection received
            
            # receiving client's auth key
            client_auth_key = client_socket.recv(1024).decode()
            if not verify_initiator(s=s, key=key, client_auth_key=client_auth_key):
                client_socket.sendall(b"You are not an authenticated user")
                client_socket.close()
                print("The user who tried to connect is not authenticated")
                continue
            client_socket.sendall(b"You are verified")
            while True:
                
                client_msg = client_socket.recv(1024).decode()
                print("Friend: " ,client_msg)
                if client_msg.lower()=="stop":
                    break
                
                server_msg = input("You: ").encode()
                client_socket.sendall(server_msg)
                if server_msg.decode().lower()=="stop":
                    break
                
            client_socket.close()
            server_socket.close()
                
        elif (choice=='b'):   # client
            # Configuration
            username=input("Enter username of user you want to talk to: ")
            
            HOST, PORT = retrieve_listener_details_username(s=s, key=key, username=username)
            if PORT==0:
                print("The person you want to talk to is either not online or not registered")
                continue
            # Create a socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            while True:
                try:
                    client_socket.connect((HOST, PORT))
                    # print("Sending my authentication key")
                    break
                except:
                        print(f"Connection to {HOST}:{PORT} refused. \na. Retry \nb. Start Listening \nc. Exit")
                        ch=(input("Enter choice: ")).lower()
                        
                        if ch=='a':            
                            time.sleep(5)
                            continue
                        elif ch=='b':
                            f=1
                            break
                        elif ch=='c':
                            print("Exiting...")
                            exit(0)
                        else:
                            print("Wrong Choice")
                            continue
            if f==1:
                continue
            my_auth_key = auth_key.encode()
            client_socket.sendall(my_auth_key)
            
            server_msg = client_socket.recv(1024).decode()
            
            if server_msg=="You are not an authenticated user":
                print("Not authenticated")
                client_socket.close()
                continue
            else:
                print("You can chat now Enter 'Stop' to stop")
                while True:
                    
                    client_msg = input("You: ").encode()
                    client_socket.sendall(client_msg)
                    if client_msg.decode().lower()=="stop":
                        break
                    
                    server_msg = client_socket.recv(1024).decode()
                    print("Friend: " ,server_msg)
                    if server_msg.lower()=="stop":
                        break

            client_socket.close()
            
        elif choice=='c':
            update_logout(s=s, key=key, auth_key=auth_key)
            print("Exiting...")
            s.close()
            exit(0)

        else:
            print("Wrong Choice")
            continue

if __name__ == "__main__":
    main()
    