import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from diffiehellman import DiffieHellman
import uuid
import threading
import sqlite3
from db_functions import create_table, insert_table, update_login, verify_password, verify_username, verify_initiator
from db_functions import retrieve_listener_details_auth_key, retrieve_listener_details_username, update_logout
from peer_functions import key_generation

# server_list = {'US':('192.168.98.86',12341), 'IN':('192.168.98.152',12340,12342)}
server_list = {'US':('192.168.165.86',12341), 'IN':('192.168.165.86',12340,12342)}


# userdict={ "user1":"one", "user2":"two" , "user3":"three" }
# HOST='10.84.4.96'
HOST=(server_list['US'])[0]
PORT = (server_list['US'])[1]
SERVPORT = (server_list['IN'])[2]
assign_port=10250
conn_db = 1

def aes_encrypt(data,key)->bytes:
    cipher = AES.new(key, AES.MODE_GCM)
    # Encrypt the message
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # Send the encrypted message
    encrypted_data = cipher.nonce + ciphertext + tag
    return encrypted_data

def aes_decrypt(encrypted_data,key)->bytes:
    nonce = encrypted_data[:16]  # Assuming a 128-bit nonce
    ciphertext = encrypted_data[16:-16]
    tag = encrypted_data[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # Decrypt the message
    decrypted_data = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)  # Verifies the authentication tag
        # print("Decryption successful")
        return decrypted_data    
    except ValueError:
        print("Authentication failed. The data may be tampered.")
        exit(0)
        
# Function to handle a single client connection
def handle_client(cursor,conn,addr,serv_in_sock):
    global assign_port
    with conn:
        print(f"Connected by {addr}")
        i=0
        # Key generation and encryption setup:
        key_pair = DiffieHellman(group=14, key_bits=32) # automatically generate one key pair              
        # generate shared key based on the other side's public key
        client_public = conn.recv(1024)
        server_shared_key = key_pair.generate_shared_key(client_public) 
        # get own public key and send to server
        server_public = key_pair.get_public_key() 
        conn.sendall(server_public) 
        # Use a KDF to derive an AES key from the shared key
        password = server_shared_key
        salt = b'salt'  # You should use a different salt
        key = PBKDF2(password, salt, dkLen=32, count=1000000)       
        
        while True:
            conn.sendall(aes_encrypt(data=b"Enter your username: ",key=key))
            data = aes_decrypt(encrypted_data=conn.recv(256), key=key)
            username = str(data, 'UTF-8')
            if verify_username(cursor=cursor, username=username):
                while(True):
                    conn.sendall(aes_encrypt(data=b"Enter your password",key=key))
                    data = aes_decrypt(encrypted_data=conn.recv(256), key=key)
                    pwd = str(data, 'UTF-8')
                    # print("Recieved Passwd",key=key))
                    if verify_password(cursor=cursor, username=username, pwd=pwd):
                        # print(f"sending Passwd: {pwd}",key=key))
                        conn.sendall(aes_encrypt(data=b"You are connected",key=key))
                        # print("Passwd sent",key=key))
                        unique_id=uuid.uuid4()
                
                        auth_key=(str(unique_id)+"US").encode()
                        # add authentication key to the database
                        assign_port+=1
                        update_login(conn=conn_db,cursor=cursor, username=username, auth_key=auth_key.decode(), port=assign_port, ip=addr[0])
                        conn.sendall(aes_encrypt(data=auth_key,key=key))
                        
                        while True:
                            message = aes_decrypt(encrypted_data=conn.recv(256), key=key)
                            message = str(message, 'UTF-8')
                            if message=="I am listening":
                                # receive auth_key of listener
                                auth_key = aes_decrypt(encrypted_data=conn.recv(256), key=key)
                                auth_key = str(auth_key, 'UTF-8')

                                if auth_key[-2:] == 'IN':
                                    # REQUEST FOR IP AND PORT USING CONNECTION TO THE US_SERVER
                                    msg = "Return_Details_Auth_Key"
                                    # print("Connection from india")
                                    serv_in_sock.sendall(msg.encode())
                                    serv_in_sock.sendall(auth_key.encode())
                                    ip,port = str(serv_in_sock.recv(256), 'UTF-8').split(',')
                                    
                                else:
                                    # print("Connection NOT from india")
                                    try:
                                        ip,port=retrieve_listener_details_auth_key(cursor=cursor, auth_key=auth_key)
                                        port=str(port)
                                    except:
                                        ip, port = "NO", "NO"
                               
                                conn.sendall(aes_encrypt(data=ip.encode(),key=key))
                                conn.sendall(aes_encrypt(data=port.encode(),key=key))
                            
                            elif message=="I am initiating":
                                # receive username of listener
                                username = aes_decrypt(encrypted_data=conn.recv(256), key=key)
                                username = str(username, 'UTF-8')
                                # print(username)
                                # print(len(username[-2:]))

                                # CHANGING HEREEEEE
                                if username[-2:] == 'IN' or username[-2:] == 'in':
                                    # REQUEST FOR IP AND PORT USING CONNECTION TO THE US_SERVER
                                    msg = "Return_Details"
                                    # print("Connection from india")
                                   
                                    serv_in_sock.sendall(msg.encode())
                                    # print("Sent message")
                                    serv_in_sock.sendall(username.encode())
                                    # print("Sent username")

                                    ip,port = str(serv_in_sock.recv(256), 'UTF-8').split(',')
                                    # print("Received port and ip", port, ip)
                                else:
                                    # print("Connection NOT from india")
                                    try:
                                        ip,port=retrieve_listener_details_username(cursor=cursor, username=username)
                                        port=str(port)
                                    except:
                                        ip,port = "NO", "NO"
                                # print("SENDING IP BACK TO CONN")
                                conn.sendall(aes_encrypt(data=ip.encode(),key=key))
                                # print("SENDING PORT BACK TO CONN", port)
                                conn.sendall(aes_encrypt(data=port.encode(),key=key))
                                
                            elif message=="Verify initiator":
                                # receive auth_key of initiator
                                # CHECK HOW TO KNOW WHERE INITIATOR IS FROM!!!!
                                auth_key = aes_decrypt(encrypted_data=conn.recv(256), key=key)
                                auth_key = str(auth_key, 'UTF-8')
                                if auth_key[-2:] == 'IN':
                                    msg = "Return_Verification"
                                    # print("Connection from india")
                                   
                                    serv_in_sock.sendall(msg.encode())
                                    serv_in_sock.sendall(auth_key.encode())
                                    check = serv_in_sock.recv(256)
                                    check = str(check, 'UTF-8')
                                    check = True if check=='True' else False
                                else:
                                    # print("Connection NOT from india")

                                    check=verify_initiator(cursor=cursor, auth_key=auth_key)
                                checkb="1" if check else "0"
                                conn.sendall(aes_encrypt(data=checkb.encode(),key=key))
                             
                            elif message=="I am logging out":
                                # receive auth_key of initiator
                                auth_key = aes_decrypt(encrypted_data=conn.recv(256), key=key)
                                auth_key = str(auth_key, 'UTF-8')
                                if auth_key[-2:] == 'US':
                                    update_logout(cursor=cursor, conn=conn_db, auth_key=auth_key)
                                conn.close() 
                                return
                        
                    else:
                        conn.sendall(aes_encrypt(data=b"Wrong Password Enter password again?(Y/N): ",key=key))
                        choice = aes_decrypt(encrypted_data=conn.recv(256), key=key)
                        choice = str(choice, 'UTF-8')
                        if(choice=="N" or choice=="n"):
                            conn.sendall(aes_encrypt(data=b"Closing Connection",key=key))
                            conn.close()
                            exit(0)
                        elif(choice=="Y" or choice=="y"):
                            continue 
                        else:
                            conn.sendall(aes_encrypt(data=b"Wrong choice.",key=key)) 
                            continue                                   
            else:
                conn.sendall(aes_encrypt(data=b"A) Register \nB) Re-enter username \nC) Exit \nEnter choice: ",key=key))
                choice = aes_decrypt(encrypted_data=conn.recv(256), key=key)
                choice = str(choice, 'UTF-8')
                if(choice=="C" or choice=="c"):
                    conn.sendall(aes_encrypt(data=b"Closing Connection",key=key))
                    conn.close()
                    exit(0)
                elif(choice=="B" or choice=="b"):
                    continue
                elif(choice=="A" or choice=="a"):
                    while(True):
                        conn.sendall(aes_encrypt(data=b"Enter name: ",key=key))
                        reg_username = aes_decrypt(encrypted_data=conn.recv(256), key=key)
                        reg_username = str(reg_username, 'UTF-8') + '.US'
                        if(verify_username(cursor=cursor, username=reg_username)):
                            conn.sendall(aes_encrypt(data=b"Username already exists.",key=key))
                            continue
                        sendinguserpwd = "Your username is " + reg_username + "\n  Enter new password: "
                        conn.sendall(aes_encrypt(data=sendinguserpwd.encode(),key=key))
                        reg_pwd = aes_decrypt(encrypted_data=conn.recv(256), key=key)
                        reg_pwd = str(reg_pwd, 'UTF-8')
                        
                        #change finding of ip
                        reg_ip=addr[0]
                        insert_table(cursor=cursor,conn=conn_db, username=reg_username, pwd=reg_pwd, ip=reg_ip)
                        # userdict[reg_username]=reg_pwd
                        # cursor.commit()
                        conn.sendall(aes_encrypt(data=b"Successfully Registered! Login?(Y/N):",key=key))
                        choice = aes_decrypt(encrypted_data=conn.recv(256), key=key)
                        choice = str(choice, 'UTF-8')
                        if(choice=="N" or choice=="n"):
                            conn.sendall(aes_encrypt(data=b"Closing Connection",key=key))
                            conn.close()
                            exit(0)
                        elif(choice=="Y" or choice=="y"):
                            break
                        else:
                            conn.sendall(aes_encrypt(data=b"Wrong choice.",key=key)) 
                            break  
                else:
                    conn.sendall(aes_encrypt(data=b"Wrong choice.",key=key))
                    continue

def handle_server(cursor, conn):
    while True:
        # American is initiator: 
        # US server requests for my ip and port - using username or auth_key
        # I request us server for verification using auth key

        # Indian is initiator: 
        # I request us server for listener's ip and port - using username or auth_key
        # US server requests me for verification using auth key

        # HANDLE ENCRYPT AND DECRYPT KEYS

        msg = conn.recv(256)
        msg = str(msg, 'UTF-8')
        if msg=="Return_Details":
            username = conn.recv(256)
            username = str(username, 'UTF-8')
            try:
                ip,port=retrieve_listener_details_username(cursor=cursor, username=username)
                port=str(port)
            except:
                ip, port = "NO", "NO"
            send_addr = ip+','+port
            conn.sendall(send_addr.encode())
            conn.sendall(send_addr.encode())

        if msg=="Return_Details_Auth_Key":
            auth_key = conn.recv(256)
            auth_key = str(username, 'UTF-8')
            try:
                ip,port=retrieve_listener_details_auth_key(cursor=cursor, auth_key=auth_key)
                port=str(port)
            except:
                ip, port = "NO", "NO"
            send_addr = ip+','+port
            conn.sendall(send_addr.encode())
            conn.sendall(send_addr.encode())

        elif msg=="Return_Verification":
            # receive auth_key of initiator
            auth_key = conn.recv(256)
            auth_key = str(auth_key, 'UTF-8')
            # print("Received auth key: ", auth_key)
            check=verify_initiator(cursor=cursor, auth_key=auth_key)
            check = 'True' if True else 'False'
            conn.sendall(check.encode())
            conn.sendall(check.encode())


def main():
    global conn_db
    conn_db = sqlite3.connect("Servdata_us.db",check_same_thread=False)
    cursor = conn_db.cursor()
    create_table(cursor=cursor,conn=conn_db)
    # DOES NOT WORK FOR WINDOWS!!!!
    # hostname = socket.gethostname()
    # global HOST 
    # HOST = socket.gethostbyname(hostname)

    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.bind((HOST,PORT))
        s.listen(8)
        print(f"Server listening on {HOST}:{PORT}")

        # ASSUME FIRST CONNECTION ALWAYS FROM SERVER and INDIAN SERVER IS THE LISTENER AMONG US AND IN
        # SOCKET TO CONNECT TO INDIAN SERVER
        s1=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s1.connect((server_list['IN'][0],SERVPORT))
        serv_handler = threading.Thread(target=handle_server, args=(cursor,s1))
        serv_handler.start()

        while True:
            # Accept a client connection
            conn,addr = s.accept()
            print(f"Accepted connection from {addr[0]}:{addr[1]}")
            # Create a new thread to handle the client
            client_handler = threading.Thread(target=handle_client, args=(cursor,conn,addr,s1))
            client_handler.start()
            conn_db.commit()
                             
if __name__ == "__main__":
    main()
                    