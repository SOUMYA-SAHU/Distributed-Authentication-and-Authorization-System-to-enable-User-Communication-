import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from diffiehellman import DiffieHellman

def aes_encrypt(data,key)->bytes:
    # Encrypt the message
    cipher = AES.new(key, AES.MODE_GCM)
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
        
def key_generation(s):
    # Key generation and encryption setup:
    key_pair = DiffieHellman(group=14, key_bits=32) # automatically generate one key pair    
    # get own public key and send to server
    client_public = key_pair.get_public_key() 
    s.sendall(client_public)    
    # generate shared key based on the other side's public key
    server_public = s.recv(1024)
    client_shared_key = key_pair.generate_shared_key(server_public)      
    # Use a KDF to derive an AES key from the shared key
    password = client_shared_key
    salt = b'salt'  # You should use a different salt
    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    return key

def login(s, key): 
    # nonce = cipher.nonce
    while True:
        encrypted_data = s.recv(256)
        data = aes_decrypt(encrypted_data=encrypted_data,key=key)
        server_msg = str(data, 'UTF-8')
        print(f"{server_msg}")
        if server_msg == "Closing Connection":
            s.close()
            exit(0)   
        elif server_msg == "Wrong choice." or server_msg=="Username already exists.":
            continue      
        elif server_msg=="You are connected":
            encrypted_data = s.recv(256)
            auth_key = aes_decrypt(encrypted_data=encrypted_data,key=key)
            auth_key = str(auth_key, 'UTF-8')
            return auth_key
            # s.close()
            # break
        data = input().encode()
        encrypted_data = aes_encrypt(data=data,key=key)
        s.sendall(encrypted_data)
    #key has been received
    # print(auth_key)
    

def retrieve_listener_details_auth_key(s, key, auth_key):
    data = "I am listening".encode()
    encrypted_data = aes_encrypt(data=data,key=key)
    s.sendall(encrypted_data)
    
    # sending my auth_key
    data = auth_key.encode()
    encrypted_data = aes_encrypt(data=data,key=key)
    s.sendall(encrypted_data)
    
    # my ip
    encrypted_data = s.recv(256)
    data = aes_decrypt(encrypted_data=encrypted_data,key=key)
    my_ip = str(data, 'UTF-8')
    
    # my port
    encrypted_data = s.recv(256)
    data = aes_decrypt(encrypted_data=encrypted_data,key=key)
    try:
        my_port = int(str(data, 'UTF-8'))
    except:
        my_port = 0
    
    return (my_ip, my_port)
    
def retrieve_listener_details_username(s, key, username):
    data = "I am initiating".encode()
    encrypted_data = aes_encrypt(data=data,key=key)
    s.sendall(encrypted_data)
    
    # sending listener's username
    data = username.encode()
    encrypted_data = aes_encrypt(data=data,key=key)
    s.sendall(encrypted_data)
    
    # my ip
    encrypted_data = s.recv(256)
    data = aes_decrypt(encrypted_data=encrypted_data,key=key)
    listener_ip = str(data, 'UTF-8')
    print("RECEIVED IP")
    
    # my port
    encrypted_data = s.recv(256)
    data = aes_decrypt(encrypted_data=encrypted_data,key=key)
    try:
        listener_port = int(str(data, 'UTF-8'))
    except:
        listener_port = 0
    print("RECEIVED PORT")
    
    return (listener_ip, listener_port)
    
def verify_initiator(s, key, client_auth_key):
    data = "Verify initiator".encode()
    encrypted_data = aes_encrypt(data=data,key=key)
    s.sendall(encrypted_data)
    
    # sending initiator's auth_key
    data = client_auth_key.encode()
    encrypted_data = aes_encrypt(data=data,key=key)
    s.sendall(encrypted_data)
    
    # 1 or 0
    encrypted_data = s.recv(256)
    data = aes_decrypt(encrypted_data=encrypted_data,key=key)
    check = int(str(data, 'UTF-8'))
    
    return True if check==1 else False

def update_logout(s, key, auth_key):
    data = "I am logging out".encode()
    encrypted_data = aes_encrypt(data=data,key=key)
    s.sendall(encrypted_data)
    
    # sending my auth_key
    data = auth_key.encode()
    encrypted_data = aes_encrypt(data=data,key=key)
    s.sendall(encrypted_data)
    
    