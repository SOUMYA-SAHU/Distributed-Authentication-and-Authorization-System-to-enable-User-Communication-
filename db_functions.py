# include exception handling
import sqlite3
from hashing_db import encryptToStore, decryptFromStore, getKey


def create_table(cursor,conn):
  query = """CREATE TABLE IF NOT EXISTS Login
  (
    Username VARCHAR,
    Pwd VARCHAR NOT NULL,
    IP VARCHAR NOT NULL,
    Auth_key VARCHAR,
    PORT VARCHAR,
    
    PRIMARY KEY (Username),
    UNIQUE (IP, PORT),
    UNIQUE (Auth_key),
    CHECK (PORT LIKE '102__')
  );"""
  cursor.execute(query)
  conn.commit()
  
def insert_table(cursor,conn,username,pwd,ip):
  hash_key=getKey()
  username=encryptToStore(key=hash_key, plaintext=username)
  pwd=encryptToStore(key=hash_key, plaintext=pwd)
  ip=encryptToStore(key=hash_key, plaintext=ip)
  
  query = f"INSERT INTO Login (Username, Pwd, IP) VALUES ('{username}', '{pwd}', '{ip}');"
  cursor.execute(query)
  conn.commit()
  
def display_table(cursor):
  hash_key=getKey()
  query = "SELECT * FROM Login"
  cursor.execute(query)
  for row in cursor.fetchall():
      for val in row:
          val=decryptFromStore(key=hash_key, enctext=val)
          print(val)
      print()
      
def drop_table(cursor,conn):
  query = "DROP TABLE IF EXISTS Login"
  cursor.execute(query)
  conn.commit()
  
def retrieve_listener_details_username(cursor, username):
  username=encryptToStore(key=getKey(), plaintext=username)
  query = f"""SELECT IP, PORT 
                FROM Login
                  WHERE Username='{username}'"""
  cursor.execute(query)
  for row in cursor.fetchall():
    ip=decryptFromStore(key=getKey(), enctext=row[0])
    port=row[1]
    try:
      return (ip,int(port))   # ip, port of listener
    except:
      return(ip,0)
  return('0',0)

def retrieve_listener_details_auth_key(cursor, auth_key):
  auth_key=encryptToStore(key=getKey(), plaintext=auth_key)
  query = f"""SELECT IP, PORT 
                FROM Login
                  WHERE Auth_key='{auth_key}'"""
  cursor.execute(query)
  for row in cursor.fetchall():
    ip=decryptFromStore(key=getKey(), enctext=row[0])
    port= row[1]
    return (ip,int(port))   # ip, port of listener
  
def verify_initiator(cursor, auth_key):
  auth_key=encryptToStore(key=getKey(), plaintext=auth_key)
  query = f"""SELECT Username 
                FROM Login
                  WHERE Auth_key='{auth_key}'"""
  cursor.execute(query)
  for _ in cursor.fetchall():
    return True   # initiator verified
  return False   # not there

def verify_username(cursor, username):
  username=encryptToStore(key=getKey(), plaintext=username)
  query = f"""SELECT Username 
              FROM Login
                WHERE Username='{username}'"""
  cursor.execute(query)
  for _ in cursor.fetchall():
    return True  
  return False  
  
def verify_password(cursor, username, pwd):
  username=encryptToStore(key=getKey(), plaintext=username)
  pwd=encryptToStore(key=getKey(), plaintext=pwd)
  query = f"""SELECT Username 
              FROM Login
              WHERE Username='{username}' AND Pwd='{pwd}' """
  cursor.execute(query)
  for _ in cursor.fetchall():
    return True 
  return False  

def update_login(cursor,conn,username,auth_key,port:int,ip:str):
  port=str(port)
  # port=encryptToStore(key=getKey(), plaintext=port)
  auth_key=encryptToStore(key=getKey(), plaintext=auth_key)
  username=encryptToStore(key=getKey(), plaintext=username)
  ip=encryptToStore(key=getKey(), plaintext=ip)

  
  query = f"""
  UPDATE Login
  SET Auth_key = '{auth_key}', PORT = {port}, IP = '{ip}'
  WHERE Username = '{username}';
  """
  cursor.execute(query)
  conn.commit()
  
def update_logout(cursor,conn,auth_key):
  auth_key=encryptToStore(key=getKey(), plaintext=auth_key)
  query = f"""
  UPDATE Login
  SET Auth_key = NULL, PORT = NULL
  WHERE Auth_key = '{auth_key}';
  """
  cursor.execute(query)
  conn.commit()

#   # write this in the server: 
# #define conection and cursor
# conn = sqlite3.connect("Servdata.sqlite")
# cursor = conn.cursor()
# # drop_table(cursor,conn)
# create_table(cursor,conn)
# while True:
#   ch=int(input("1. insert \n2. login \n3.logout \n4.retrieve listener \n5.verify initiator \n6. display \n7. exit \nEnter: "))
#   if(ch==1):
#     username=input("Enter username: ")
#     pwd=input("Enter pwd: ")
#     ip=input("Enter ip: ")
#     insert_table(username=username, cursor=cursor, pwd=pwd, ip=ip)
#     # conn.commit()
#   elif(ch==2):
#     username=input("Enter username: ")
#     auth_key=input("Enter auth_key: ")
#     p=int(input("Enter port: "))
#     update_login(cursor,conn=cursor, username=username, auth_key=auth_key, port=p)
#     # conn.commit()
#   elif(ch==3):
#     username=input("Enter username: ")
#     update_logout(cursor,conn=cursor, username=username)
#     # conn.commit()
#   elif(ch==4):
#     ip,port=retrieve_listener_details(cursor,conn=cursor)
#     print(f"ip: {ip}      port: {port}")
#   elif(ch==5):
#     auth_key=input("Enter auth_key: ")
#     flag = verify_initiator(cursor,conn=cursor, auth_key=auth_key)
#     if flag:
#       print("Verified")
#     else:
#       print("Not registered")
#   elif(ch==6):
#     display_table(cursor,conn)
#   else:
#     break
# # Commit the changes and close the connection
# conn.commit()
# conn.close()
