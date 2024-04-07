#!/usr/bin/python3

'''
Python multi user GUI messenger (Server V2)
author = xenon-xenon(Mohammad Amin Nasiri)
email = Khodexenon@gmail.com
'''

import tkinter as tk
from tkinter import *
from tkinter import messagebox
import sqlite3
import socket
import threading
from threading import Thread
from time import sleep
import datetime
import os
import re

connection_status = None # for detecting the server status , 1 is listening , 0 is not listening

# class for managing server and connections
class ServerManager():
    def __init__(self,main_win):
        self.app_version = 'V2.1'
      
        # regex for getting users and their password from creds.txt file and when getting users and passwords from client
        self.cred_regex = '''conntype:(.*),user:(.*),pass:(.*);'''

        # clients socket connections list
        self.clients_list = []
        self.clients_num = 0
        # clients name list
        self.clients_name = []
        self.dbconn = None
        self.dbcursor = None

        self.main_win = main_win
        self.main_win.title('Messenger (Server) V2')
        self.main_win.geometry('500x555')
        self.main_win.resizable(1, 1)
        # setting listening ip element
        self.server_ip_label = Label(self.main_win,font=('Tahoma',15),text='Server IP')
        self.server_ip_label.pack()
        self.server_ip_entry = Entry(self.main_win,font=('Tahoma',15))
        self.server_ip_entry.pack()
        # setting listening port elements
        self.server_port_num_label = Label(self.main_win,font=('Tahoma',15),text='Port')
        self.server_port_num_label.pack()
        self.server_port_num_entry = Entry(self.main_win,font=('Tahoma',15))
        self.server_port_num_entry.pack()

        # setting start listening button
        self.server_start_button = Button(self.main_win,text = '           Start           ', font = ('Tahoma',15),fg = 'Green',command = self.check_input_values)
        self.server_start_button.pack()
        # server stop listening button
        self.server_stop_button = Button(self.main_win,text ='           stop           ', font = ('Tahoma',15),fg = 'Red',command = self.server_stop_to_listening)
        self.server_stop_button.pack()
        self.server_stop_button.config(state ='disabled')
        # client label element
        self.client_list_label = Label(text = 'Clients list',font=('Tahoma',15))
        self.client_list_label.pack()
        # setting the text box for displaying connected users
        self.client_list_text_box = Text(self.main_win)
        self.client_list_text_box.pack()
        self.client_list_text_box.config(height = '13',width = '40',state = 'disabled',font = ('Tahoma',15))

        self.create_log_folder_content() # for creating banner for log files
        self.check_log_dir() # check if log folder and log files exist if they don't exist they will be created
        
        self.setup_db()
        self.get_messages()


    def signup(self,username, password):
        try:
            #SQL INJECTION
            op_res = self.dbcursor.executescript('''INSERT INTO users (username,password) VALUES ('{0}','{1}')'''
                                           .format(username,password))

            self.dbconn.commit()
        except Exception as e:
            print(e)
            return "invalid credentials"
        print(self.dbcursor.execute('SELECT * FROM users').fetchall())
        return "invalid credentials" if op_res == None else "valid credentials"
    
    def login(self,username, password):
        self.dbcursor.execute('SELECT * FROM users WHERE username = ?' , (username,))
        
        try :
            user = self.dbcursor.fetchall()[0]
            if password != user[2]:
                return "invalid credentials"
        except Exception as e:
            print(e)
            
            return "invalid credentials"

        return "valid credentials"
    
    def setup_db(self):

        # Connect to the SQLite database
        self.dbconn = sqlite3.connect('database.db',check_same_thread=False)

        # Create a cursor object to execute SQL commands
        self.dbcursor = self.dbconn.cursor()

        # Create the users table
        self.dbcursor.execute('''CREATE TABLE IF NOT EXISTS users
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username VARCHAR(30) NOT NULL UNIQUE,
                 password VARCHAR(30) NOT NULL)''')
        
        self.dbcursor.execute('''CREATE TABLE IF NOT EXISTS messages 
                       (username VARCHAR(30) NOT NULL,
                        message  VARCHAR(30) NOT NULL)''')
        
        self.dbconn.commit()

        return
    
    def persist_msg(self, username, message):
        op_res = self.dbcursor.execute('''INSERT INTO messages (username,message) VALUES (?,?)'''
                                    ,(username,message))

        self.dbconn.commit()

        return 
    
    # TESTING PURPOSES - CHANGED
    def get_messages(self):
        self.dbcursor.execute('''SELECT * FROM messages''')
        return self.dbcursor.fetchall()
    
    
    def reset_db(self):
        return

    def check_input_values(self):
        '''
        function for check entered values
        this function will be called when start button is clicked
        '''
        try:
            self.server_ip = self.server_ip_entry.get()
            self.server_port = int(self.server_port_num_entry.get())
        except ValueError:
            messagebox.showerror('Error', 'You must enter integer in port field e.g. (54321)')
        else:
            self.server_start_to_listening()

    def server_start_to_listening(self):
        '''function for start listening'''
        global connection_status
        connection_status = 1 # 1 is listening
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.server_ip, self.server_port))
            self.server_socket.listen(10) # setting socket to accept up to 10 connection
            Thread(target=self.connection_accept).start()

        except Exception as e:
            print(e)
            messagebox.showerror('Error', 'Listening failed !')
        else:
            connection_status = 1 # 1 is listening
            self.server_start_button.config(state='disabled')
            self.server_stop_button.config(state='normal')
            messagebox.showinfo('Connection', ('listening on ' + str(self.server_ip) + ':' 
                                               + str(self.server_port)))

    def connection_accept(self):
        '''Function for accepting client connection requests.'''

        while True:
            if connection_status == 0:  # Exit loop if the server is no longer listening.
                break

            try:
                self.client_connection, client_ip = self.server_socket.accept()
            except Exception as e:
                print(f"Error accepting connection: {e}")
                continue  # Continue accepting next connections

            try:
                client_creds = self.client_connection.recv(4096).decode()
                match = re.match(self.cred_regex, client_creds)
                if not match:
                    self.send_error_response(client_ip, "Invalid credential format")
                    continue

                conntype, client_name, client_pass = match.groups()
                check_client = self.signup(client_name, client_pass) if conntype == 'sign' else self.login(client_name, client_pass)

                if check_client == 'valid credentials':
                    self.handle_valid_credentials(client_name, client_ip)
                else:
                    self.send_error_response(client_ip, "Invalid credentials")

            except Exception as e:
                print(f"Error handling connection: {e}")
                self.send_error_response(client_ip, "Error in connection handling")

    def send_error_response(self, client_ip, error_message):
        '''Sends an error response to the client and logs the error.'''
        print(f"{error_message} - IP: {client_ip[0]}")
        self.client_connection.sendall(error_message.encode())
        self.client_connection.close()
        self.save_connections_logs('unknown user', client_ip[0], error_message, 'connection failed')

    def handle_valid_credentials(self, client_name, client_ip):
        '''Handles actions for valid credentials.'''

        # Add client name to the list and update the clients' display
        self.clients_name.append(client_name)
        self.update_clinets_list_display()

        # Log the successful connection
        self.save_connections_logs(client_name, client_ip[0], 'valid credentials', 'connection successful')

        # Send a positive acknowledgment to the client
        self.client_connection.sendall(b'valid credentials')

        # Inform other clients that a new user has joined
        join_msg = client_name.encode() + b" joined"
        for c in self.clients_list:
            if c != self.client_connection:
                c.sendall(join_msg)

        # Log the new client connection
        new_client_msg = f"New client -> Name: {client_name}, IP: {client_ip[0]}"
        print(new_client_msg)

        # Increment the client counter and add the new connection to the clients list
        self.clients_num += 1
        self.clients_list.append(self.client_connection)

        # Send a welcome message to the new client
        welcome_msg = b"Welcome " + client_name.encode()
        self.client_connection.sendall(welcome_msg)

        # Send existing messages to the new client
        msgs_encoded = '\n'.join([f'{x},{y}' for x, y in self.get_messages()]).encode()
        self.client_connection.sendall(msgs_encoded)

        # Start threads for message handling and server signaling
        Thread(target=self.send_recv_clients_msg, args=(self.client_connection, client_name, client_ip[0])).start()
        Thread(target=self.send_server_signal, args=(self.client_connection, client_name, client_ip)).start()
            
    def send_recv_clients_msg(self, client_connection, client_name, client_ip):
        '''function for receive and send client messages'''

        client = client_connection
        client_name = client_name
        client_ip = client_ip
        try:
            while True:
                data = client.recv(4096)
                if data.decode() != 'client signal': # clients signal won't be showed in server shell
                    print(data.decode())
                if not data: break
                if data == b'quit': break
                client_msg = data.decode().strip()
                client_msg = client_msg.encode()
                if client_msg.decode() != 'client signal': # client signal message is for checking connection
                    self.persist_msg(client_name,client_msg.decode())
                    for c in self.clients_list:
                        if c != client:
                            c.sendall(client_msg)
        except:
            print('Connection is closed ! --> client name :' + client_name + ' with IP :' + client_ip)
            if client in self.clients_list:
                self.clients_list.remove(client) # remove client socket from clients sockets list
            if client_name in self.clients_name:
                self.clients_name.remove(client_name)  # remove client name from clients names list
                self.save_connections_logs(client_name, client_ip, "-", 'connection closed')
            self.update_clinets_list_display() # updating clients displaying box
            for c in self.clients_list:
                c.sendall(client_name.encode() + b' left')

    def send_server_signal(self,client_connection,client_name,client_ip):
        '''function for sending signal to clients for checking connection between client and server'''

        while True:
            sleep(5) # sending signal every 5 sec
            try:
                client_connection.sendall(b'server signal')
            except:
                client_connection.close()
                print('Connection is closed ! --> client name :' + client_name)
                if client_connection in self.clients_list :
                    self.clients_list.remove(client_connection) # remove client socket from clients sockets list
                    self.save_connections_logs(client_name, client_ip[0], "-", 'connection closed')
                if client_name in self.clients_name :
                    self.clients_name.remove(client_name) # remove client name from clients names list

                self.clients_num -= 1 # decrease client numbers
                self.update_clinets_list_display() # updating clients displaying box

                for c in self.clients_list:
                    try:
                        c.sendall(client_name.encode() + b' left')
                    except:
                        continue
                break

    def update_clinets_list_display(self):
        '''function for updating clients list in GUI'''

        self.client_list_text_box.config(state='normal')
        self.client_list_text_box.delete(1.0, tk.END)
        for client_name in self.clients_name:
            self.client_list_text_box.insert(tk.END, client_name + '\n')
        self.client_list_text_box.config(state='disabled')

    def check_log_dir(self):
        '''This function checks if logs folder and other log files exist'''

        if os.path.exists('logs') :
            if os.path.exists('logs/connections.log'):
                pass
            else:
                with open('logs/connections.log','w') as file :
                    file.write(self.main_log_text)
        else:
            os.mkdir('logs')
            self.check_log_dir()

    def create_log_folder_content(self):
        '''This functions is for create banners for log files'''

        version_in_log = 'Server version : ' + self.app_version
        log_info_connections_log = '''This file (connections.log) contains client connections logs :

        usernames ,client IPs who has connected and authentication attempts (failed or successful)
                '''
        self.main_log_text = log_info_connections_log + '\n' + version_in_log + '\n'  # banner of the log file

    def save_connections_logs(self,username,ip,auth_status,connection_status):
        '''This function is for saving logs ---> logs/*.log'''

        time_now = datetime.datetime.now() # time in log
        time_now_formatted = time_now.strftime('%Y-%m-%d %H:%M:%S')

        event =  time_now_formatted + '| ' + username + '| ' + ip + '| ' + auth_status + '| ' + connection_status + '\n'
        with open('logs/connections.log','a') as file :
            file.write(event)

    def server_stop_to_listening(self):
        '''
        function for stop listening to connections and close existing connections
        this function will be called when stop button is clicked
        '''

        global connection_status
        connection_status = 0 # zero is not listening

        for client in self.clients_list:
            client.close() # close connection with clients
        self.server_socket.shutdown(socket.SHUT_RDWR) 
        self.server_socket.close() # remove server socket

        self.clients_num = 0 # set number of clients to 0
        self.clients_list.clear() # clear the client sockets list
        self.clients_name.clear() # clear the client names list

        self.server_start_button.config(state='normal')
        self.server_stop_button.config(state='disabled')
        self.client_list_text_box.config(state='normal')
        self.client_list_text_box.delete('1.0', END)
        self.client_list_text_box.config(state='disabled')

root = Tk()
Gui = ServerManager(root)
root.mainloop()
