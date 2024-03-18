import socket
from threading import Thread
from time import sleep
import argparse
import logging
logger = logging.getLogger(__name__)


class Client:

    def __init__(self,server_ip, server_port):

        self.server_ip = server_ip
        self.server_port = server_port
        self.client_socket = None
        self.authStatus = None

    def connect_to_server(self,conntype,username,password):
        '''function for initial connection to the server'''
        logging.debug('Connecting...')
        # try:
        self.username = username
        self.password = password
        self.client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.client_socket.connect((self.server_ip,self.server_port))
        # credential format => user:username,pass:password;
        print("Sent already???")
        credential = 'conntype:' + conntype + ',user:' + username + ',pass:' + password + ';'
        self.client_socket.sendall(credential.encode())

        # except :
        #     self.client_socket.close()
        #     return
        # else:
            # get ACK if credential is correct or 

        credential_ack = self.client_socket.recv(4096)
        print(credential_ack)
        if credential_ack.decode() == 'invalid credentials':
            self.client_socket.close()
            return
        elif credential_ack.decode() == 'valid credentials':
            pass
        else:
            self.client_socket.close()
            return
        
        self.authStatus = True
        msgs_encoded = self.client_socket.recv(4096)
        print(msgs_encoded)
        msgs_decode = [tuple(part.split(b',')) for part in msgs_encoded.split(b'\n')]

        # try :
        #     for _, message in msgs_decode:
        #         print(message)
        #         self.update_text_display(message)
        
        # except:
        #     pass

        Thread(target=self.receive_msg).start() # start threading for getting messages
        Thread(target=self.send_client_signal).start() # start threading for sending signal messages

    def receive_msg(self):
        '''function for getting clients messages from server'''
        while True :
            try:
                self.clients_message_from_server = self.client_socket.recv(4096)
                print("Server -> " + self.clients_message_from_server)
                if not self.clients_message_from_server : break
                
                # if (self.clients_message_from_server) and \
                #         (self.clients_message_from_server.decode() != 'server signal') :
                    # server signal is a message from server to check connection between itself and client
                    # Thread(target=self.update_text_display,args=(self.clients_message_from_server,)).start()

            except:
                self.client_socket.close()
                # self.connect_button.config(state='normal')  # enable connect button
                # self.send_message_text_box.config(state='disabled')  # disable send message box
                # self.send_message_button.config(state='disabled')  # disable send message button
                # self.chat_server_connection_status.config(text=('Server status : Not connected'), 
                #                                             font=('Tahoma', '15'),fg='Red')
                # messagebox.showerror('Error','Connection closed !')
                break

    def send_msg(self,message):
        '''
        function for sending messages
        this function will be called when send button is clicked
        '''

        # new_message = self.send_message_text_box.get('1.0',END)
        if (len(message.strip()) >= 1) and (len(message.strip()) <= 100) :

            local_message = 'You->' + message.strip()
            final_message = self.username + '->' + message.strip()
            print(final_message)
            try:
                self.client_socket.sendall(final_message.encode())
            except:
                self.client_socket.close()
                # self.connect_button.config(state='normal')
                # self.send_message_text_box.config(state='disabled')  # disable send message box
                # self.send_message_button.config(state='disabled') # disable send message button
                # self.chat_server_connection_status.config(text=('Server status : Not connected'), 
                #                                           font=('Tahoma', '15'), fg='Red')
                # messagebox.showerror('Connection error','Connection is closed !')

            # else:
                # self.send_message_text_box.delete('1.0', END)
        # elif (len(message.strip()) < 1) :
        #     # messagebox.showerror('Error','Your message must be at least 1 character !')
        # elif (len(message.strip()) > 100) :
        #     messagebox.showerror('Error', 'Your can\'t send more that 100 character !')
        # else:
        #     messagebox.showerror('Error', 'Message can\'t be sent !')
                
    def send_client_signal(self):
        '''function for sending signal to server for checking connection between client and server'''
        while True:
            sleep(5) # sending signal every 5 sec
            try:
                self.client_socket.sendall(b'client signal')
            except:
                self.client_socket.close()
                # self.connect_button.config(state='normal')
                # self.send_message_text_box.config(state='disabled')  # disable send message box
                # self.send_message_button.config(state='disabled')  # disable send message button
                # self.chat_server_connection_status.config(text=('Server status : Not connected'), 
                #                                           font=('Tahoma', '15'), fg='Red')
                # messagebox.showerror('Connection error', 'Connection is closed !')



def main():

    parser = argparse.ArgumentParser(description="Send message to server")
    parser.add_argument("--server-ip", type=str, help="Server IP address")
    parser.add_argument("--server-port", type=int, help="Server port number")
    parser.add_argument("--username", type=str, help="Username for authentication")
    parser.add_argument("--password", type=str, help="Password for authentication")
    parser.add_argument("--connection-type", type=str, help="Connection type: sign or login")
    parser.add_argument("--debug", action="store_true", help="Debug mode")

    args = parser.parse_args()

    if not args.debug:
        logging.disable(logging.CRITICAL + 1)

    else :
        # Configure logging
        logging.basicConfig(level= logging.DEBUG,  # Set the logging level to DEBUG
                    format='%(asctime)s - %(levelname)s - %(message)s')  # Define log message format
    # Fetching values of arguments
    server_ip = args.server_ip
    server_port = args.server_port
    username = args.username
    password = args.password
    connection_type = args.connection_type

    c = Client(server_ip,server_port)
    c.connect_to_server(connection_type,username,password)

    try :
        while True:
            message = input(">")
            c.send_msg(message)

    except KeyboardInterrupt:
        pass
    # while c.authStatus:
        

if __name__ == "__main__":
    main()