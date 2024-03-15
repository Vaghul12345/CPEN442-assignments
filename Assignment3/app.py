# system imports
import os
import sys
import socket
from threading import Thread
import pygubu
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox

# local import from "protocol.py"
from protocol import Protocol

# Added for Assignment 3
import json


class Assignment3VPN:
    # Constructor
    def __init__(self, master=None):
        # Initializing UI
        self.builder = builder = pygubu.Builder()
        builder.add_from_file("UI.ui")
        
        # Getting references to UI elements
        self.mainwindow = builder.get_object('toplevel', master)
        self.hostNameEntry  = builder.get_object('ipEntry', self.mainwindow)
        self.connectButton  = builder.get_object('connectButton', self.mainwindow)
        self.secureButton  = builder.get_object('secureButton', self.mainwindow)
        self.clientRadioButton = builder.get_object('clientRadioButton', self.mainwindow)
        self.serverRadioButton = builder.get_object('serverRadioButton', self.mainwindow)
        self.ipEntry = builder.get_object('ipEntry', self.mainwindow)
        self.portEntry = builder.get_object('portEntry', self.mainwindow)
        self.secretEntry = builder.get_object('secretEntry', self.mainwindow)
        self.sendButton = builder.get_object('sendButton', self.mainwindow)
        self.logsText = builder.get_object('logsText', self.mainwindow)
        self.messagesText = builder.get_object('messagesText', self.mainwindow)
        
        # Getting bound variables
        self.mode = None
        self.hostName = None
        self.port = None
        # For an actual shared secret, this would be handled properly and shared before hand. However, due to the small scale nature, I have it auto loaded
        self.sharedSecret = bytes.fromhex("44d10b8638e5ab61d1c7429aa85a907fb87351050dc97e0f6d1e0cd9cfc96812")
        self.textMessage = None
        builder.import_variables(self, ['mode', 'hostName', 'port', 'sharedSecret', 'textMessage'])               
        builder.connect_callbacks(self)
        
        # Network socket and connection
        self.s = None
        self.conn = None
        self.addr = None
        
        # Server socket threads
        self.server_thread = Thread(target=self._AcceptConnections, daemon=True)
        self.receive_thread = Thread(target=self._ReceiveMessages, daemon=True)
        
        # Creating a protocol object
        self.prtcl = Protocol(shared_secret=self.sharedSecret, callback_key=self.callback_key, callback_send=self._SendMessage)

     
    # Distructor     
    def __del__(self):
        # Closing the network socket
        if self.s is not None:
            self.s.close()
            
        # Killing the spawned threads
        if self.server_thread.is_alive():
            self.server_thread.terminate()
        if self.receive_thread.is_alive():
            self.receive_thread.terminate()
            
    
    # Handle client mode selection
    def ClientModeSelected(self):
        self.hostName.set("localhost")


    # Handle sever mode selection
    def ServerModeSelected(self):
        pass
    
    def generate_shared_secret(length=32):
        return os.urandom(length)

    # Create a TCP connection between the client and the server
    def CreateConnection(self):
        # Change button states
        self._ChangeConnectionMode()
        
        # Create connection
        if self._CreateTCPConnection():
            if self.mode.get() == 0:
                # enable the secure and send buttons
                self.secureButton["state"] = "enable"
                self.sendButton["state"] = "enable"
        else:
            # Change button states
            self._ChangeConnectionMode(False)


    # Establish TCP connection/port
    def _CreateTCPConnection(self):
        if not self._ValidateConnectionInputs():
            return False
        
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if self.mode.get() == 0:
                self._AppendLog("CONNECTION: Initiating client mode...")
                self.s.connect((self.hostName.get(), int(self.port.get())))
                self.conn = self.s
                self.receive_thread.start()
                self._AppendLog("CLIENT: Connection established successfully. You can now send/receive messages.")
            else:
                self._AppendLog("CONNECTION: Initiating server mode...")
                self.s.bind((self.hostName.get(), int(self.port.get())))
                self.s.listen(1)
                self.server_thread.start()
            return True
        except Exception as e:
            self._AppendLog("CONNECTION: connection failed: {}".format(str(e)))
            return False
            
     
    # Accepting connections in a separate thread
    def _AcceptConnections(self):
        try:
            # Accepting the connection
            self._AppendLog("SERVER: Waiting for connections...")
            self.conn, self.addr = self.s.accept()
            self._AppendLog("SERVER: Received connection from {}. You can now send/receive messages".format(self.addr))
            
            # Starting receiver thread
            self.receive_thread.start()
            
            # Enabling the secure and send buttons
            self.secureButton["state"] = "enable"
            self.sendButton["state"] = "enable"
        except Exception as e:
            self._AppendLog("SERVER: Accepting connection failed: {}".format(str(e)))
            return False
    def callback_key(self):
        self.secureButton["state"] = "normal"
        self.sendButton["state"] = "normal"

    # Receive data from the other party


    def _ReceiveMessages(self):
        print("recieving messages")
        while True:
            try:
                raw_data = self.conn.recv(4096)
                print("received message")

                if not raw_data:
                    self._AppendLog("RECEIVER_THREAD: Received empty message, nothing here to see")
                    break

                try:
                    print("got here")
                    message = json.loads(raw_data.decode('utf-8'))
                    print("stuck here?")
                    if self.prtcl.IsMessagePartOfProtocol(message) and message.get('type') == 'init':
                        print("processing initialization message")
                        self.prtcl.ProcessReceivedProtocolMessage(message)
                    else:
                        self._AppendLog("RECEIVER_THREAD: Received message is not initialization type or not part of protocol")
                except:
                    # If connection is secure, attempt to decrypt; otherwise, log an error
                    print("got to here, before checking if connection is secure")
                    
    
                    print("attempting to decrypt message")
                    try:
                            print("decrypt 1")
                            decrypted_message = self.prtcl.DecryptAndVerifyMessage(raw_data)
                            print("decrypt 2")
                            message = json.loads(decrypted_message)
                            if self.prtcl.IsMessagePartOfProtocol(message):
                                print("processing protocol message")
                                self.prtcl.ProcessReceivedProtocolMessage(message)
                            else:
                                self._AppendMessage(f"Other: {decrypted_message}")
                    except Exception as e:
                            self._AppendLog(f"RECEIVER_THREAD: Error decrypting or processing message: {e}")
                    else:
                        self._AppendLog("RECEIVER_THREAD: Received encrypted message but connection is not secure.")
            except Exception as e:
                self._AppendLog(f"RECEIVER_THREAD: General error receiving data: {e}")
        # while True:
        #     try:
        #         # Receiving all the data
        #         cipher_text = self.conn.recv(4096)
        #         print("recieved message")
        #         # Check if socket is still open
        #         if cipher_text == None or len(cipher_text) == 0:
        #             self._AppendLog("RECEIVER_THREAD: Received empty message nothing here to see")
        #             break

        #         # Checking if the received message is part of your protocol
        #         # TODO: MODIFY THE INPUT ARGUMENTS AND LOGIC IF NECESSARY
        #         print("recieved message 2")
        #         try:

        #             message = json.loads(cipher_text.decode('utf-8'))
        #             if self.prtcl.IsMessagePartOfProtocol(message):
        #                 print("within the protocol message part")
        #                 # Disabling the button to prevent repeated clicks
        #                 self.secureButton["state"] = "disabled"
        #                 # Processing the protocol message
        #                 self.prtcl.ProcessReceivedProtocolMessage(message)
        #         except json.JSONDecodeError:
        #         # Not a JSON, so likely an encrypted message. Continue processing below.
        #             pass
        #         # Otherwise, decrypting and showing the messaage
        #         print("checking secure protocol")
        #         if self.prtcl.isConnectionSecure:
        #             plain_text = self.prtcl.DecryptAndVerifyMessage(message)
        #             self._AppendMessage("Other: {}".format(plain_text))
        #         else:
        #             self._AppendLog("RECEIVER_THREAD: Received unsecured message.")
        #             # plain_text = self.prtcl.DecryptAndVerifyMessage(cipher_text)
        #             # self._AppendMessage("Other: {}".format(plain_text.decode()))
                    
        #     except Exception as e:
        #         self._AppendLog("RECEIVER_THREAD: Error receiving data: {}".format(str(e)))
        #         return False


    # Send data to the other party
    def _SendMessage(self, message):
        message_type = message.get('type') if isinstance(message, dict) else None

        # Convert to JSON from dictionary to fix bug
        if isinstance(message, dict):
            message = json.dumps(message).encode('utf-8')

        if message_type == 'init':
            print("got to sending message")
            # encrypted_message = self.prtcl.EncryptAndProtectMessage(message)
            self.conn.send(message)
        elif message_type == 'key_exchange':
            encrypted_message = self.prtcl.EncryptAndProtectMessage(message)
            self.conn.send(encrypted_message)
        if self.prtcl.isConnectionSecure:
            encrypted_message = self.prtcl.EncryptAndProtectMessage(message)
            self.conn.send(encrypted_message)
        else:
            self._AppendLog("MESSAGE: Cannot send. Connection not secure.")
            # if isinstance(message, dict):
            #     message = json.dumps(message)

            # cipher_text = self.prtcl.EncryptAndProtectMessage(message)
            # self.conn.send(cipher_text.encode())
            

    # Secure connection with mutual authentication and key establishment
    def SecureConnection(self):
        print("first of secure connection")
        init_message = self.prtcl.GetProtocolInitiationMessage()
        # self._SendMessage(self.prtcl.GetProtocolInitiationMessage())
        
        # disable the button to prevent repeated clicks
        self.secureButton["state"] = "disabled"

        # TODO: THIS IS WHERE YOU SHOULD IMPLEMENT THE START OF YOUR MUTUAL AUTHENTICATION AND KEY ESTABLISHMENT PROTOCOL, MODIFY AS YOU SEEM FIT
        # init_message = self.prtcl.GetProtocolInitiationMessage()

        self._SendMessage(init_message)

# def SecureConnection(self):
#     try:
#         # Starting the mutual authentication and key establishment
#         self.prtcl.InitiateProtocol(self.sharedSecret.get())  # pass the shared secret to the protocol
#         self.secureButton["state"] = "disabled"
#     except Exception as e:
#         self._AppendLog(f"SECURE_CONNECTION: Error - {e}")
        
    # Called when SendMessage button is clicked
    def SendMessage(self):
        text = self.textMessage.get()
        if  text != "" and self.s is not None:
            try:
                self._SendMessage(text)
                self._AppendMessage("You: {}".format(text))
                self.textMessage.set("")
            except Exception as e:
                self._AppendLog("SENDING_MESSAGE: Error sending data: {}".format(str(e)))
                
        else:
            messagebox.showerror("Networking", "Either the message is empty or the connection is not established.")


    # Clear the logs window
    def ClearLogs(self):
        self.logsText.configure(state='normal')
        self.logsText.delete('1.0', tk.END)
        self.logsText.configure(state='disabled')

    
    # Append log to the logs view
    def _AppendLog(self, text):
        self.logsText.configure(state='normal')
        self.logsText.insert(tk.END, text + "\n\n")
        self.logsText.see(tk.END)
        self.logsText.configure(state='disabled')

        
    def _AppendMessage(self, text):
        self.messagesText.configure(state='normal')
        self.messagesText.insert(tk.END, text + "\n\n")
        self.messagesText.see(tk.END)
        self.messagesText.configure(state='disabled')


    # Enabling/disabling buttons based on the connection status
    def _ChangeConnectionMode(self, connecting=True):
        value = "disabled" if connecting else "enabled"
        
        # change mode changing
        self.clientRadioButton["state"] = value
        self.serverRadioButton["state"] = value
        
        # change inputs
        self.ipEntry["state"] = value
        self.portEntry["state"] = value
        self.secretEntry["state"] = value
        
        # changing button states
        self.connectButton["state"] = value

        
    # Verifying host name and port values
    def _ValidateConnectionInputs(self):
        if self.hostName.get() in ["", None]:
            messagebox.showerror("Validation", "Invalid host name.")
            return False
        
        try:
            port = int(self.port.get())
            if port < 1024 or port > 65535:
                messagebox.showerror("Validation", "Invalid port range.")
                return False
        except:
            messagebox.showerror("Validation", "Invalid port number.")
            return False
            
        return True

        
    # Main UI loop
    def run(self):
        self.mainwindow.mainloop()


# Main logic
if __name__ == '__main__':
    app = Assignment3VPN()
    app.run()
