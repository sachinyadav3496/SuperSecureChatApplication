"""
    client file for super secure communication
    a client will try to connect with auth request to server
    using userid, passcode (inserted from matrix keypad on resberry pi)
    and auth request header and process further the chat session by look
    up request for user and starts a chat session.
"""
#!/usr/bin/env python
import socket
#importing socket module create sockets for
#receiving and sending bytes over network
import json
#importing json module data serialization and deserialization tool
import threading
#importing threading module use concurrent programming
import hashlib
#hashlib module for hashing passcodes
import sys
#importing sys module for system i/o or exit functionality
import time
#importing time moddule for introducing delay and time functionality
from cryptography.fernet import Fernet
#cryptography module for encryting ad decryting messages for secure communication
import digitalio
#digitalio module to access i/o ports of resberry pi
import adafruit_matrixkeypad
#adafruit_matrixkeypad module to access 4x4 matrix keypad
import board
#board module to acces i/o pins of resberry pi

#SERVER_IP = "192.168.1.7"
SERVER_PORT = 8082
#Default Server Port

def log(msg):
    """
        log messages for debugging purpose.
    """
    #print(msg)
    open('access_log.txt', 'a').write(msg+"\n")

class State():
    """Abstract parent state class."""
    def __init__(self):
        pass

    @property
    def name(self):
        """
            state name property
        """
        return ''

    def enter(self, machine):
        """
            tasks to be completed on entry point of state
        """

    def exit(self, machine):
        """
            exiting from the state
        """

    def update(self, machine):
        """
            transition from one state to another happens here
        """

class Idle(State):
    """
    Idle State
    """
    def __init__(self):
        State.__init__(self)
        self.string = ""
        self.is_authenticated = False
        self.rows = []
        self.cols = []
        self.keys = None
        self.keypad = None
    @property
    def name(self):
        """
            state name property
        """
        return "Idle"

    def enter(self, machine):
        """
            initilizing keypad and printing welcome message
        """
        log("Inside Enter event of state Idle")
        log("Initlizing keypad into Chat Application")
        if not self.keypad:
            machine.keypad = self.initlize_keypad()
        log(f"added keypad to machine as {machine.keypad}")
        print("\nWelcome to Super Secure Chat Application\n")

    def exit(self, machine):
        """
            "exiting from IDLE State"
        """
        log("exiting from Idle State")
        #State.exit(self, machine)
    def update(self, machine):
        """
            processing input from user
            userid, passcode input
        """
        try:
            log("inside update method of Idle state")
            machine.userid = input("User id: ")
            log("processing keypad press events")
            machine.passcode = self.keypress(machine)
            log(f"you have pressed passcode {machine.passcode}")
            log(f"Your userid is {machine.userid}")
            if machine.userid and machine.passcode:
                log("ready to authenticate your userid & passcode")
                auth = self.auth_request(machine)
                log(f"recevied authentication as {auth}")
                if auth:
                    log("Authentication Granted by server")
                    log("Switching to LoggedIn State")
                    machine.gotostate("LoggedIn")
                else:
                    log("Server has Refused your authentication")
                    log("Make sure your userid are correct")
                    print("\nInvalid Credentials\n")
                    log("Switching to Idle State")
                    machine.gotostate("Idle")
            else:
                log("No userid or passcode is pressed so swithching to Idle State")
                print("\nInvalid Credentials\n")
                machine.gotostate("Idle")
        except KeyboardInterrupt:
            log("..........Exiting Program.......")
            sys.exit(0)

    def initlize_keypad(self):
        """
            initlizing 4x4 pi keypad
        """
        log("Initlization of keypad starts in initlize keypad method")
        row_pins = [board.D21, board.D20, board.D16, board.D12]
        log(f"row_pins are {row_pins}")
        col_pins = [board.D26, board.D19, board.D13, board.D6]
        log(f"col_pins are {col_pins}")
        self.rows = []
        self.cols = []
        log(f"cols = {self.cols} and rows = {self.rows}")
        for row_pin in row_pins:
            self.rows.append(digitalio.DigitalInOut(row_pin))
        log(f"after initlizing i/o pins rows = {self.rows}")
        for col_pin in col_pins:
            self.cols.append(digitalio.DigitalInOut(col_pin))
        log(f"after initlizing i/o pins cols = {self.cols}")
        log("Defining Keypad Layout")
        self.keys = (
            ("D", "#", 0, "*"),
            ("C", 9, 8, 7),
            ("B", 6, 5, 4),
            ("A", 3, 2, 1)
            )
        log(f"keypad is \n{self.keys}")
        self.keypad = adafruit_matrixkeypad.Matrix_Keypad(self.rows, self.cols, self.keys)
        log(f"matrix keypad now is {self.keypad}")
        print("Intilization of keypad is sucessfull")
        return self.keypad

    def keypress(self, machine):
        """
        Reading input from 4x4 pi input keyapd
            passcode keys --> 1, 2, 3, 4, 5, 6, 7, 8, 9, 0
            B --> backspace
            C --> cancel
            A --> enter
        """
        log("Inside keypress event of matrix keypad")
        print("Enter your Passcode: ", end='', flush=True)
        log("accessing machin keypad as {machine.keypad}")
        #keypad = machine.keypad
        try:
            self.string = ""
            while True:
                key_pressed = machine.keypad.pressed_keys
                time.sleep(0.2)
                if key_pressed:
                    key_pressed = str(key_pressed[0])
                    log(f"Pressed keys: {key_pressed}")
                    #print(f"Pressed: {kp}")
                    if key_pressed == "C":
                        print(".............Exiting the Program...........")
                        log("You have cancelled the input event redirecting to Idle state")
                        machine.gotostate("Idle")
                    elif key_pressed == "B":
                        if self.string:
                            log("You have pressed backspace key")
                            self.string = self.string[:-1]

                    elif key_pressed in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0']:
                        log(f"You have pressed key {key_pressed}")
                        self.string += key_pressed
                        #print("*", end="", flush=True)

                    elif key_pressed == "A":
                        log(f"You have submitted {self.string} as passcode")
                        return self.string

                    else:
                        print("Invalid Key Pressed")

        except KeyboardInterrupt:
            print("-"*30, "Exiting", "-"*30)
            sys.exit(0)

    def auth_request(self, machine):
        """
            for sending an auth request to server and getting authenticated
        """
        log("Entering into auth request method of Idle state")
        #gagandeep, krishna, yaneisi
        salts = {'ali': '00', 'bianca':'11', 'gagandeep': '22',
                 'krishna': '33', 'yaneisi': '44'}
        salt = salts.get(machine.userid, 'xx')
        log(f"Salt value of user {machine.userid} is selected as {salt}")
        passcode = salt + hashlib.sha256((salt+machine.passcode).encode()).hexdigest()
        log(f"encrypted passcode is {passcode}")
        log("making auth request")
        request = json.dumps({"msgtype": "AUTHREQ",
                              "userid": machine.userid,
                              "passcode": passcode}).encode("utf-8")
        log(f"auth request is : \n{request}")
        log("Opening a socket to send request to server")
        client = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        log(f"connecting to server at {SERVER_IP}:{SERVER_PORT}")
        client.connect((SERVER_IP, SERVER_PORT))
        log(f"Connection Established to Server sucessfully....sending request")
        client.send(request)
        log("request sucessfully send....reciving response")
        try:
            response = json.loads(client.recv(1024).decode('utf-8'))
            log(f"server response for auth request is \n {response}\n")
            client.close()
            log("processing auth response")
            if response['msgtype'] == 'AUTHREPLY' and response["status"] == "GRANTED":
                machine.my_enc_key = response['key']
                log(f"got own encryption key as {machine.my_enc_key}")
                self.is_authenticated = True
                log("Authentication is sucessfull so returning True")
                return True
            log("Authentication is Denied from server so returning False")
            return False

        except json.JSONDecodeError:
            log(f"Invalid response from server as {response}")
            return False

class LoggedIn(State):
    """
        LoggedIn State to make further connect to a client requests
        or accept connections from remote client
    """
    def __init__(self):
        State.__init__(self)
    @property
    def name(self):
        """
            name property of LoggedIn Class
        """
        return "LoggedIn"
    def enter(self, machine):
        """
            LoggedIn enter state to initlize a socket to listen on port 8085 for all
            incoming traffic or requests.
        """
        log(f"Entering into LoggedIn State of server")
        #log("Starting a thread to accept income connection to this machine")
        #machine.accept_thread = threading.Thread(target=self.accept_connection, args=(machine,))
        #machine.chat_flag = False
        #log("Starting a thread accept_connection")
        #machine.accept_thread.start()
        #log("Thread has been started returning to update state")
    def exit(self, machine):
        """
            exit state to ensure to go to state Idle again
        """
        #machine.gotostate("Idle")
    def update(self, machine):
        """
            update state to start communication by usig userid
            and lookup reqeust
        """
        machine.gotostate("Chatting")
class Chatting(State):
    """
        chatting state where client will send or recv messages untill connection is break.
    """
    def __init__(self):
        State.__init__(self)
        self.chatting = False
    @property
    def name(self):
        """
            name property of Chatting State
        """
        return "Chatting"

    def enter(self, machine):
        """
            Entering in chatting session
        """
        log("inside chatting enter state")
        log("..........Starting Chat Session........")

    def update(self, machine):
        print("\n\n1. Start Session\n2.Join Session")
        try:
            choice = int(input("Your Choice : "))
            if choice == 1:
                self.accept_connection(machine)
            elif choice == 2:
                self.make_connection(machine)
            else:
                print("\n choose 1 or 2")
                machine.gotostate("LoggedIn")
        except ValueError:
            print("\n choose 1 or 2")
            machine.gotostate("LoggedIn")
        except KeyboardInterrupt:
            print(".........Exiting......")
            sys.exit(0)
    def make_connection(self, machine):
        """
            open a socket and reqeuest client to accept your chat request.
        """
        userid = input("\nEnter destination user ID: ")
        #log(f"Now let's lookup into server to check whather user {userid} is LoggedIn or not")
        #log("Calling Lookup Method")
        lookup_answer = self.lookup(machine, userid)
        #log(f"got lookup answer as {lookup_answer}")
        if lookup_answer:
            try:
                #log("now lookup is successfull so start connection request")
                machine.client_enc_key = lookup_answer.get('key')
                #log(f"client encryption key is {machine.client_enc_key}")
                machine.client_name = lookup_answer.get('answer')
                #log(f"client name is {machine.client_name}")
                cip = lookup_answer.get('address')
                #log(f"client address {cip}")
                machine.client_ip = cip
                machine.client_socket = socket.socket()
                machine.client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                #log(f"requesting to client at {cip}:{8085}")
                machine.client_socket.connect((cip, 8085))
                #log("Got connected to client")
                req = json.dumps({
                    "msgtype": "CONNECTREQ",
                    "initiator": machine.userid
                    }).encode('utf-8')
                #log(f"Sending connect request {req}")
                machine.client_socket.send(req)
                #log("request send successfully")
                ans = json.loads(machine.client_socket.recv(1024).decode("utf-8"))
                #log(f"client is replied as answere {ans}")
                if ans.get("msgtype") == "CONNECTREPLY" and ans.get("status") == "ACCEPTED":
                    #log("client is ready to start chatting....start Chatting Session")
                    print("\nConnection established, type your messages\n")
                    self.start_chatting(machine, machine.client_socket)
                    machine.gotostate('LoggedIn')
                else:
                    log("Connection request is REFUSED.....closing socket")
                    try:
                        if hasattr(machine, "client_socket"):
                            machine.client_socket.close()
                            del machine.client_socket
                    except AttributeError:
                        pass
                    #log("Switching to LoggedIn State")
                    machine.gotostate("LoggedIn")
            except json.JSONDecodeError:
                log("Invalid Response from server")
                try:
                    if hasattr(machine, "client_socket"):
                        machine.client_socket.close()
                        del machine.client_socket
                except AttributeError:
                    pass
                machine.gotostate("LoggedIn")
            except OSError:
                log("os error ")
                try:
                    if hasattr(machine, "client_socket"):
                        machine.client_socket.close()
                        del machine.client_socket
                except AttributeError:
                    pass
                machine.gotostate("LoggedIn")
        else:
            print("User is not LoggedIn right now try again later")
            machine.gotostate("LoggedIn")
    def accept_connection(self, machine):
        """
            a thread to listen for clients on port 8085
        """
        try:
            #log("inside accept connection method to accept request of a client")
            machine.server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
            machine.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            #log("created a socket to listen on")
            machine.server_socket.bind(('', 8085))
            #log("opening socket at port 8085")
            machine.server_socket.listen()
            #log("listing for client request")
            machine.client_socket, address = machine.server_socket.accept()
            #log(f"received a request from {address[0]}:{address[1]}")
            machine.client_ip, machine.client_port = address
            #log("receving client request")
            client_request = machine.client_socket.recv(1024).decode("utf-8")
            client_request = json.loads(client_request)
            #log(f"received client reqeust as {client_request}")
            conditions = [
                client_request.get("msgtype") == "CONNECTREQ",
                client_request.get("initiator")
            ]
            if all(conditions):
                #log(f"client reqeust seems good...verifing client by looking up into server")
                lookup_answer = self.lookup(machine, client_request.get("initiator"))
                #log(f"lookup answer for client is {lookup_answer}")
                if lookup_answer and lookup_answer['address'] == machine.client_ip:
                    machine.chat_flag = True
                    machine.client_enc_key = lookup_answer.get('key')
                    #log(f"lookup client user key is {machine.client_enc_key}")
                    machine.client_name = lookup_answer.get('answer')
                    #log(f"lookup client user {machine.client_name}")
                    resp = json.dumps({
                        "msgtype": "CONNECTREPLY",
                        "status": "ACCEPTED"
                        }).encode('utf-8')
                    #log(f"sending response is {resp} to client")
                    machine.client_socket.send(resp)
                    log("Switching to state Chatting")
                    print("\n\nConnection received from user bianca, type yur messages\n\n")
                    self.start_chatting(machine, machine.client_socket)
                else:
                    #log("Un-authorized connect request by Client")
                    #log("swithching to LoggedIn state")
                    resp = json.dumps({
                        "msgtype": "CONNECTREPLY",
                        "status": "REFUSED"
                        }).encode('utf-8')
                    #log(f"sending response as {resp}")
                    machine.client_socket.send(resp)
            else:
                print("Invalid Connect Request by Client")
                resp = json.dumps({
                    "msgtype": "CONNECTREPLY",
                    "status": "REFUSED"
                    }).encode('utf-8')
                #log(f"sending response as {resp}")
                machine.client_socket.send(resp)
        except json.JSONDecodeError:
            log("Invalid Request")
            resp = json.dumps({
                "msgtype": "CONNECTREPLY",
                "status": "REFUSED"
                }).encode('utf-8')
            #log(f"sending response as {resp}")
            machine.client_socket.send(resp)
        except OSError:
            log("Os Error occured due to connection abort")
        try:
            if hasattr(machine, "client_socket"):
                machine.client_socket.close()
                del machine.client_socket
        except AttributeError:
            log("client socket is already closed")
        else:
            try:
                if hasattr(machine, "server_socket"):
                    machine.server_socket.close()
                    del machine.server_socket
            except AttributeError:
                log("server_socket already closed")
        machine.gotostate("LoggedIn")
    def lookup(self, machine, user):
        """
            verifing a client by sending lookup reqeust to the server
        """
        self.chatting = False
        log("Inside lookup method of LoggedIn class")
        log(f"making a request for user {user}")
        request = json.dumps({"msgtype": "LOOKUPREQ",
                              "userid": machine.userid,
                              "lookup": user}).encode("utf-8")
        log(f"LOOKUP Request is {request}")
        log("creating a lookup socket")
        lookup_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        lookup_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        log("connecting to server for lookup request")
        lookup_socket.connect((SERVER_IP, SERVER_PORT))
        log("Connection sucessfully made to server... sending request")
        lookup_socket.send(request)
        log("Request send sucessfull")
        try:
            response = json.loads(lookup_socket.recv(1024).decode('utf-8'))
            log("lookup response from server {response}")
            lookup_socket.close()
            log("lookup socket closed successfully")
            condition = [response.get("msgtype") == "LOOKUPREPLY",
                         response.get("status") == "SUCCESS"]
            if all(condition):
                user = response.get("answer")
                log(f"response user {user}")
                address = response.get("address")
                log(f"response address {address}")
                key = response.get("key")
                log(f"response key {key}")
                return {'user': user, 'address': address, 'key': key, 'answer': user}
            log("got a reply with status NOTFOUND user")
            return False
        except json.JSONDecodeError:
            log(f"Invalid Response from server as {response}")
            lookup_socket.close()
            log("returning to False")
            return False
    def start_chatting(self, machine, client_socket):
        """
        let's start chatting
        """
        self.chatting = True
        th1 = threading.Thread(target=self.send, args=(machine, client_socket))
        th2 = threading.Thread(target=self.recv, args=(machine, client_socket))
        try:
            th1.start()
            th2.start()
            th1.join()
            th2.join()
        except KeyboardInterrupt:
            self.chatting = False
    def send(self, machine, client_socket):
        """
            method to take message input and send to destination socket
        """
        enc = Fernet(machine.my_enc_key)
        while True:
            try:
                if self.chatting:
                    msg = (" "+input(f"\n{machine.userid}: ")+" ").encode('utf-8')
                    msg = enc.encrypt(msg)
                    client_socket.send(msg)
                else:
                    break
            except ConnectionAbortedError:
                break
            except OSError:
                break
            except KeyboardInterrupt:
                msg = "EOFBYEEOF".encode('utf-8')
                msg = enc.encrypt(msg)
                client_socket.send(msg)
                break
            except EOFError:
                break
        self.chatting = False
        try:
            if hasattr(machine, "client_socket"):
                machine.client_socket.close()
                del machine.client_socket
        except AttributeError:
            pass
    def recv(self, machine, client_socket):
        """
            recv mehtod to recieve messages from destination and print on standard output
        """
        dec = Fernet(machine.client_enc_key)
        while True:
            try:
                if self.chatting:
                    msg = client_socket.recv(1024)
                    msg = dec.decrypt(msg).decode('utf-8')
                    if msg and msg != "EOFBYEEOF":
                        print("\n")
                        print(f"{machine.client_name}: {msg}".rjust(50))

                    else:
                        print("\n\nConnection closed by remote machine\n\n")
                        break
                else:
                    break
            except ConnectionAbortedError:
                break
            except OSError:
                break
            except KeyboardInterrupt:
                break
            except EOFError:
                break
        self.chatting = False
        try:
            if hasattr(machine, "client_socket"):
                machine.client_socket.close()
                del machine.client_socket
        except AttributeError:
            pass



class ChatApplication:
    """
        A pi-2-pi secure chat application using 4x4 matrix keypad on pi for passcodes
    """
    def __init__(self):
        self.state = None
        self.states = {}

    def add_state(self, state):
        """
            adding a state to Chat Application
        """
        self.states[state.name] = state

    def gotostate(self, state_name):
        """
            Transition from one state to another state
        """
        log(f"Current state is {self.state}")
        if self.state:
            log(f"Exiting state {self.state}")
            self.state.exit(self)
        log(f"Changing State to {state_name}")
        self.state = self.states[state_name]
        log(f"Entering into state {self.state}")
        self.state.enter(self)
        log(f"Returned form enter state of {self.state}")

    def update(self):
        """
            updating a state to complete the tasks which are given to it.
        """
        log(f"Inside update")
        if self.state:
            log(f"update {self.state}")
            self.state.update(self)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        SERVER_IP = sys.argv[1]
    else:
        print("Usages: client.py server_ip_address")
        sys.exit(0)
    log("Creating an Instance of Application")
    CHAT = ChatApplication()
    log("Adding Idle state to Chat Application")
    CHAT.add_state(Idle())
    log("Adding LoggedIn state to Chat Application")
    CHAT.add_state(LoggedIn())
    log("Adding Idle state to Chat Application")
    CHAT.add_state(Chatting())
    log("Switching to Idle state")
    CHAT.gotostate("Idle")
    log(f"state {CHAT.state} transistion is sucessfull")
    try:
        while True:
            log(f"Updating State to {CHAT.state}")
            CHAT.update()
    except KeyboardInterrupt:
        print("..............Exiting.........")
        sys.exit(0)
