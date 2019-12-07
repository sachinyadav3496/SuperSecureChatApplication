"""
    A Server Socket which listen for clients and process there request as
    if client has login request, userid and passcode log them in active users
    or if client request for lookup than send valid request if user is logged in
"""
import json # data serialization library
import socket # socket programming library
import sys # command line arguments library

class Server:
    """
        TCP IP server to accept and process client requests according to super
        secure communication protocols.
    """
    def __init__(self, ip):
        self.active_users = {}
        self.client_ip = None
        self.client_port = None
        self.client_socket = None
        self.server_port = 8082
        self.server_ip = ip
        self.initilize_socket() # initlize a server socket

    def initilize_socket(self):
        """
            Initlize a socket on port 8082 and start listning to clients request
        """
        self.server = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        #creating a TCP type IPV4 faimly Socket
        self.server.bind((self.server_ip, self.server_port))
        #binding server to fix ip and port 8082
        self.server.listen(10)
        #server is ready to accept clients requests

    def accept(self):
        """
            will accept requests of client
        """
        client, (client_ip, client_port) = self.server.accept()
        self.client_ip = client_ip
        self.client_port = client_port
        self.client_socket = client
        # accept clients request for further processing
        self.log()
        # log client's ip address and port into log.txt file
        self.process_request()
        # process client request accoring to protocols
        self.client_socket.close() # closing client request
        self.client_ip = None
        self.client_port = None
        self.client_socket = None
    def process_request(self):
        """
            process client request according to predefine protocols.
        """
        try:
            request = json.loads(self.client_socket.recv(1024).decode('utf-8'))
            #print(request)
            if request['msgtype'] == "AUTHREQ":
                #print("auth request received")
                self.handle_auth_request(request)
                # handling authentication type request
            elif request['msgtype'] == "LOOKUPREQ":
                self.handle_lookup_request(request)
                # handling lookup request for user query
            elif request["msgtype"] == "LOGOUTREQ":
                self.handle_logout_request(request)
                # handling logout request of user
            else:
                response = {"msgtype": "RESPONSE", "status": "FAILED",
                            "message": "Invalid request"}
                response = json.dumps(response).encode()
                self.client_socket.sendall(response)
                # sending answer to an invalid request
        except json.JSONDecodeError:
            #print("Invalid Request of Client")
            response = {"msgtype": "RESPONSE", "status": "FAILED",
                        "message": "Invalid request"}
            response = json.dumps(response).encode()
            self.client_socket.sendall(response)
            # handling invalid request of client
        except TypeError:
            #print("Invalid JSON Data Send by Client")
            # handling invalid request of client
            response = {"msgtype": "RESPONSE", "status": "FAILED",
                        "message": "Invalid request"}
            response = json.dumps(response).encode()
            self.client_socket.sendall(response)

    def log(self):
        """
            log a connection request of client with client ip address and port from request
            has been send.
        """
        with open("logs.txt", "a") as file_pointer: # opening log file for appending
            message = f"""Connection from ({self.client_ip}, {self.client_port})"""
            #creating a log message
            print(message)# printing log message
            file_pointer.write(message) # logging message
            file_pointer.close() #closing file

    def handle_auth_request(self, request):
        """
            handling auth request and repling accoring to protocols
        """
        #print("handling auth reqeust")
        database = json.load(open("user_db.json"))
        # loading database to check user authentication
        #
        #print(database)
        #print(request)
        if request['userid'] in database:
            # checking user exists or not in database
            #print("user fond in database")
            if request['passcode'] == database[request['userid']][0]:
                # checking passcode of user to verify it's authenticity
                #print("user has authenticated")
                response = {"msgtype": "AUTHREPLY",
                            "status": "GRANTED",
                            "key": database[request['userid']][1]}
                # preparing granted response
                response = json.dumps(response).encode('utf-8')
                #print(response)
                # serialzing and converting into bytes to send over network
                self.active_users[request['userid']] = [
                    self.client_ip,
                    database[request['userid']][1]]
                # logging in user server side for lookup requests
                #print("active users ",self.active_users)
                self.client_socket.send(response)
                #print("Send answer")
                # sending response to client
                return
        response = json.dumps({"msgtype": "AUTHREPLY", "status": "REFUSED"}).encode('utf-8')
        # sending connection refused response for invalid authentication
        self.client_socket.sendall(response)
    def handle_lookup_request(self, request):
        """
            handling lookup request of clients and anwering accordingly
        """
        if request['userid'] in self.active_users:
            # checking ligitimacy of user
            user = request['lookup']
            # looking up for user in active users
            if user in self.active_users:
                response = {"msgtype": "LOOKUPREPLY", "status": "SUCCESS",
                            "answer": user, "address": self.active_users[user][0],
                            "key": self.active_users[user][1]}
                response = json.dumps(response).encode()
                # sending response for sucessfull lookup of user
                self.client_socket.sendall(response)
            else:
                response = {"msgtype": "LOOKUPREPLY", "status": "NOTFOUND",
                            "answer": "", "address": ""}
                response = json.dumps(response).encode()
                # sending response for un-sucessfull lookup of user
                self.client_socket.sendall(response)
        else:
            response = {"msgtype": "LOOKUPREPLY", "status": "INVALIDREQUEST",
                        "answer": "", "address": ""}
            response = json.dumps(response).encode()
            # sending response for invalid lookup request
            self.client_socket.sendall(response)
            return
    def handle_logout_request(self, request):
        """
            logging out a user
        """
        if request['userid'] in self.active_users:
            del self.active_users[request['userid']]
            # logging out user from active users
            response = {"msgtype": "LOGOUTREPLY", "status": "SUCCESS",
                        "answer": "loggout sucessfull"}
            response = json.dumps(response).encode()
            # sending response for sucessfull logout of a user
            self.client_socket.sendall(response)
        else:
            response = {"msgtype": "LOGOUTREPLY", "status": "INVALIDREQUEST",
                        "answer": "auth error signin for access"}
            response = json.dumps(response).encode()
            # sending response for invalid logout request
            self.client_socket.sendall(response)

    def __del__(self):
        """
        closing server socket.
        """
        self.server.close()
        # closing server socket
        del self

if __name__ == "__main__":
    try:
        if len(sys.argv) == 2:
            SERVER = Server(sys.argv[1])
            # up and running server on given ip
            print(f"Server is Up and Running at {SERVER.server_ip}:{SERVER.server_port}")
            while True:
                SERVER.accept()
                # accept client requests forever
        else:
            print("Usages: server.py ip_address")
            # printing error message on invalid use of script (without ip)
    except KeyboardInterrupt:
        print("Closing Server Socket")
        # exiting message from server
        del SERVER
