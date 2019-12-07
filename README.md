# Super Secure Chat Application using Raspberry Pi

In this project,  we are developing a super secure communication system using
Raspberry Pi microcontroller kits to build custom terminals to communicate with each other. The
communication is peer-to-peer between the Raspberry Pi peers, but they communicate with the
server to log into the system and to get information. Once the communication between Pi
terminals is established, the server is idle.
This project can be developed in stages. Encryption is desirable but adds a layer of complexity
therefore it can be left out initially. The most important is the communication between the client
(Raspberry Pi terminal) and the server. As the client-server interaction progresses, the client
moves through several states. The demonstration will be considered successful if the terminals
manage to connect for one round trip exchange: “Hello, are you there?”, “Yes, here I am!”.

---

## Hardware



The secure terminal consists of the Pi, monitor and mouse, with a 4×4 keypad that will be 
used to enter the user’s passcode. The server is simply the Windows PC (or a student owned laptop). The terminals and server are connected to each other over the IP network (wired or wireless).

---

## Typical session

Both users must first log into the system. Each sends an Authentication Request to the server, including the user ID and passcode. The passcode was entered on the 4×4 keypad attached to each Pi. The server replies with an Authentication Reply granting them access, in the case of a passcode match, or denying access otherwise. When a user is logged in, the server remembers that user’s IP address. After logging in successfully, each terminal opens a socket to listen for incoming connections on port 8085.

A typical session begins by user A (Ali) at one terminal wishing to communicate with user B (Bianca) at her terminal. Ali sends a Lookup Request to the server asking for Bianca’s address. If encryption is implemented, the server also gives Ali the encryption key for Bianca. Next, Ali’s terminal attempts to socket.connect(ADDRESS) a TCP connection to Bianca’s address on port 8085. If Bianca is logged in and her terminal is socket.accept()-ing connections, Ali’s terminal sends a Connect Request. Bianca must make sure that the connection request is legitimate. Bianca sends a Lookup Request to the server to verify Ali’s IP address and (optionally, if implemented) Ali’s encryption key. Once Bianca has verified Ali’s connection request, Bianca sends a Connection Reply to Ali. Finally, the communication proceeds. Each terminal goes through an infinite loop of input()-->send() and recv()-->print().	
	The communication ends when either user types CTRL-C to end the chat session. After the end, each terminal continues to listen for connection requests to begin another chat session. A typical session session might look like this. Here ali talks to bianca then types CTRL-C to end the connection (what ali types is in italics).

---

**Login: ali**
**Enter passcode on keypad.**
**Logged in.**
**Enter destination user ID: bianca**
**Connection established, type your messages**
**Hello, how are you today?**
**I am fine, how about you?**
**I am well. Goodbye.**
**CTRL-C connection ended**
**Enter destination user ID:**

---

In another session, ali is logged in and receives a connection request from bianca who then
types CTRL-C to end the connection (what ali types is in italics).

---

**Login:**
**Enter passcode on keypad.**
**Logged in.**
**Enter destination user ID:**
**Connection received from user bianca, type your messages**
**Hello, how are you today?**
**I am fine, how about you?**
**I am well. Goodbye.**
**Connection ended**
**Enter destination user ID:**

---

# Requirements

---

## Passcode

The user must use the keypad to enter a numeric passcode, consisting of one or more digits 0—9. The ‘A’ key serves as the “Enter & Validate” key. The passcode is never displayed, not even “*” characters that would “leak” the number of digits. 
		
**Optional:** The ‘B’ key is Backspace and the ‘C’ key is Cancel

---

## Communications protocol

The chat session must start with several phases to log in to the system, request user information and request a chat connection before any messages can be exchanged. The chat client goes through several states during the phases of the connection.

Information exchange between server and client is done with JSON formatted messages. Each message is a sequence of name:value pairs. Message types are identified with the msgtype key present in all messages.

---

### Authentication phase

Each client sends an Authentication Request to the server. The authentication request includes the user ID and the hashed passcode. The server looks up the user ID and compares the hashed passcode to the hashed passcode it has stored. If the hashed passcodes match, the server returns an Authentication Reply message and also stores the current IP address of the user who has just authenticated.

The client sends an Authentication Request message to the server.

---

* **msgtype: “AUTHREQ”
* **userid: string as entered by the user making the request;
* **passcode:** the user’s passcode entered by the user on the keypad, then salted and hashed

**Authentication Request Message Example**
	
		{
		   "msgtype": "AUTHREQ",
		   "userid": "sachin",
		   "passcode": "0123hh3ghjgjh23gh23f23fewrew13"
		}
		
The server sends the Authentication Reply message to the client telling the client if the user is authenticated or not. The value of the status key is either “GRANTED” if successful (Listing 2), or “REFUSED” otherwise 


* **msgtype:** “AUTHREPLY”
* **userid:** string as entered by the user making the request;
* **status:** “GRANTED” if the credentials were accepted, “REFUSED” otherwise.

---

**Authentication Grant Reply Message Example - Authentication Granted**

		{
			"msgtype": "AUTHREPLY",
			"status": "Granted"
		}
		
**Authentication Grant Reply Message Example - Authentication Refused**

		{
			"msgtype": "AUTHREPLY",
			"status": "REFUSED"
		}

---

## Lookup phase

The initiating client sends a Lookup Request to the server. The request includes the user ID of the initiator and the user ID of the person the initiator wishes to contact. The server replies with a Lookup Reply message giving information about the person, or no information if that person is not logged in. As a precaution against requests by users not logged in, the server also replies with no information if the user making the request is not logged in. The server replies with a Lookup Reply message. The reply includes the user ID of the person the initiator wishes to contact, the IP address of her/his client and (optional) the encryption key to be used when communicating with that person.

The client sends the Lookup Request message to the server

* **msgtype:** “LOOKUPREQ”;
* **userid:** string as entered by the user making the request;
* **lookup:** the user ID of the person that the user is calling.

**Lookup Request message example**

	{
	 "msgtype": "LOOKUPREQ",
	 "userid": "sachin",
	 "lookup": "rajat"
	 }
	
**The server sends the Lookup Reply message to the client, with “status”:“SUCCESS” and information if found, or “status”:“NOTFOUND” and empty information fields otherwise.**

* **msgtype:** “LOOKUPREPLY”;
* **status:** “SUCCESS” if the user ID is logged in, “NOTFOUND” otherwise
* **answer:** the user ID of the person that the user is calling;
* **address:** the IP address of the remote user;
* **encryptionkey:** the encryption key as a string.

**Lookup Reply message example – User found, information returned**

	{
	  "msgtype": "LOOKUPREPLY",
	  "status": "SUCCESS",
	  "answer": "rajat",
	  "address": "192.168.0.12",
	  "encryptionkey": "1234",
	} 
	
**Lookup Reply message example – User not found**

	{
	  "msgtype": "LOOKUPREPLY",
	  "status": "SUCCESS",
	  "answer": "",
	  "address": "",
	  "encryptionkey": "",
	} 

---

**Connection Phase**

The initiating terminal sends a Connection Request to the destination terminal. The request includes the user ID of the initiator. The destination terminal performs a Lookup Request of its own to the server and, if the address of the initiating user’s terminal matches the one registered with the server, the destination terminal replies with a Connect Reply “accepted” message to go ahead with the chat session, otherwise it sends a Connect Reply “refused” message. The initiator sends the Connect Request message to the destination terminal

* **msgtype:** “CONNECTREQ”;
* **initiator:** the user ID of the person making the request.

**Connect Request message example – sachin requests connection to rajat**

	{
	 "msgtype": "CONNECTREQ",
	 "initiator": "ali"
	}

**The destination sends the Connect Reply message “status”:“ACCEPTED” to the initiator terminal, or “status”:“REFUSED” otherwise.**

* msgtype: “CONNECTREPLY”
* answer: “ACCEPTED” or “REFUSED”



**Connect Reply message example – Connection request accepted by destination**

	{
	  "msgtype": "CONNECTREPLY",
	  "status": "ACCEPTED"
	}

**Connect Reply message example – Connection request refused**

	{
	  "msgtype": "CONNECTREPLY",
	  "status": "REFUSED"
	}
	
---


**Chat phase**

No special messaging format is required in the chat phase. The two-way connection is established between terminals and the main loop can simply read from the open connection as if it was a stream of bytes. Each client can “catch” the CTRL-C KeyboardInterrupt to end the chat at any time. No special protocol is needed to end a session.
	
--- 
## Cryptography

The extra functionality of hashing the passcodes and encrypting/decrypting the messages and chat exchanges is left as an option. A bonus of up to 2 points will be awarded for reasonably convincing hashing of the passcodes. A bonus of up to 3 points for reasonably convincing symmetric encryption of the messages and chat exchanges using the cryptographymodule in Python.


---

---
