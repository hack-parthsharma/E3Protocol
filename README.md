# E3 Protocol (End-to-End Encryption)

*Attention:* this repository has been archived indefinitely due to it being unfinished and the author reprioritizing his time with no plans to continue working on this.

A basic end-to-end encryption protocol implemented in Python in which messages are sent between two clients. The server connecting the clients has no visibility into the conversation, and only exists to bridge two clients that use the same connection key.

## Features:

### End-to-End Encryption

4096-bit RSA is used for the key exchange, and 256-bit AES (EAX mode) is used for the cipher. The server bridging the connections has no way of snooping on the connection between two clients.

### Message length abstraction

Message length is calculated at runtime and sent to the receiving client before the message. This greatly simplifies the message sending and receiving process when utilized in an application.

### Tips and Warnings:

Warning: The current server implementation has a 30 second timeout for clients waiting for their matches.

Warning: This server implementation is secure, but in theory an untrusted server could snoop on the connections. In the future, cryptographic trust between the server and the clients will be implemented as well as a mechanism for trust between clients.

Tip: For security, you should use a randomly generated connection key for each session. If a malicious party learns your connection key and spams the server with it, they may be connected to your inteded counterpart client.
