#!/usr/bin/python3
"""
Program: e3client.py
Description: Client to be connected to another client through an e3server instance. All messages are end-to-end encrypted.
"""

import argparse
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import select
from socket import socket, gethostbyname, IPPROTO_TCP, TCP_NODELAY
import threading


class e3client:
    def __init__(self, e3server="", connectionKey="#!ConnectionKey_CHANGE_ME!!!"):
        self.connectionKey = connectionKey
        self.header = bytes(connectionKey)
        self.socket = socket()
        self.socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        if not e3server:
            raise(ValueError("Hostname of mediator server not specified."))
        self.e3server = e3server
        # self.cipherKey declared in key exchange

    def send(self, message):
        # encrypt and send size to target
        size = f"{len(message.encode()):064b}".encode()
        cipher = AES.new(self.cipherKey, AES.MODE_EAX)
        cipher.update(self.header)
        ciphertext, tag = cipher.encrypt_and_digest(size)
        self.socket.sendall(cipher.nonce)
        self.socket.sendall(tag)
        self.socket.sendall(ciphertext)
        # encrypt and send message to target
        cipher = AES.new(self.cipherKey, AES.MODE_EAX)
        cipher.update(self.header)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())
        self.socket.sendall(cipher.nonce)
        self.socket.sendall(tag)
        self.socket.sendall(ciphertext)

    def recv(self):
        # receive and decrypt size
        nonce = self.socket.recv(16)
        tag = self.socket.recv(16)
        ciphertext = self.socket.recv(8)
        cipher = AES.new(self.cipherKey, AES.MODE_EAX, nonce=nonce)
        cipher.update(self.header)
        try:
            size = cipher.decrypt_and_verify(ciphertext, tag)
            size = int(size.decode(), 2)
        except ValueError:
            raise(ValueError("Decryption failed -- invalid key or message integrity broken"))
        # receive message in 1KB chunks for reliability
        progress = 0
        message = b''
        while progress < size:
            buffersize = min(1024, size-progress)
            nonce = self.socket.recv(16)
            tag = self.socket.recv(16)
            ciphertext = self.socket.recv(buffersize)
            # make sure we received full ciphertext
            remaining = buffersize - len(ciphertext)
            while remaining:
                moreCiphertext = self.socket.recv(remaining)
                ciphertext += moreCiphertext
                remaining = buffersize - len(ciphertext)
            # decrypt chunk and add to message
            cipher = AES.new(self.cipherKey, AES.MODE_EAX, nonce=nonce)
            cipher.update(self.header)
            try:
                bytesRead = cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError:
                raise(ValueError("Decryption failed -- message integrity broken"))
            message += bytesRead
            progress += len(bytesRead)
        return message

    def connect(self):
        # connect to e3server
        self.socket.connect((gethostbyname(self.e3server), 443))
        self.socket.sendall(self.connectionKey.encode())
        order = self.socket.recv(1)
        if order.decode() not in ["1", "2"]:
            message = "Connection key validation failed\n"
            message += f"Invalid response from server: {order.decode()}"
            raise ValueError(message)
        if order.decode() == "1":
            self.initiateKeyExchange()
        else:
            self.joinKeyExchange()

    def initiateKeyExchange(self):
        privKey = RSA.generate(4096)
        pubKey = privKey.publickey()
        self.socket.sendall(pubKey.exportKey('PEM'))
        message = self.socket.recv(1024)
        cipher = PKCS1_OAEP.new(privKey)
        try:
            aesKey = cipher.decrypt(message)
        except ValueError:
            raise(ValueError("Key exchange failure -- invalid asymmetric key received"))
        except ConnectionResetError:
            raise(ConnectionResetError("Connection timed out waiting for matching client"))
        self.cipherKey = aesKey


    def joinKeyExchange(self):
        try:
            pemPubKey = self.socket.recv(1024)
            pubKey = RSA.import_key(pemPubKey)
        except ValueError:
            raise(ValueError("Key exchange failure -- invalid public key received"))
        self.cipherKey = get_random_bytes(32)
        cipher = PKCS1_OAEP.new(pubKey)
        message = cipher.encrypt(self.cipherKey)
        self.socket.sendall(message)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Client to be connected to another client through an e3server instance. All messages are end-to-end encrypted.")
    parser.add_argument("-c", "--connection-key", dest="connectionKey", action="store",
                        help="connection key to match to a reverse shell")
    parser.add_argument("-s", "--server", dest="serverAddr", action="store",
                        help="address of e3server",
                        default="example.com")
    args = parser.parse_args()
    if args.connectionKey:
        e3client = e3client(e3server=args.serverAddr, connectionKey=args.connectionKey)
    else:
        e3client = e3client(e3server=args.serverAddr)
    e3client.run()

