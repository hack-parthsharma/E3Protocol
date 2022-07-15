#!/usr/bin/python3
"""
Program: e3server.py
Description: Bridge two client connections to each other by forwarding data bit for bit
"""

import argparse
import datetime
import select
from socket import socket, AF_INET, SOCK_STREAM, IPPROTO_TCP, TCP_NODELAY
import subprocess
import threading
import time


class e3server:
    def __init__(self, logLevel=1):
        # set log level
        self.logLevel = logLevel
        # create listening socket and bind it to a port
        self.server = socket(AF_INET, SOCK_STREAM)
        self.server.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        self.server.bind(("0.0.0.0",443))
        # queue and match incoming connections
        self.clients = {}
        self.connCount = 0

    def handleConnections(self):
        # start listening on server socket for a max of 10 connections
        self.server.listen(10)
        # make threads for connection handling and bridging
        clientHandler = threading.Thread(target=self.handleClients)
        timeoutWorker = threading.Thread(target=self.waitlistCleaner)
        # run in the background
        clientHandler.daemon = True
        timeoutWorker.daemon = True
        # start threads
        clientHandler.start()
        timeoutWorker.start()
        # wait for keyboard interrupt
        waiter = threading.Event()
        try:
            waiter.wait()
        except KeyboardInterrupt:
            exit()

    def handleClients(self):
        while True:
            # wait for a client to connect
            clientConnection, clientAddress = self.server.accept()
            if self.logLevel >= 2:
                print("Client connection initiated from {}".format(clientAddress[0]))
            clientKey = None
            # get connection key from client
            ready = select.select([clientConnection], [], [], 10)
            if ready[0]:
                try:
                    clientKey = clientConnection.recv(1024)
                except ConnectionResetError:
                    clientConnection.close()
                    continue
            if not clientKey:
                if self.logLevel >= 2:
                    print("No connection key sent by client {}... Closing connection".format(clientAddress[0]))
                clientConnection.close()
                continue
            try:
                if clientKey.decode()[:16] != "#!ConnectionKey_":
                    if self.logLevel >= 2:
                        print("Invalid connection key '{}' sent by client {}... Closing connection".format(clientKey, clientAddress[0]))
                    clientConnection.close()
                    continue
            except Exception:
                if self.logLevel >= 2:
                    print("ERROR: unable to read connection key '{}' from client {}...".format(clientKey, clientAddress[0]))
                    continue
            # if matching key exists in waiting clients, tell client it was second and bridge connections
            if clientKey.decode() in self.clients:
                clientConnection.send("2".encode())
                self.bridgeConnections(clientKey.decode(), clientConnection)
                if self.logLevel >= 1:
                    print("Found matching client key...")
                clientConnection.close()
                continue
            # tell client it was first and add to waiting clients
            clientConnection.send("1".encode())
            self.clients[clientKey.decode()] = (clientConnection, datetime.datetime.now())
            if self.logLevel >= 1:
                print("Client '{}' connected from {}... Waiting for matching client".format(clientKey.decode(), clientAddress[0]))

    def bridgeConnections(self, clientKey, clientConnection):
        # search for matching connection keys
        for waitingClientKey in list(self.clients):
            if waitingClientKey == clientKey:
                # bridge connections with matching keys
                firstConnection = self.clients[clientKey][0]
                secondConnection = clientConnection
                self.applyBlackMagic(firstConnection, secondConnection, clientKey)
                # remove connection from waiting clients
                self.clients.pop(clientKey)
                break

    def waitlistCleaner(self):
        while True:
            for clientKey in list(self.clients):
                # close waiting client if timed out (waiting > 30 seconds)
                timeout = datetime.timedelta(seconds=30) + self.clients[clientKey][1]
                if datetime.datetime.now() > timeout:
                    if self.logLevel >= 2:
                        print("Target '{}' from {} timed out... Closing connection".format(clientKey, self.clients[clientKey][0].getpeername()[0]))
                    self.clients[clientKey][0].close()
                    self.clients.pop(clientKey)
            time.sleep(1)
                

    def applyBlackMagic(self, firstConnection, secondConnection, connectionKey):
        # connect the streams with GNU black magic
        fromSecond = secondConnection.makefile("rb")
        toSecond = secondConnection.makefile("wb")
        fromFirst = firstConnection.makefile("rb")
        toFirst = firstConnection.makefile("wb")
        secondToFirst = subprocess.Popen("cat",
                                            stdin=fromSecond,
                                            stdout=toFirst,
                                            stderr=toFirst)
        firstToSecond = subprocess.Popen("cat",
                                            stdin=fromFirst,
                                            stdout=toSecond,
                                            stderr=toSecond)
        if self.logLevel >= 1:
            print("Client '{}' at {} bridged to matching client at {}... Connection ID {}".format(connectionKey, secondConnection.getpeername()[0], firstConnection.getpeername()[0], self.connCount))
        # create thread to gracefully close connection when done
        terminatorThread = threading.Thread(target=self.waitAndTerminate,
                                            args=[secondToFirst,
                                                  firstToSecond,
                                                  secondConnection,
                                                  firstConnection,
                                                  self.connCount])
        terminatorThread.daemon = True
        terminatorThread.start()
        self.connCount += 1

    def waitAndTerminate(self, secondToFirst, firstToSecond, secondSock, firstSock, connID):
        # close connections when done
        secondToFirst.wait()
        firstToSecond.wait()
        secondSock.close()
        firstSock.close()
        # connections terminated
        if self.logLevel >= 1:
            print("Connection ID {} terminated.".format(connID))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A server that bridges two client connections with matching client keys.")
    parser.add_argument("-l", "--log-level",
                        dest="logLevel",
                        action="store",
                        help="detail of logs created by the server (range: 0-2)",
                        default="1")
    args = parser.parse_args()
    try:
        if int(args.logLevel) not in range(0,3):
            raise ValueError
    except ValueError:
        print("Error: invalid log level supplied (valid range: 0-2)")
        exit(1)
    server = e3server(logLevel=args.logLevel)
    server.handleConnections()
