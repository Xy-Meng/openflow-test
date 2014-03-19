#!/usr/bin/python
__author__ = 'krish'

import argparse
import logging
import socket
import time
import sys
import asyncore
import binascii
# Change log level to suppress annoying IPv6 error
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import RandNum, Raw, packet
from of_protocol import OpenFlowHeader, OpenFlowHello, OpenFlowEchoRequest, OpenFlowEchoReply, OpenFlowFeaturesReply, OpenFlowFeaturesRequest

# Generate random source port number
port=RandNum(1024,65535)


#bind_layers(TCP, OpenFlowHeader, sport=port)
#bind_layers(TCP, OpenFlowHeader, dport=port)

#bind_layers( TCP, OpenFlow, sport=6633, dport = random port number generated earlier ) or use guess_payload_function

# OF1.3 handshake
# Create OF1.3 HELLO pkt
#ss.recv().show() # will show the controller sent hello pkt
#hello=ip/TCP(sport=SYNACK.dport, dport=6633, flags="A", seq=SYNACK.ack
#ack=SY    NACK.seq + 1)
#ACK.show()

class Cli():
    ''' this will work only in unix! '''

    class AsyncCliRead(asyncore.file_dispatcher):
        """ Class for handling stdin """
        def __init__(self, fd):
            asyncore.file_dispatcher.__init__(self, fd)
            self.data = ''

        def handle_read(self):
            received = self.recv(1024)
            bytes_recvd = len(received)
            received = received.strip()
            #print "Read data: '" + received + "'"
            if bytes_recvd > 0:
                #self.sock_data = self.data + received
                # process the command received
                if received.strip() == 'exit':
                    sys.exit(0) # TODO cleanup
            Cli.print_prompt()

        def handle_write(self):
            # not allowed to write to stdin
            pass

    class AsyncCliWrite(asyncore.file_dispatcher):
        """ Class for handling stdout """

        def __init__(self, fd):
            asyncore.file_dispatcher.__init__(self, fd)
            self.data = ''

        def handle_write(self):
            if self.data is not '':
                sent_bytes = self.send(self.data)
                if sent_bytes > 0:
                    print "len(data): ", len(data), "sent bytes: ", sent_bytes
                    self.sock_data = self.sock_data[sent_bytes:]

        def handle_read(self):
            # not allowed to read from stdout
            pass

    ## 'Static' vars and methods for Cli class
    stdin = AsyncCliRead(sys.stdin)
    stdout = AsyncCliWrite(sys.stdout)
    @classmethod
    def print_prompt(clazz):
        clazz.stdout.send('crafter> ')

    def __init__(self):
        Cli.print_prompt()

class AsyncServerSocket(asyncore.dispatcher):
    """ convert the streamsocket into a non-blocking socket """

    def __init__(self, normal_socket):
        asyncore.dispatcher.__init__(self, sock=normal_socket)
        self.sock_data = ''
        # map of client session to automata
        self.state = {}

    def writable(self):
        return (len(self.sock_data) > 0)
    
    def readable(self):
        return True

    def writable(self):
        return (len(self.sock_data) > 0)

    def handle_connect(self):
        print "handle connect"

    def handle_read(self):
        received = self.recv(1024)
        bytes_recvd = len(received)
        if bytes_recvd > 0:
            print 'data recvd by server'
            self.sock_data = self.sock_data + received
            self.sock_data = self.sock_data[len(received):]
            # get the length from the openflow header
            # check if the 'length' data has been received, if yes, then we
            # have the complete packet
            # if complete packet, handle it
            ofpkt = OpenFlowHeader(received)
            if bytes_recvd == ofpkt.length:
                # process of pkt
                self.process_packet(ofpkt)
                #print "pkt recvd"
            #else:
            #    won't happen #TODO

    def handle_close(self):
        print "handle close"
        self.close()

    def handle_write(self):
        if self.sock_data is not '':
            sent_bytes = self.send(self.sock_data)
            if sent_bytes > 0:
                print binascii.hexlify(self.sock_data)
                self.sock_data = self.sock_data[sent_bytes:]

    def handle_expt(self):
        print "handle server expt"

    def handle_accept(self):
        # send hello pkt
        client = self.accept()
        ofhello = OpenFlowHeader()/OpenFlowHello()
        self.sock_data = str(ofhello)
        print 'accepted connection from', client # ??


    def handle_accepted(self):
        print 'handle accepted'

    def process_packet(self, ofpkt):
        print 'processing.....pkt'
    """
        if ofpkt.type == 0:
            # hello received, reply with a crafted hello
            ofhello = OpenFlowHeader()/OpenFlowHello()
            self.sock_data = str(ofhello)
        elif ofpkt.type == 2:
            print 'echo req received'
            ofechoreply = OpenFlowHeader()/OpenFlowEchoReply()
            self.sock_data = str(ofechoreply)
            #sent_bytes = self.send(str(ofechoreply))
            #print "length: length", "sent bytes: ", sent_bytes
        elif ofpkt.type == 5:
            # fea_req recvd, reply with feature reply
            offeaturesreply = OpenFlowHeader()/OpenFlowFeaturesReply()
            self.sock_data = str(offeaturesreply)
            #offeaturereply = packet.__class__(str(offeaturereply))
            #length = offeaturereply.length
            #sent_bytes = self.send(str(offeaturesreply))
            #print "length: length", "sent bytes: ", sent_bytes
            #print "length: ", length, "sent bytes: ", sent_bytes
            #if length == sent_bytes:
            #    print 'sent correct number of bytes'
    """

class AsyncClientSocket(asyncore.dispatcher):
    """ convert the streamsocket into a non-blocking socket """

    def __init__(self, normal_socket):
        asyncore.dispatcher.__init__(self, sock=normal_socket)
        self.sock_data = ''

    def writable(self):
        return (len(self.sock_data) > 0)
    
    def readable(self):
        return True

    def writable(self):
        return (len(self.sock_data) > 0)

    def handle_connect(self):
        #print "handle connect"
        pass

    def handle_read(self):
        received = self.recv(1024)
        bytes_recvd = len(received)
        if bytes_recvd > 0:
            #print 'data recvd'
            self.sock_data = self.sock_data + received
            self.sock_data = self.sock_data[len(received):]
            # get the length from the openflow header
            # check if the 'length' data has been received, if yes, then we
            # have the complete packet
            # if complete packet, handle it
            ofpkt = OpenFlowHeader(received)
            if bytes_recvd == ofpkt.length:
                # process of pkt
                self.process_packet(ofpkt)
                #print "pkt recvd"
            #else:
            #    won't happen #TODO

    def handle_close(self):
        #print "handle close"
        self.close()

    def handle_write(self):
        if self.sock_data is not '':
            sent_bytes = self.send(self.sock_data)
            if sent_bytes > 0:
                #print "len(sock_data): ", len(self.sock_data), "sent bytes: ", sent_bytes
                #print binascii.hexlify(self.sock_data)
                self.sock_data = self.sock_data[sent_bytes:]

    def handle_expt(self):
        print "handle expt"

    def handle_accept(self):
        print 'handle_accept'
        #TODO send hello

    def handle_accepted(self):
        print 'handle accepted'

    def process_packet(self, ofpkt):
        #print 'processing.....pkt'
        #ofpkt.show()
        xid = ofpkt.xid
        if ofpkt.type == 0:
            # hello received, reply with a crafted hello
            ofhello = OpenFlowHeader()/OpenFlowHello()
            ofhello.xid = xid
            self.sock_data = str(ofhello)
        elif ofpkt.type == 2:
            # echo req received, reply with echo reply
            ofechoreply = OpenFlowEchoReply.get_reply_packet(ofpkt)
            self.sock_data = str(ofechoreply)
        elif ofpkt.type == 5:
            # fea_req recvd, reply with feature reply
            offeaturesreply = OpenFlowHeader()/OpenFlowFeaturesReply()
            offeaturesreply.xid = xid
            self.sock_data = str(offeaturesreply)

class OpenFlowImpl():
    def __init__(self, server_socket, client_socket, ip, port):
        self.clientsocket = AsyncClientSocket(client_socket)
        self.clientsocket.connect((ip, port)) #TODO
        self.serversocket = AsyncServerSocket(server_socket)
        self.serversocket.bind((socket.gethostname(), 6633))
        self.serversocket.listen(16)
        # create an async for stdin and stdout
        self.cli = Cli()


if __name__ == '__main__':
    # set up logging
    #logging.basicConfig(filename='testResults.log', level=logging.DEBUG)
    # parse cmdline arguments
    parser = argparse.ArgumentParser(description='Run OpenFlow protocol simulation')
    parser.add_argument('-ci', '--controllerip', default='192.168.1.1', help='device to conect to') #required=True)
    parser.add_argument('-cp', '--controllerport', type=int, default=6633, help='port on which device is listening (6653/6633)')
    args = parser.parse_args()
    # TODO: Sanity test for args

    # print the state diagram
    #OpenFlowSession.graph(format="png")
    #b = OpenFlowSession()
    #b.run()

    # create a client socket
    client_socket = socket.socket()
    # create a server socket @ 0.0.0.0:6633
    server_socket = socket.socket()
    ofimpl = OpenFlowImpl(server_socket, client_socket, args.controllerip,
    args.controllerport)
    # start the loop
    # check if something is ready for writing to socket every 5 seconds
    asyncore.loop(5) 


