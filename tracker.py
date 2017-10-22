# pytorrent-tracker.py
# A bittorrent tracker

from threading import Thread
from socket import inet_aton
import SocketServer
import json


def decode_request(message):
    """ Return the decoded request string. """
    b = b''
    b += message
    d = json.loads(message)
    return d;


def add_peer(info_hash, ip, port):
    """ Add the peer to the peer list. """

    # If the file exists in the file list, just add the peer
    if info_hash in torrents.keys():
        # Only add the peer if they're not already in the database
        if (ip, port) not in torrents[info_hash]:
            torrents[info_hash].append((ip, port))
    # Otherwise, add the info_hash and the peer
    else:
        torrents[info_hash] = [(ip, port)]


def delete_peer(ip, port):
    for info_hash in torrents.keys():
        if (ip, port) in torrents[info_hash]:
            torrents[info_hash].remove((ip, port))


def peer_list(peer_list):
    """ Return an expanded peer list suitable for the client, given the peer list. """

    peers = []
    for peer in peer_list:
        p = {}
        p["ip"] = peer[0]
        p["port"] = int(peer[1])
        peers.append(p)
    return peers


def make_peer_list(file_chunks):
    peer_list = {}
    for info_hash in file_chunks:
        peer_list[info_hash] = torrents[info_hash]
    return peer_list


def generate_ack():
    message = {'message': 'successful'}
    ack = json.dumps(message)
    return ack.encode('utf8');


def generate_error():
    message = {'message': 'invalid type'}
    error = json.dumps(message)
    return error.encode('utf8');

class TCPHandler(SocketServer.BaseRequestHandler):
    def handle(self):

        # self.request is the TCP socket connected to the client

        self.data = self.request.recv(1024).strip()
        message = decode_request(self.data)
        print("{} wrote:".format(self.client_address[0]))
        print("{} wrote:".format(self.client_address[1]))

        if message.type == 0:
            delete_peer(message.ip, message.port);
            self.request.sendall(generate_ack())
        elif message.type == 1:
            for chunk in message.chunks:
                add_peer(chunk, message.ip, message.port)
            self.request.sendall(generate_ack())
        elif message.type == 2:
            peer_list = make_peer_list(message.chunks)
            data = json.dumps(peer_list)
            # just send back the same data, but upper-cased
            self.request.sendall(data.encode('utf8'))
        else:
            self.request.sendall(generate_error())
        self.request.close()


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = "localhost", 9999

    torrents = {}

    # Create the server, binding to localhost on port 9999
    server = ThreadedTCPServer((HOST, PORT), TCPHandler)
    server.serve_forever()