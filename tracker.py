# pytorrent-tracker.py
# A bittorrent tracker

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from logging import basicConfig, info, INFO
from socket import inet_aton
from urllib import urlopen
from urlparse import parse_qs
import SocketServer
import json


def decode_request(path):
	""" Return the decoded request string. """

	# Strip off the start characters
	if path[:1] == "?":
		path = path[1:]
	elif path[:2] == "/?":
		path = path[2:]

	return parse_qs(path)

def add_peer(torrents, info_hash, peer_id, ip, port):
	""" Add the peer to the peer list. """

	# If the file exists in the file list, just add the peer
	if info_hash in torrents:
		# Only add the peer if they're not already in the database
		if (peer_id, ip, port) not in torrents[info_hash]:
			torrents[info_hash].append((peer_id, ip, port))
	# Otherwise, add the info_hash and the peer
	else:
		torrents[info_hash] = [(peer_id, ip, port)]

def peer_list(peer_list):
	""" Return an expanded peer list suitable for the client, given
	the peer list. """

	peers = []
	for peer in peer_list:
		p = {}
		p["peer id"] = peer[0]
		p["ip"] = peer[1]
		p["port"] = int(peer[2])

		peers.append(p)

	return peers

class TCPHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        # self.request is the TCP socket connected to the client
        b = b''
        self.data = self.request.recv(1024).strip()
        b += self.data
        print "{} wrote:".format(self.client_address[0])
        print b
        d = json.loads(b)
        print d
        print type(d)
        info_hash = d['info_hash']
        print info_hash
        peer_id = d['peer_id']
        ip = self.client_address[0]
        port = d['port']
        add_peer(torrents, info_hash, peer_id, ip, port)
        peers = peer_list(torrents[info_hash])
        data = json.dumps(peers)
        # just send back the same data, but upper-cased
        self.request.sendall(data.encode('utf8'))


if __name__ == "__main__":
    HOST, PORT = "localhost", 9999

    torrents = {}

    # Create the server, binding to localhost on port 9999
    server = SocketServer.TCPServer((HOST, PORT), TCPHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()