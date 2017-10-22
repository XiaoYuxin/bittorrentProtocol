# torrent.py
# Torrent file related utilities

from hashlib import md5, sha1
from random import choice
import socket
from struct import pack, unpack
from threading import Thread
from time import sleep, time
import types
from util import collapse
from bencode import encode, decode

CLIENT_NAME = "p2p_peer1"
CLIENT_ID = "peer1"
CLIENT_VERSION = "0001"
SLEEP_TIME = 5
SERVER_PORT = 50007

def read_torrent_file(torrent_file):
	""" Given a .torrent file, returns its decoded contents. """

	with open(torrent_file) as file:
		return decode(file.read())

def generate_peer_id():
	""" Returns a 20-byte peer id. """

	# As Azureus style seems most popular, we'll be using that.
	# Generate a 12 character long string of random numbers.
	random_string = ""
	while len(random_string) != 12:
		random_string = random_string + choice("1234567890")

	return "-" + CLIENT_ID + CLIENT_VERSION + "-" + random_string

def generate_handshake(info_hash, peer_id):
	""" Returns a handshake. """
	protocol_id = "BitTorrent protocol"
	len_id = str(len(protocol_id))
	reserved = "00000000"
	return len_id + protocol_id + reserved + info_hash + peer_id


def encode_message(type=None, chunks=None, ip=None, port=None):
    #TODO: implement encode message
    encoded = None
    return encoded

class Torrent():
    def __init__(self, torrent_file):
        self.data = read_torrent_file(torrent_file)
        self.info_hash = sha1(encode(self.data["info"])).digest()
        self.tracker_ip = self.data["tracker"][0]
        self.tracker_port = self.data["tracker"][1]
        self.peer_id = generate_peer_id()
        self.handshake = generate_handshake(self.info_hash, self.peer_id)

        #inform tracker about the interest
        self.contact_tracker()
        #start the TCP server, listening to incoming request from other peers
        self.run_server()

    def contact_tracker(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.tracker_ip, self.tracker_port))
        myip = ([l for l in (
        [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [
            [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in
             [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])

        encoded = encode_message(type = 1, chunks=[], ip =  myip, port = SERVER_PORT)
        s.send(encoded)
        response = s.recv(1024)
        s.close()
        return

    def run_server(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', SERVER_PORT ))
        s.listen(1)
        while True:
            conn, addr = s.accept()
            print ('Connected by', addr)
            server_loop = Thread(target=self.server_handle_request,  args=(conn,))
            server_loop.start()



    def server_handle_request(self, conn):
        #TODO:handle individual request from other peer, then terminate the thread
        while 1:
            data = conn.recv(1024)
            if not data: break
            conn.sendall(data)
        return

    def client_send_request(self):
        #TODO: send download request for each chunk, after downloading one chunk, need to update the tracker
        return



