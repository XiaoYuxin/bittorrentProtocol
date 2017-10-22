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

CLIENT_NAME = "p2p_peer1"
CLIENT_ID = "peer1"
CLIENT_VERSION = "0001"

def read_torrent_file(torrent_file):
	""" Given a .torrent file, returns its decoded contents. """

	with open(torrent_file) as file:
		return file.read()

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

def encode(data):
    temp = [data[key] for key in sorted(data.keys())]
    return collapse(temp)

class Torrent():
    def __init__(self, torrent_file):
        self.data = read_torrent_file(torrent_file)
        self.info_hash = sha1(encode(self.data["info"])).digest()
        self.tracker = self.data["tracker"]
        self.peer_id = generate_peer_id()
        self.handshake = generate_handshake(self.info_hash, self.peer_id)

    def contact_tracker(self):
        """contact tracker to indicate the interest to download the file"""
        return



