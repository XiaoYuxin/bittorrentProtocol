# pytorrent-tracker.py
# A bittorrent tracker

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from logging import basicConfig, info
from socket import inet_aton
from urllib import urlopen


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

def make_peer_list(peer_list):
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

class RequestHandler(BaseHTTPRequestHandler):
	def do_GET(s):
		""" Take a request, do some some database work, return a peer
		list response. """

		# Get the necessary info out of the request
		info_hash = package["info_hash"][0]
		ip = s.client_address[0]
		port = package["port"][0]
		peer_id = package["peer_id"][0]

		add_peer(s.server.torrents, info_hash, peer_id, ip, port)

		# Generate a response
		response = {}
		response["interval"] = s.server.interval
		response["complete"] = 0
		response["incomplete"] = 0
		response["peers"] = make_peer_list( \
		s.server.torrents[info_hash])

		# Send off the response
		s.send_response(200)
		s.end_headers()
		s.wfile.write(encode(response))

		# Log the request, and what we send back
		info("PACKAGE: %s", package)
		info("RESPONSE: %s", response)

	def log_message(self, format, *args):
		""" Just supress logging. """

		return

class Tracker():
	def __init__(self, host = "", port = 9010, interval = 5, log = "tracker.log"):
		""" Read in the initial values, load the database. """

		self.host = host
		self.port = port

		self.server_class = HTTPServer
		self.httpd = self.server_class((self.host, self.port), \
			RequestHandler)

		self.running = False	# We're not running to begin with

		self.server_class.interval = interval

		self.server_class.torrents = []

		# Set logging info
		basicConfig(filename = log, level = INFO)

	def runner(self):
		""" Keep handling requests, until told to stop. """

		while self.running:
			self.httpd.handle_request()

	def run(self):
		""" Start the runner, in a seperate thread. """

		if not self.running:
			self.running = True

			self.thread = Thread(target = self.runner)
			self.thread.start()

	def send_dummy_request(self):
		""" Send a dummy request to the server. """

		# To finish off httpd.handle_request()
		address = "http://127.0.0.1:" + str(self.port)
		urlopen(address)

	def stop(self):
		""" Stop the thread, and join to it. """

		if self.running:
			self.running = False

			self.send_dummy_request()
			self.thread.join()

	def __del__(self):
		""" Stop the tracker thread, write the database. """

		self.stop()
		self.httpd.server_close()