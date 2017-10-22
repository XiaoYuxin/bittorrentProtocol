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
import random

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

def decode_message(raw_message):
    #TODO: implement decode message
    decoded = {}
    decoded['queried_chunk_list'] = {}
    return decoded

def format_filename_chunk_num(filename, chunk_num):
    return 'filename:' + filename + 'chunknum:' + chunk_num

def deformat_filename_chunk_num(formated_name):
    splited = formated_name.split(':')
    result = {}
    result['filename'] = splited[1]
    result['chunknum'] = int(splited[3])
    return result

class Torrent():
    def __init__(self, torrent_file):
        self.data = read_torrent_file(torrent_file)
        self.info_hash = sha1(encode(self.data["info"])).digest()
        self.tracker_ip = self.data["tracker"][0]
        self.tracker_port = self.data["tracker"][1]
        self.filename = self.data['info']['name']
        self.myip = ([l for l in (
        [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [
            [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in
             [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
        self.peer_id = generate_peer_id()
        self.handshake = generate_handshake(self.info_hash, self.peer_id)
        self.is_running = True
        #set of all remaining chunk numer
        self.remaining_chunk_set = { key for key in range(0, self.data['info']['chunk number'])}
        #set of already owned chunk num
        self.available_chunk_set = set()
        #dict of all chunks with corresponding peers having this chunk, initially all empty list
        self.chunk_status_dict = {key : [] for key in range(0, self.data['info']['chunk number'])}
        #dict of all real chunks data, innitially all empty
        self.chunks_data = {key: None for key in range(0, self.data['info']['chunk number'])}


        #inform tracker about the interest
        self.update_tracker()
        #start the TCP server, listening to incoming request from other peers
        self.run_server()
        self.query_tracker_loop = Thread(target=self.query_tracker_for_status)
        self.query_tracker_loop.start()
        #start send request to peers
        #start 3 threads simultaneously
        self.query_peer_loop_1 = Thread(target=self.client_send_request)
        self.query_peer_loop_2 = Thread(target=self.client_send_request)
        self.query_peer_loop_3 = Thread(target=self.client_send_request)
        self.query_peer_loop_1.start()
        self.query_peer_loop_2.start()
        self.query_peer_loop_3.start()

    def update_tracker(self):
        #send query type 1 to tracker, when
        #1) innitially indicate interest to tracker
        #2) every time after it finish download a chunk, update the status
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.tracker_ip, self.tracker_port))
        formated_available_chunk = [format_filename_chunk_num(self.filename, chunk_num) for chunk_num in self.available_chunk_set]
        encoded = encode_message(type = 1, chunks=formated_available_chunk, ip =  self.myip, port = SERVER_PORT)
        s.send(encoded)
        response = s.recv(1024)
        s.close()
        return

    def query_tracker_for_status(self):
        #update the status for all the chunks that have not downloaded yet
        while self.is_running and len(self.remaining_chunk_set) > 0:
            chunks_to_query = [format_filename_chunk_num(self.filename, chunk_num) for chunk_num in self.remaining_chunk_set]
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.tracker_ip, self.tracker_port))
            encoded = encode_message(type=2, chunks=chunks_to_query)
            s.send(encoded)
            response = s.recv(1024)
            status_list_from_tracker = decode_message(response)['queried_chunk_list']
            self.update_status_list(status_list_from_tracker)
            s.close()
            #check the status for every 5 sec
            sleep(SLEEP_TIME)


    def run_server(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', SERVER_PORT ))
        s.listen(1)
        while True:
            conn, addr = s.accept()
            print ('Connected by', addr)
            server_loop = Thread(target=self.server_handle_request,  args=(conn,))
            server_loop.start()

    """handle request from other peer"""
    def server_handle_request(self, conn):
        formated_filename = conn.recv(1024)
        chunknum = deformat_filename_chunk_num(formated_filename)['chunknum']
        conn.sendall(self.chunks_data[chunknum])
        return

    def generate_rand_chunk_num(self):
        result = {}
        exclude_set = set()
        while True:
            chunk_num = random.choice(tuple(self.remaining_chunk_set.difference(exclude_set)))
            if len(self.chunk_status_dict[chunk_num]) == 0:
                exclude_set.add(chunk_num)
                if len(self.remaining_chunk_set.difference(exclude_set)) == 0:
                    return result
            else:
                peer = random.choice(self.chunk_status_dict[chunk_num])
                result['peer_ip'] = peer[0]
                result['peer_port'] = peer[1]
                result['chunknum'] = chunk_num
                return result

    """send request to other peer"""
    def client_send_request(self):
        while(len(self.remaining_chunk_set) > 0):
            rand_chunk = self.generate_rand_chunk_num()
            if rand_chunk:
                self.remaining_chunk_set.remove(rand_chunk['chunknum'])
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((rand_chunk['peer_ip'], rand_chunk['peer_port']))
                s.send(format_filename_chunk_num(self.filename, rand_chunk['chunknum']))
                response = s.recv(1024)
                print('chunk get is : ' + response)
                self.chunks_data[rand_chunk['chunknum']] = response
                self.available_chunk_set.add(rand_chunk['chunknum'])
                #update tracker for the new chunk
                self.update_tracker()


    def perform_send_request(self, peer_ip, peer_port, chunk_num):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((peer_ip, peer_port))
        s.send(format_filename_chunk_num(self.filename, chunk_num))
        response = s.recv(1024)
        #TODO: convert into chunk data
        return response


    def update_status_list(self, updated_list):
        deformated_update_list = {deformat_filename_chunk_num(key)[1] : updated_list[key] for key in updated_list.keys()}
        for each_chunk in deformated_update_list.keys():
            self.chunk_status_dict[each_chunk] = deformated_update_list['each_chunk']

