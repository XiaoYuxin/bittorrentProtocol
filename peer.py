# torrent.py
# Torrent file related utilities

from hashlib import md5, sha1
from random import choice
import socket
from struct import pack, unpack
from threading import Thread
from time import sleep, time
import types
from util import collapse, encode_request, decode_request
from bencode import encode, decode
import random
import json
import sys
import math

CLIENT_NAME = "p2p_peer1"
CLIENT_ID = "peer1"
CLIENT_VERSION = "0001"
SLEEP_TIME = 5
SERVER_PORT = 49981
PIECE_LENGTH = 4096


# CLIENT_NAME = "p2p_uploa#der"
# CLIENT_ID = "uploader"
# CLIENT_VERSION = "0001"
TRACKER_IP = '172.25.107.64'
TRACKER_PORT = 9995


def read_torrent_file(torrent_file):
    """ Given a .torrent file, returns its decoded contents. """

    with open(torrent_file, 'rb') as file:
        return json.loads((file.read().decode('utf-8')))


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


def format_filename_chunk_num(filename, chunk_num):
    return 'filename:' + filename + ':chunknum:' + str(chunk_num)


def deformat_filename_chunk_num(formated_name):
    splited = formated_name.split(':')
    result = {}
    result['filename'] = splited[1]
    result['chunknum'] = int(splited[3])
    return [splited[1], int(splited[3])]


class Torrent:
    def __init__(self):
        self.myip = ([l for l in (
            [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [
                [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in
                 [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
        run_server_loop = Thread(target=self.run_server)
        run_server_loop.start()
        self.info_hash = None
        self.tracker_ip = None
        self.tracker_port = None
        self.filename = None
        self.peer_id = None
        self.is_running = None
        self.remaining_chunk_set = None
        self.available_chunk_set = None
        self.chunk_status_dict = dict()
        self.chunks_data = None
        self.data = []
        self.query_peer_loop_1 = None
        self.query_peer_loop_2 = None
        self.query_peer_loop_3 = None

    def make_info_dict(self, file):
        """ Returns the info dictionary for a torrent file. """
        print('before open the file')
        with open(file, 'rb') as f:
            self.data = f.read()

        info = dict()
        info["piece length"] = PIECE_LENGTH
        info["length"] = len(self.data)
        info["chunk number"] = int(math.ceil(len(self.data) / PIECE_LENGTH * 1.0))
        info["name"] = file
        # info["md5sum"] = md5(contents).hexdigest()
        # Generate the pieces
        # pieces = slice_str(contents, piece_length)
        # pieces = [ sha1(p).digest() for p in pieces ]
        # info["pieces"] = collapse(pieces)
        return info

    def make_torrent_file(self, file):
        """ Returns the bencoded contents of a torrent file. """
        if not file:
            raise TypeError("make_torrent_file requires at least one file, non given.")

        torrent = dict()
        torrent["tracker"] = [TRACKER_IP, TRACKER_PORT]
        torrent["creation date"] = int(time())
        torrent["created by"] = CLIENT_NAME
        torrent["info"] = self.make_info_dict(file)
        meta_file_name = file + '.torrent'
        print('meta file name: ' + meta_file_name)
        with open(meta_file_name, "w") as torrent_file:
            torrent_file.write(json.dumps(torrent))
        return int(torrent["info"]["chunk number"])

    def upload(self, file):
        chunk_num = self.make_torrent_file(file)
        print('finish generating torrent file')
        self.filename = file
        self.available_chunk_set = []
        for i in range(0, chunk_num):
            self.available_chunk_set.append(i)
        self.update_tracker()

    def download(self, torrent_file):
        data = read_torrent_file(torrent_file)
        self.info_hash = data["info"]
        self.tracker_ip = data["tracker"][0]
        self.tracker_port = data["tracker"][1]
        self.filename = data['info']['name']

        self.peer_id = generate_peer_id()
        # self.handshake = generate_handshake(self.info_hash, self.peer_id)
        self.is_running = True
        # set of all remaining chunk numer
        self.remaining_chunk_set = {key for key in range(0, data['info']['chunk number'])}
        #print('remaining chunk set: ' + str(len(self.remaining_chunk_set)))
        # set of already owned chunk num
        self.available_chunk_set = set()
        # dict of all chunks with corresponding peers having this chunk, initially all empty list
        self.chunk_status_dict = {key: [] for key in range(0, data['info']['chunk number'])}

        # dict of all real chunks data, innitially all empty
        self.chunks_data = {key: None for key in range(0, data['info']['chunk number'])}

        # inform tracker about the interest
        self.update_tracker()
        # start the TCP server, listening to incoming request from other peers
        query_tracker_loop = Thread(target=self.query_tracker_for_status)
        query_tracker_loop.start()
        # start send request to peers
        # start 3 threads simultaneously
        self.query_peer_loop_1 = Thread(target=self.client_send_request)
        self.query_peer_loop_2 = Thread(target=self.client_send_request)
        self.query_peer_loop_3 = Thread(target=self.client_send_request)
        self.query_peer_loop_1.start()
        self.query_peer_loop_2.start()
        self.query_peer_loop_3.start()
        self.query_peer_loop_1.join()
        self.query_peer_loop_2.join()
        self.query_peer_loop_3.join()
        self.write_into_file()

    def write_into_file(self):
        with open(self.filename, "wb") as data_file:
            for key, value in self.chunks_data.items():
                data_file.write(value)


    def update_status_list(self, updated_list):
        deformated_update_list = {deformat_filename_chunk_num(key)[1]: updated_list[key] for key in updated_list.keys()}
        #print('dfjdlskgjlkgjlsf')
        #print(deformated_update_list)
        for each_chunk in deformated_update_list.keys():
            #print(deformated_update_list[each_chunk])
            self.chunk_status_dict[each_chunk] = deformated_update_list[each_chunk]

    def query_tracker_for_status(self):
        # update the status for all the chunks that have not downloaded yet
        print('before connecting to tracker')
        while self.is_running and len(self.remaining_chunk_set) > 0:
            chunks_to_query = [format_filename_chunk_num(self.filename, chunk_num) for chunk_num in
                               self.remaining_chunk_set]
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.tracker_ip, self.tracker_port))
            encoded = encode_request({'type': 2, 'chunks': chunks_to_query})
            s.send(('%16s' % (len(encoded))).encode('utf-8'))
            s.send(encoded)

            length = int(s.recv(16).decode('utf-8'))
            print('receiving length from tracker: ' + str(length))
            data = b''
            while len(data) < length:
                newdata = s.recv(1024)
                data += newdata
            print(len(data))
            b = b''
            b += data

            #status_list_from_tracker = decode_request(data)
            status_list_from_tracker= json.loads(b)


            #status_list_from_tracker = decode_request(response)
            print('before update status list')
            self.update_status_list(status_list_from_tracker)
            s.close()
            # check the status for every 5 sec
            #print(self.chunk_status_dict)
            sleep(SLEEP_TIME)

    def update_tracker(self):
        # send query type 1 to tracker, when
        # 1) innitially indicate interest to tracker
        # 2) every time after it finish download a chunk, update the status
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TRACKER_IP, TRACKER_PORT))
        formated_available_chunk = [format_filename_chunk_num(self.filename, chunk_num) for chunk_num in
                                    self.available_chunk_set]
        encoded = encode_request({'type': 1, 'chunks': formated_available_chunk, 'ip': self.myip, 'port': SERVER_PORT})
        s.send(('%16s' % (len(encoded))).encode('utf-8'))
        s.send(encoded)
        response = s.recv(1024)
        s.close()
        return

    def run_server(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', SERVER_PORT))
        s.listen(1)
        while True:
            conn, addr = s.accept()
            print('Connected by', addr)
            server_loop = Thread(target=self.server_handle_request, args=(conn,))
            server_loop.start()

    """handle request from other peer"""

    def server_handle_request(self, conn):
        print('handling request from another server')
        formated_filename = conn.recv(1024)
        print(str(formated_filename))
        chunknum = deformat_filename_chunk_num(formated_filename.decode('utf-8'))[1]
        print('handling request for chunk: ' + str(chunknum))
        data_to_send = self.data[chunknum*PIECE_LENGTH:min(chunknum*PIECE_LENGTH+PIECE_LENGTH, len(self.data))]
        conn.sendall(('%16s' % (len(data_to_send))).encode('utf-8'))
        conn.sendall(data_to_send)
        return

    def generate_rand_chunk_num(self):
        result = {}
        exclude_set = set()
        while True:
            chunk_num = random.choice(tuple(self.remaining_chunk_set.difference(exclude_set)))
            #print(chunk_num)
            #print(self.chunk_status_dict)
            if len(self.chunk_status_dict[chunk_num]) == 0:
                exclude_set.add(chunk_num)
                if len(self.remaining_chunk_set.difference(exclude_set)) == 0:
                    return result
            else:
                peer = random.choice(self.chunk_status_dict[chunk_num])
                result['peer_ip'] = peer[0]
                if peer[0] == self.myip:
                    result = {}
                    continue
                result['peer_port'] = peer[1]
                result['chunknum'] = chunk_num
                return result


    """send request to other peer"""

    def client_send_request(self):
        print('remaining chunk set')
        #print(self.remaining_chunk_set)
        while len(self.remaining_chunk_set) > 0:
            rand_chunk = self.generate_rand_chunk_num()
            #print('rand chunk')
            #print(rand_chunk)
            if rand_chunk:
                self.remaining_chunk_set.remove(rand_chunk['chunknum'])
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((rand_chunk['peer_ip'], rand_chunk['peer_port']))
                print('send request: ')
                print(format_filename_chunk_num(self.filename, rand_chunk['chunknum']).encode('utf-8'))
                s.send(format_filename_chunk_num(self.filename, rand_chunk['chunknum']).encode('utf-8'))

                length = int(s.recv(16).decode('utf-8'))
                # print(length)
                data = ""
                while len(data) < length:
                    newdata = s.recv(1024)
                    data += newdata
                # response = s.recv(1024)
                print('chunk get is : ' + str(data))
                self.chunks_data[rand_chunk['chunknum']] = data
                self.available_chunk_set.add(rand_chunk['chunknum'])
                # update tracker for the new chunk
                self.update_tracker()

    """contact tracker to exit"""

    def exit(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.tracker_ip, self.tracker_port))
        encoded = encode_request({'type': 0, 'ip': self.myip, 'port': SERVER_PORT})
        s.send(encoded)
        s.close()


print('starting: ')
""" Start  generating torrent file. """
torrent = Torrent()
while True:
    print('1.upload 2.download')
    option = int(sys.stdin.readline())
    if option == 1:
        print('enter file name: ')
        line = sys.stdin.readline()
        print('getting file name: ' + line)
        file = line.strip()
        torrent.upload(file)
    else:
        print('enter torrent file name: ')
        line = sys.stdin.readline()
        print('getting torrent file name: ' + line)
        file = line.strip()
        torrent.download(file)
