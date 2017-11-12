# torrent.py
# Torrent file related utilities

from hashlib import md5, sha1
from random import choice
import socket
from struct import pack, unpack
from threading import Thread, Lock
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
SERVER_PORT = 49985
PIECE_LENGTH = 4096


# CLIENT_NAME = "p2p_uploa#der"
# CLIENT_ID = "uploader"
# CLIENT_VERSION = "0001"
TRACKER_IP = '172.17.6.152'
TRACKER_PORT = 10017
TRACKER_UDP_PORT = 12355


# for testing
UDP_TIME = 1

def read_torrent_file(torrent_file):
    """ Given a .torrent file, returns its decoded contents. """

    with open(torrent_file, 'rb') as file:
        return json.loads((file.read().decode('utf-8')))


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
        # self.myip = ([l for l in (
        #     [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [
        #         [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in
        #          [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
        # run_server_loop = Thread(target=self.run_server)
        #run_server_loop.start()
        self.info_hash = None
        self.tracker_ip = None
        self.tracker_port = None
        self.filename = None
        self.remaining_chunk_set = None
        self.available_chunk_set = None
        self.pid = None
        self.chunk_status_dict = dict()
        self.chunks_data = dict()
        register_loop = Thread(target=self.register)
        register_loop.start()
        self.query_peer_loop_1 = None
        self.query_peer_loop_2 = None
        self.query_peer_loop_3 = None
        #self.mutex = Lock()

    def register(self):
        print('start registering.....')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TRACKER_IP, TRACKER_PORT))
        print('finish connecting....')
        encoded = encode_request({'type': 5})
        s.send(('%16s' % (len(encoded))).encode('utf-8'))
        s.send(encoded)
        length = int(s.recv(16).decode('utf-8'))
        data = b''
        print('finishing sending...')
        while len(data) < length:
            newdata = s.recv(1024)
            data += newdata
        #print(len(data))
        b = b''
        b += data
        self.pid = json.loads(b)['pid']
        print ("my peer id %s", self.pid)
        # data_queue_loop = Thread(target=self.register_data_queue, args=(self.pid))
        # data_queue_loop.start()
        while True:
            try:
                length = int(s.recv(16).decode('utf-8'))
                data = b''
                while len(data) < length:
                    newdata = s.recv(1024)
                    data += newdata
                #print(len(data))
                b = b''
                b += data
                request = json.loads(b)
                print('handle request from' + str(request['req_pid']) + ' for chunk ' + str(request['chunk_num'])
                      + ' using TCP')
                filename = request['filename']
                chunk = request['chunk_num']
                data_to_send = self.chunks_data[chunk]
                s.send(('%16s' % (len(data_to_send))).encode('utf-8'))
                s.send(data_to_send)
            except TypeError:
                print(TypeError)
                continue

    # def register_data_queue(self):
    #     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     s.connect((TRACKER_IP, TRACKER_PORT))
    #     print('start registering data queue....')
    #     encoded = encode_request({'type': 6, 'pid': self.pid})
    #     s.send(('%16s' % (len(encoded))).encode('utf-8'))
    #     s.send(encoded)
    #     #length = int(s.recv(16).decode('utf-8'))
    #     #data = b''
    #     print('finishing regitering data queue...')
    #


    def make_info_dict(self, file):
        """ Returns the info dictionary for a torrent file. """
        #print('before open the file')
        with open(file, 'rb') as f:
            data = f.read()

        info = dict()
        info["piece length"] = PIECE_LENGTH
        info["length"] = len(data)
        info["chunk number"] = int(math.ceil(len(data) / PIECE_LENGTH * 1.0))
        info["name"] = file
        for chunk_num in range(0, info["chunk number"]):
            self.chunks_data[chunk_num] = data[chunk_num*PIECE_LENGTH:min(chunk_num*PIECE_LENGTH+PIECE_LENGTH, len(data))]
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
        self.tracker_ip = TRACKER_IP
        self.tracker_port = TRACKER_PORT
        self.update_tracker()

    def download(self, torrent_file):
        print('start downloading...')
        data = read_torrent_file(torrent_file)
        self.info_hash = data["info"]
        self.tracker_ip = data["tracker"][0]
        self.tracker_port = data["tracker"][1]
        self.filename = data['info']['name']

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
        print('indicate interest to tracker...')
        self.update_tracker()
        # start the TCP server, listening to incoming request from other peers
        query_tracker_loop = Thread(target=self.query_tracker_for_status)
        query_tracker_loop.start()
        # start send request to peers
        self.query_peer_loop_1 = Thread(target=self.client_send_request)
        self.query_peer_loop_1.start()
        self.query_peer_loop_1.join()
        self.write_into_file()

    def write_into_file(self):
        print('received all chunks, writing into files....')
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
        while len(self.remaining_chunk_set) > 0:
            print('query tracker for status.....')
            chunks_to_query = [format_filename_chunk_num(self.filename, chunk_num) for chunk_num in
                               self.remaining_chunk_set]
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.tracker_ip, self.tracker_port))
            encoded = encode_request({'type': 2, 'chunks': chunks_to_query})
            s.send(('%16s' % (len(encoded))).encode('utf-8'))
            s.send(encoded)

            length = int(s.recv(16).decode('utf-8'))
            data = b''
            while len(data) < length:
                newdata = s.recv(1024)
                data += newdata
            #print(len(data))
            b = b''
            b += data

            #status_list_from_tracker = decode_request(data)
            status_list_from_tracker = json.loads(b)

            #status_list_from_tracker = decode_request(response)
            self.update_status_list(status_list_from_tracker)
            s.close()
            # check the status for every 5 sec
            #print(self.chunk_status_dict)
            sleep(SLEEP_TIME)

    def get_chunk(self, peer_id, filename, chunk_num):
        print('request peer %d for a chunk %d using TCP', peer_id, chunk_num)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TRACKER_IP, TRACKER_PORT))
        data_to_send = {'type': 6, 'req_pid': self.pid, 'res_pid': peer_id, 'filename': filename, 'chunk_num': chunk_num}
        encoded = encode_request(data_to_send)
        s.send(('%16s' % (len(encoded))).encode('utf-8'))
        s.send(encoded)
        length = int(s.recv(16).decode('utf-8'))
        data = b''
        while len(data) < length:
            newdata = s.recv(1024)
            data += newdata
        #print(len(data))
        self.chunks_data[chunk_num] = data
        print('getting the requested chunk....' + str(chunk_num))
        print('Remaining chunk set length...' + str(len(remaining_chunk_set)))
        s.close()
        return

    def update_tracker(self):
        # send query type 1 to tracker, when
        # 1) innitially indicate interest to tracker
        # 2) every time after it finish download a chunk, update the status
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.tracker_ip, self.tracker_port))
        formated_available_chunk = [format_filename_chunk_num(self.filename, chunk_num) for chunk_num in
                                    self.available_chunk_set]
        encoded = encode_request({'type': 1, 'chunks': formated_available_chunk, 'pid': self.pid})
        print('update available chunks...')
        s.send(('%16s' % (len(encoded))).encode('utf-8'))
        s.send(encoded)
        response = s.recv(1024)
        s.close()
        return

    # def run_server(self):
    #     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     s.bind(('', SERVER_PORT))
    #     s.listen(5)
    #     while True:
    #         conn, addr = s.accept()
    #         print('Connected by', addr)
    #         server_loop = Thread(target=self.server_handle_request, args=(conn,))
    #         server_loop.start()

    """handle request from other peer"""

    # def send_chunk(self, filename, chunk):
    #     print('handle request for a chunk using TCP')
    #     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     s.connect((TRACKER_IP, TRACKER_PORT))
    #     data_to_send = self.chunks_data[chunk]
    #     s.send(('%16s' % (len(data_to_send))).encode('utf-8'))
    #     s.send(data_to_send)
    #     length = int(s.recv(16).decode('utf-8'))
    #     data = b''
    #     while len(data) < length:
    #         newdata = s.recv(1024)
    #         data += newdata
    #     #print(len(data))
    #     self.chunks_data[chunk_num] = data
    #     print('getting the requested chunk....' + str(chunk_num))
    #     s.close()
    #     return
    #
    #
    #
    #
    #
    #     print('handling request and send chunk to another peer')
    #     s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #     data_to_send = self.chunks_data[chunk]
    #     # TODO: check UDP packet size
    #     print (peer_ip)
    #     print (peer_port)
    #     print (chunk)
    #     print (len(data_to_send))
    #     s.sendto(data_to_send, (peer_ip, peer_port))
    #     print ("Finish sending first time...")
    #     s.sendto(data_to_send, (peer_ip, peer_port))
    #     print ("Finish sending second time...")
    #     s.sendto(data_to_send, (peer_ip, peer_port))
    #     print ("Finish sending third time...")
    #     s.sendto(data_to_send, (peer_ip, peer_port))
    #     print ("Finish sending 4th time...")
    #     s.sendto(data_to_send, (peer_ip, peer_port))
    #     print ("Finish sending 5th time...")
    #     s.sendto(data_to_send, (peer_ip, peer_port))
    #     print ("Finish sending 6th time...")
    #     s.sendto(data_to_send, (peer_ip, peer_port))
    #     print ("Finish sending 7th time...")
    #     s.sendto(data_to_send, (peer_ip, peer_port))
    #     print ("Finish sending 8th time...")
    #     s.sendto(data_to_send, (peer_ip, peer_port))
    #     print ("Finish sending 9th time...")
    #     s.sendto(data_to_send, (peer_ip, peer_port))
    #     print ("Finish sending 10th time...")
    #     if UDP_TIME == 2:
    #         s.sendto(data_to_send, (peer_ip, peer_port))
    #     s.close()
    #     return

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
                peer_id = random.choice(self.chunk_status_dict[chunk_num])
                print('peer list...')
                print(peer_id)
                result['pid'] = peer_id
                if peer_id == self.pid:
                    result = {}
                    continue
                result['chunknum'] = chunk_num
                return result


    """send request to other peer"""

    def client_send_request(self):
        #print(self.remaining_chunk_set)
        while len(self.remaining_chunk_set) > 0:
            print('sending request....')
            rand_chunk = self.generate_rand_chunk_num()
            #print('rand chunk')
            #print(rand_chunk)
            if rand_chunk:
                #self.remaining_chunk_set.remove(rand_chunk['chunknum'])
                # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # s.connect((rand_chunk['peer_ip'], rand_chunk['peer_port']))
                #print(format_filename_chunk_num(self.filename, rand_chunk['chunknum']).encode('utf-8'))
                # s.send(format_filename_chunk_num(self.filename, rand_chunk['chunknum']).encode('utf-8'))

                # length = int(s.recv(16).decode('utf-8'))
                # # print(length)
                # data = b''
                # while len(data) < length:
                #     newdata = s.recv(1024)
                #     data += newdata
                # # response = s.recv(1024)
                # #print('chunk get is : ' + str(data))
                # self.chunks_data[rand_chunk['chunknum']] = data
                print('before sending request.....')
                self.get_chunk(rand_chunk['pid'], self.filename, rand_chunk['chunknum'])
                self.available_chunk_set.add(rand_chunk['chunknum'])
                self.remaining_chunk_set.remove(rand_chunk['chunknum'])
                # update tracker for the new chunk
                print('received chunk: ' + str(rand_chunk['chunknum']))
                print('updating tracker for the new chunk')
                self.update_tracker()

    """contact tracker to exit"""

    def exit(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.tracker_ip, self.tracker_port))
        encoded = encode_request({'type': 0, 'pid': self.pid})
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
