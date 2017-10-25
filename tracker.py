# pytorrent-tracker.py
# A bittorrent tracker

from threading import Thread
from socket import inet_aton
import SocketServer
import json
import util


def add_file_chunk(filename, chunk_num):
    if filename in files:
        if chunk_num not in files[filename]:
            files[filename].append(chunk_num)
    else:
        files[filename] = [chunk_num]


def delete_file_chunk(filename, chunk_num):
    if filename in files:
        if chunk_num in files[filename]:
            files[filename].remove(chunk_num)
        if files[filename] is []:
            files.pop(filename, None)


def add_peer(info_hash, ip, port):
    """ Add the peer to the peer list. """

    # If the file exists in the file list, just add the peer
    if info_hash in torrents:
        # Only add the peer if they're not already in the database
        if (ip, port) not in torrents[info_hash]:
            torrents[info_hash].append((ip, port))
    # Otherwise, add the info_hash and the peer
    else:
        torrents[info_hash] = [(ip, port)]


def delete_peer(ip, port):
    for info_hash, value in torrents.items():
        if (ip, port) in value:
            value.remove((ip, port))
        if value is []:
            torrents.pop(info_hash, None)
            data = info_hash.split(':')
            delete_file_chunk(data[1], int(data[3]))


def expand_peer_list(peer_list):
    """ Return an expanded peer list suitable for the client, given the peer list. """

    peers = []
    for peer in peer_list:
        p = dict()
        p["ip"] = peer[0]
        p["port"] = int(peer[1])
        peers.append(p)
    return peers


def make_peer_list(file_chunks):
    peer_list = dict()
    for info_hash in file_chunks:
        peer_list[info_hash] = torrents[info_hash]
    return peer_list


def generate_ack():
    message = {'message': 'successful'}
    ack = json.dumps(message)
    return ack.encode('utf8')


def generate_error():
    message = {'message': 'invalid type'}
    error = json.dumps(message)
    return error.encode('utf8')


class TCPHandler(SocketServer.BaseRequestHandler):
    def handle(self):

        # self.request is the TCP socket connected to the client
        length = int(self.request.recv(16).decode('utf-8'))
        print(length)

        data = ""
        while len(data) < length:
            newdata = self.request.recv(1024)
            data += newdata

        print(len(data))
        message = util.decode_request(data)

        if 'type' not in message:
            self.request.sendall(generate_error())
        else:
            if message['type'] == 0:  # exit the network
                delete_peer(message['ip'], int(message['port']))
                print(torrents)
                self.request.sendall(generate_ack())
                print('Type 0')
            elif message['type'] == 1:  # inform and update
                if 'chunk_num' in message.keys():
                    message['filename'] = message['chunk_num']
                for chunk in message['chunks']:
                    add_peer(chunk, message['ip'], message['port'])
                    data = chunk.split(':')
                    add_file_chunk(data[1], int(data[3]))
                # print(files)
                # print(torrents)
                self.request.sendall(generate_ack())
            elif message['type'] == 2:  # query for content
                peers = make_peer_list(message['chunks'])
                self.request.sendall(util.encode_request(peers))
            elif message['type'] == 3:  # query for a list of files available
                file_list = files.keys()
                self.request.sendall(util.encode_request(file_list))
            elif message['type'] == 4:  # query for a specific file
                if message['filename'] in files:
                    chunk_list = files[message['filename']]
                else:
                    chunk_list = []
                self.request.sendall(util.encode_request(chunk_list))
            else:
                self.request.sendall(generate_error())
        self.request.close()


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = '172.25.107.133', 9995

    torrents = {}
    files = {}

    # Create the server, binding to localhost on port 9999
    server = ThreadedTCPServer((HOST, PORT), TCPHandler)
    server.serve_forever()
