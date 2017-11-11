# pytorrent-tracker.py
# A bittorrent tracker

from threading import Thread
from socket import inet_aton
import socket
import SocketServer
import json
import util
from Queue import Queue

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


def add_peer(info_hash, pid):
    """ Add the peer to the peer list. """

    # If the file exists in the file list, just add the peer
    if info_hash in torrents:
        # Only add the peer if they're not already in the database
        if pid not in torrents[info_hash]:
            torrents[info_hash].append(pid)
    # Otherwise, add the info_hash and the peer
    else:
        torrents[info_hash] = [pid]


def delete_peer(pid):
    for info_hash, value in torrents.items():
        if pid in value:
            value.remove(pid)
        if value is []:
            torrents.pop(info_hash, None)
            data = info_hash.split(':')
            delete_file_chunk(data[1], int(data[3]))


# def expand_peer_list(peer_list):
#     """ Return an expanded peer list suitable for the client, given the peer list. """
#
#     peers = []
#     for peer in peer_list:
#         p = dict()
#         p["pid"] = int()
#         peers.append(p)
#     return peers


def make_peer_list(file_chunks):
    peer_list = dict()
    for info_hash in file_chunks:
        peer_list[info_hash] = torrents[info_hash]
    print(peer_list)
    return peer_list


def generate_ack():
    message = {'message': 'successful'}
    ack = json.dumps(message)
    return ack.encode('utf8')


def generate_error():
    message = {'message': 'invalid type'}
    error = json.dumps(message)
    return error.encode('utf8')


def indicate_interest_loop(pid, skt):
    while True:
        interest = queues[pid].get(True)
        encoded = util.encode_request(interest)
        length = len(encoded)
        # print(encoded + " length " + ('%16s' % length))
        skt.sendall(('%16s' % length).encode('utf-8'))
        skt.sendall(encoded)


class TCPHandler(SocketServer.BaseRequestHandler):
    def handle(self):

        # self.request is the TCP socket connected to the client
        length = int(self.request.recv(16).decode('utf-8'))
        print("Data length: " +  str(length))

        data = ""
        while len(data) < length:
            newdata = self.request.recv(1024)
            data += newdata

        message = util.decode_request(data)

        if 'type' not in message:
            self.request.sendall(generate_error())
        else:
            if message['type'] == 0:  # exit the network
                delete_peer(message['pid'])
                print('Peer exits')
                self.request.sendall(generate_ack())
                print('Type 0')
            elif message['type'] == 1:  # inform and update
                temp = 0
                print_chunks_list = []
                if 'chunk_num' in message.keys():
                    message['filename'] = message['chunk_num']
                for chunk in message['chunks']:
                    if temp == 0:
                        print('Peer ' + str(message["pid"]) + ' updating the chunk he/she has: ')
                    add_peer(chunk, message["pid"])
                    data = chunk.split(':')
                    print_chunks_list.append(int(data[3]))
                    add_file_chunk(data[1], int(data[3]))
                    temp = temp + 1
                print(print_chunks_list)
                # print(files)
                # print(torrents)
                self.request.sendall(generate_ack())
            elif message['type'] == 2:  # query for content
                peers = make_peer_list(message['chunks'])
                print('Peer requesting chunks...')
                data = util.encode_request(peers)
                self.request.sendall(('%16s' % (len(data))).encode('utf-8'))
                self.request.sendall(data)
            elif message['type'] == 3:  # query for a list of files available
                file_list = files.keys()
                self.request.sendall(util.encode_request(file_list))
            elif message['type'] == 4:  # query for a specific file
                if message['filename'] in files:
                    chunk_list = files[message['filename']]
                else:
                    chunk_list = []
                self.request.sendall(util.encode_request(chunk_list))
            elif message['type'] == 5:  # register
                pid = len(queues)
                queues.append(Queue())
                reply = {"pid": pid}
                self.request.send(('%16s' % (len(reply))).encode('utf-8'))
                self.request.sendall(util.encode_request(reply))
                indicate_interest_loop(pid, self.request)
            else:
                self.request.sendall(generate_error())
        self.request.close()


def udp_thread():
    udp_port = 12345
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((my_ip, udp_port))
    while True:
        data, address = sock.recvfrom(1024)
        request = util.decode_request(data)
        message = dict()
        message["ip"] = address[0]
        message["port"] = address[1]
        message["chunk_num"] = request["chunk_num"]
        message["filename"] = request["filename"]
        queues[request["pid"]].put(message, True)


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


if __name__ == "__main__":
    my_ip = ([l for l in (
            [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [
                [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in
                 [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
    HOST, TCP_PORT = my_ip, 9991

    torrents = {}
    files = {}
    queues = []

    udp = Thread(target=udp_thread)
    udp.start()

    # Create the server, binding to localhost on port 9999
    print('Running tracker...')
    print('Waiting for peers to connect...')
    server = ThreadedTCPServer((HOST, TCP_PORT), TCPHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()

    udp.join()
