from hashlib import md5, sha1
from time import time
import sys
from util import collapse, slice_str
import math


CLIENT_NAME = "p2p_uploader"
CLIENT_ID = "uploader"
CLIENT_VERSION = "0001"
TRACKER_IP = '127.0.0.1'
TRACKER_PORT = 500


def make_info_dict(file):
    """ Returns the info dictionary for a torrent file. """
    print('before open the file')
    with open(file) as f:
        contents = f.read()

    piece_length = 10  # TODO: This should change dependent on file size

    info = dict()
    info["piece length"] = piece_length
    info["length"] = len(contents)
    info["chunk number"] = math.ceil(len(contents) / piece_length * 1.0)
    info["name"] = file
    info["md5sum"] = md5(contents).hexdigest()
    # Generate the pieces
    pieces = slice_str(contents, piece_length)
    pieces = [ sha1(p).digest() for p in pieces ]
    info["pieces"] = collapse(pieces)
    return info


def make_torrent_file(file = None):
    """ Returns the bencoded contents of a torrent file. """
    if not file:
        raise TypeError("make_torrent_file requires at least one file, non given.")

    torrent = dict()
    torrent["tracker"] = (TRACKER_IP, TRACKER_PORT)
    torrent["creation date"] = int(time())
    torrent["created by"] = CLIENT_NAME
    torrent["info"] = make_info_dict(file)
    meta_file_name = file + '.torrent'
    print('meta file name: ' + meta_file_name)
    with open(meta_file_name, "w") as torrent_file:
        torrent_file.write(str(torrent))


def run():
    print('starting: ')
    """ Start  generating torrent file. """
    while True:
        print('enter file name: ')
        line = sys.stdin.readline()
        print('getting file name: ' + line)
        make_torrent_file(line.strip())
        print('finish generating torrent file')


run()
