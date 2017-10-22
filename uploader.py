from hashlib import md5, sha1
from time import time
import sys
from util import collapse, slice


CLIENT_NAME = "p2p_uploader"
CLIENT_ID = "uploader"
CLIENT_VERSION = "0001"
TRACKER_ADDR = '127.0.0.1'


def make_info_dict(file):
    """ Returns the info dictionary for a torrent file. """
    print('before open the file')
    with open(file) as f:
        contents = f.read()

    piece_length = 524288	# TODO: This should change dependent on file size

    info = {}
    info["piece length"] = piece_length
    info["length"] = len(contents)
    info["name"] = file
    info["md5sum"] = md5(contents).hexdigest()
    # Generate the pieces
    pieces = slice(contents, piece_length)
    pieces = [ sha1(p).digest() for p in pieces ]
    info["pieces"] = collapse(pieces)
    return info

def make_torrent_file(file = None):
    """ Returns the bencoded contents of a torrent file. """
    if not file:
        raise TypeError("make_torrent_file requires at least one file, non given.")

    torrent = {}
    torrent["tracker"] = TRACKER_ADDR
    torrent["creation date"] = int(time())
    torrent["created by"] = CLIENT_NAME
    torrent["info"] = make_info_dict(file)
    metaFileName = file + '.torrent'
    print('meta file name: ' + metaFileName)
    with open(metaFileName, "w") as torrent_file:
        torrent_file.write(str(torrent))

def run():
    print('starting: ')
    """ Start  generating torrent file. """
    while(True):
        print('enter file name: ')
        line = sys.stdin.readline()
        print('getting file name: ' + line)
        make_torrent_file(line.strip())
        print('finish generating torrent file')
run()
