# util.py
# A small collection of useful functions
import json


def collapse(data):
    result = ''
    for x in data:
        result = result + x
    return result


def slice_str(string, n):
    """ Given a string and a number n, cuts the string up, returns a
    list of strings, all size n. """

    temp = []
    i = n
    while i <= len(string):
        temp.append(string[(i - n):i])
        i += n

    try:  # Add on any stragglers
        if string[(i - n)] != "":
            temp.append(string[(i - n):])
    except IndexError:
        pass

    return temp


def decode_request(message):
    """ Return the decoded request string. """
    b = b''
    b += message
    data = json.loads(b)
    return data


def encode_request(message):
    data = json.dumps(message)
    return data.encode('utf8')
