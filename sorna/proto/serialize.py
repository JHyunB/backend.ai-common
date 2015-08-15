#! /usr/bin/env python3

from collections import OrderedDict
import base64
import json
import uuid

def odict(*args):
    '''
    A short-hand for the constructor of OrderedDict.
    :code:`odict(('a':1), ('b':2))` is equivalent to :code:`OrderedDict([('a':1), ('b':2)])`.
    '''
    return OrderedDict(args)

def msg_encode(o):
    return bytes(json.dumps(o), encoding='utf8')

def msg_decode(s):
    if isinstance(s, bytes):
        s = s.decode('utf8')
    return json.loads(s, object_pairs_hook=OrderedDict)

def generate_uuid():
    u = uuid.uuid4()
    # Strip the last two padding characters because u always has fixed length.
    return base64.urlsafe_b64encode(u.bytes)[:-2]
