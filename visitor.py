from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.PKSig import PKSig
from charm.schemes.grpsig.groupsig_bgls04 import *
import sys
import socket
"""
>>> group = PairingGroup('MNT224')
>>> n = 3    # how manu users are in the group
>>> user = 1 # which user's key we will sign a message with
>>> shortSig = ShortSig(group)
>>> (global_public_key, global_master_secret_key, user_secret_keys) = shortSig.keygen(n)
>>> msg = 'Hello World this is a message!'
>>> signature = shortSig.sign(global_public_key, user_secret_keys[user], msg)
>>> shortSig.verify(global_public_key, msg, signature)
True
"""
def init():
    print('This is a card reader')

if __name__ == '__main__':
    init()
    while True:
        #build socket to school
        buf = input('{school ip} {school port} : ')
        hostname = buf.split()[0]
        port = int( buf.split()[1] )
        addr = (hostname, port)

        vstr = socket.socket()
        vstr.connect(addr)
        print('successfully build connection')
        #send msg
        msg = input()
        vstr.send(msg.encode())
        vstr.close() 
