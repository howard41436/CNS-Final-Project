from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.PKSig import PKSig
from charm.schemes.grpsig.groupsig_bgls04 import *
import os
import sys
import socket
import signal
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
    print('This is a CDC')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('$python3 cdc.py hostname port')
        exit(0)
    init()
    #build socket
    hostname = sys.argv[1]
    port = int( sys.argv[2] )
    addr = (hostname, port)
    srv = socket.socket()
    try:
        srv.bind(addr)
        srv.setblocking(False)
        srv.listen(10)
    except:
        print('Build socket fail!!')
        exit(0)

    #waiting connection
    usrs=[]
    pids=[]
    while True:
        try: 
            usr, usr_addr = srv.accept()
            print(f'new school from {usr_addr}\n {usr}')
            # non-blocking 
            usr.setblocking(False)
            usrs.append(usr)
            pids.append(dict())
        except:
            pass
            
        for usr in usrs:
            try:
                msg = usr.recv(1024).decode().strip()
                print(msg)
                if not msg.isdigit():
                    print('need school pid, a digit')
                    exit(0)
                pids[usr]=int(msg)
                #usr.send('')
                #usr.close()
                #usrs.remove(usr)
            except:
                pass


