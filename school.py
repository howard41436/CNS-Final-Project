from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.PKSig import PKSig
from charm.schemes.grpsig.groupsig_bgls04 import *
import sys
import socket
import time
import os
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
    print('This is a school server')

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('$python3 school.py hostname port')
        exit(0)
    init()
    #build socket with cdc
    buf = input('{cdc ip} {cdc port} : ')
    hostname_cdc = buf.split()[0]
    port_cdc = int( buf.split()[1] )
    addr_cdc = (hostname_cdc, port_cdc)

    sch2cdc = socket.socket()
    sch2cdc.connect(addr_cdc)
    print('successfully build connection')
    #send pid
    msg = str( os.getpid())
    sch2cdc.send(msg.encode())
    
    #build socket with visitors
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
    while True:
        try: 
            usr, usr_addr = srv.accept()
            print(f'new visitor from {usr_addr}\n {usr}')
            # non-blocking 
            usr.setblocking(False)
            usrs.append(usr)
        except:
            pass
            
        for usr in usrs:
            try:
                msg = usr.recv(1024).decode().strip()
                print(msg)
                sig = dict( usr.recv(1024).decode() )
                print(sig)
                #usr.send('')
                usr.close()
                usrs.remove(usr)
            except:
                pass




