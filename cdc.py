from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.PKSig import PKSig
from charm.schemes.grpsig.groupsig_bgls04 import *
from charm.core.engine.util import objectToBytes, bytesToObject
import os
import sys
import socket
import signal
import pickle
import csv

BUILDINGS = {1: "DerTian", 2: "MingDa", 3: "XiaoFu"}
GS_PROTOCOL = 'ShortSig'
GROUP = PairingGroup('MNT224')
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

class Oracle:
    def __init__(self):
        self.group = PairingGroup('MNT224')
        self.gs_protocol = eval(GS_PROTOCOL)(self.group)
        self.path = f'parameters/{GS_PROTOCOL.lower()}'
        gpk_path = os.path.join(self.path, 'public/gpk')
        self.gpk = bytesToObject(open(gpk_path, 'rb').read(), self.group)
        gmsk_path = os.path.join(self.path, 'gm/gmsk')
        self.gmsk = bytesToObject(open(gmsk_path, 'rb').read(), self.group)
        dic_path = os.path.join(self.path, 'gm/identity.pkl')
        self.dic = pickle.load(open(dic_path, 'rb'))
    def open(self, msg, signature):
        #signature = bytesToObject(signature, self.group)
        return self.gs_protocol.open(self.gpk, self.gmsk, msg, signature)
class Cdc:
    def __init__(self):
        self.oracle = Oracle()
    def read_database(self):
        return csv.reader(open('database.csv','r',newline=''))
    def find_patient_footprint(self, data, sickuid):
        signature = data[3]
        msg = f'{data[1]}||{data[2]}'
        identifier = self.oracle.open(msg,signature)
        identity = self.oracle.dic[identifier]
        for i in sickuid:
            if i == identity:
                return 1
        return 0


if __name__ == '__main__':
    init()
    cdc = Cdc()
    patient_number = int(input('How many patients today? '))
    sickuid=[]
    print("please enter the patient's uid: ")
    for i in range(patient_number):
        sickuid.append(int(input()))
    database = cdc.read_database()
    for data in database:
        danger = cdc.find_patient_footprint(data,sickuid)
        if danger:
            print(f'{data[1]}, {data[2]}')
            
              
'''
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

'''    
