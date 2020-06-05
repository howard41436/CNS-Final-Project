from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.PKSig import PKSig
from charm.schemes.grpsig.groupsig_bgls04 import *
import sys
import socket
import key_gen
import time 
import random
import pickle
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

building = {1:"DerTian", 2:"MingDa", 3:"XiaoFu"}

def random_date():
    a1=(2020,1,1,0,0,0,0,0,0)       #設定開始日期時間元組（1976-01-01 00：00：00）
    a2=(2020,12,31,23,59,59,0,0,0)  #設定結束日期時間元組（1990-12-31 23：59：59）
    start=time.mktime(a1)  #生成開始時間戳
    end=time.mktime(a2)   #生成結束時間戳
    #隨機生成10個日期字串
    t=random.randint(start,end)  #在開始和結束時間戳中隨機取出一個
    date_touple=time.localtime(t)     #將時間戳生成時間元組
    date=time.strftime("%Y-%m-%d",date_touple) #將時間元組轉成格式化字串（1976-05-21）
    return date

def init():
    print('This is a card reader')

if __name__ == '__main__':
    group = PairingGroup('MNT224')
    shortSig = ShortSig(group)
    init()
    buf = "init"
    while True:
        #build socket to school
        if buf != "init":
            tmp = input('type ''r'' to re-connect to previous connection')
            if tmp != "r":
                buf = input('{school ip} {school port} : ')
        else:
            buf = input('{school ip} {school port} : ')
        hostname = buf.split()[0]
        port = int( buf.split()[1] )
        addr = (hostname, port)

        vstr = socket.socket()
        vstr.connect(addr)
        print('successfully build connection')
        #send msg
        user=0
        while True:
            rd = random.randint(1,3)
            user = random.randint(0,99)
            msg = str(user)+"||"+building[rd]+"||"+random_date()
            print("simulate a visitor went to a building : ")
            print(msg)
            tmp = input('n=select again y=confirm : ')
            if tmp == "y":
                break
        signature = shortSig.sign(key_gen.global_public_key, key_gen.user_secret_keys[user], msg)
        #print(signature,type(signature['c']))
        vstr.send(msg.encode())
        # Save the file
        pickle.dump(signature, file = open("sig.pickle", "wb"))
        # Reload the file
        sig = pickle.load(open("sig.pickle", "rb"))
        vstr.send(sig)
        vstr.close() 
