#!/usr/bin/env python3
from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.grpsig.groupsig_bgls04 import ShortSig
from charm.core.engine.util import objectToBytes, bytesToObject
from pwn import remote
import sys
import os
import time
import datetime
import random
import csv

BUILDINGS = {1: "DerTian", 2: "MingDa", 3: "XiaoFu"}
GS_PROTOCOL = 'ShortSig'
GROUP = PairingGroup('MNT224')
RID_MAX = 10 ** 10

def gettime():
    return time.strftime("%Y%m%d%H%M", time.localtime(time.time()))

class Oracle:
    def __init__(self):
        self.group = PairingGroup('MNT224')
        self.gs_protocol = eval(GS_PROTOCOL)(self.group)
        self.path = f'parameters/{GS_PROTOCOL.lower()}'
        gpk_path = os.path.join(self.path, 'public/gpk')
        self.gpk = bytesToObject(open(gpk_path, 'rb').read(), self.group)

    def is_valid(self, msg):
        return True

    def verify(self, msg, signature):
        signature = bytesToObject(signature, self.group)
        return self.is_valid(msg) and \
               self.gs_protocol.verify(self.gpk, msg, signature)

class School:
    def __init__(self):
        self.oracle = Oracle()

    def record(self, msg, signature):
        building, timestamp = msg.split('||')
        rid = random.randrange(RID_MAX)
        new_record = f'{rid}, {building}, {timestamp}, {signature}\n'
        if not os.path.exists('database.csv'):
            header = 'rid, building, timestamp, signature\n'
            open('database.csv', 'w').write(header)
        open('database.csv', 'a').write(new_record)

    def verify(self, msg_sig):
        msg, signature = msg_sig.split(',')
        if self.oracle.verify(msg, signature):
            self.record(msg, signature)
            return True
        else:
            return False
    
    def read_database(self):
        return csv.reader(open('database.csv','r', newline=''))

    def send_data_to_cdc(self):
        current_time = gettime()
        current_time = f'{current_time[:4]}-{current_time[4:6]}-{current_time[6:8]}'
        today = datetime.datetime.strptime(current_time,'%Y-%m-%d')
        #today = datetime.date(int(current_time[:4]), current_time[4:6], int(current_time[6:8]))
        database = self.read_database()
        # skip header
        next(database)
        buf_data = []
        cnt = 0
        for data in database:
            data[2] = data[2].strip()
            tmp = f'{data[2][:4]}-{data[2][4:6]}-{data[2][6:8]}'
            dataday = datetime.datetime.strptime(tmp,'%Y-%m-%d')
            #dataday = datetime.date(int(data[2][:4]), int(data[2][4:6]), int(data[2][6:8]))
            if (today - dataday).days <= 14:
                cnt += 1
                buf_data.append(data)
        print(str(cnt))
        for data in buf_data:
            print(str(data))

if __name__ == '__main__':
    school = School()
    msg_sig = input()
    # msg from cdc
    if msg_sig == "INFECTED":
        school.send_data_to_cdc()
    else:
        verdict = school.verify(msg_sig)
        if verdict:
            print('OK')
        else:
            print('NO')
