#!/usr/bin/env python3
from charm.schemes.grpsig.groupsig_bgls04 import ShortSig
from VLR import VLRSig
from charm.core.engine.util import objectToBytes, bytesToObject
from datetime import datetime
from const import *
from base64 import b64decode
import pickle
import sys
import os
import time
import random
import csv
import sqlite3

def gettime():
    return datetime.strftime(datetime.now(), "%Y%m%d%H%M")

class Oracle:
    def __init__(self):
        self.group = GROUP
        self.gs_protocol = eval(GS_PROTOCOL)(self.group)
        self.path = f'parameters/{GS_PROTOCOL.lower()}'
        gpk_path = os.path.join(self.path, 'public/gpk')
        self.gpk = bytesToObject(open(gpk_path, 'rb').read(), self.group)

    def is_valid(self, msg):
        return True

    def verify(self, msg, signature, time_period, rl):
        signature = bytesToObject(signature, self.group)
        rl = [bytesToObject(rt, self.group) for rt in rl]
        if GS_PROTOCOL == 'ShortSig':
            return self.is_valid(msg) and \
                   self.gs_protocol.verify(self.gpk, msg, signature)
        elif GS_PROTOCOL == 'VLRSig':
            return self.is_valid(msg) and \
                   self.gs_protocol.verify(self.gpk, msg, signature, time_period, rl)

class School:
    def __init__(self):
        self.oracle = Oracle()
        if not os.path.exists('database.db'):
            self.conn = sqlite3.connect('database.db')
            self.cursor = self.conn.cursor()
            self.cursor.execute("CREATE TABLE datas (Building, Timestamp, Signature)")
        else:
            self.conn = sqlite3.connect('database.db')
            self.cursor = self.conn.cursor()
        self.revocation_list = []
        if GS_PROTOCOL == 'VLRSig':
            if os.path.exists('revocation_list.pkl'):
                self.revocation_list = pickle.load(open('revocation_list.pkl', 'rb'))

    def __del__(self):
        self.conn.close()

    def record(self, msg, signature):
        building, timestamp = msg.split('||')
        new_record = f'{building}, {timestamp}, {signature}\n'
        self.cursor.execute(f"INSERT INTO datas VALUES ('{building}','{timestamp}','{signature}')")
        self.conn.commit()

    def verify(self, msg_sig):
        msg, signature = msg_sig.split(',')
        building, timestamp = msg.split('||')
        current_day = datetime.strptime(timestamp, "%Y%m%d%H%M").date()
        initial_day = datetime.strptime("20200101", "%Y%m%d").date()
        time_period = (current_day - initial_day).days
        if self.oracle.verify(msg, signature, time_period, self.revocation_list):
            self.record(msg, signature)
            return True
        else:
            return False

    def send_records(self, today = datetime.now().date()):
        records = []
        record_cnt = 0
        for record in self.cursor.execute("SELECT * FROM datas ORDER BY Timestamp"):
            timestamp = record[TIMESTAMP_INDEX]
            dataday = datetime.strptime(timestamp, "%Y%m%d%H%M").date()
            if 0 <= (today - dataday).days < 14:
                record_cnt += 1
                records.append(record)
        print(record_cnt)
        for record in records:
            print(record)

    def update_revocation_list(self, revocation_list):
        pickle.dump(revocation_list, open('revocation_list.pkl', 'wb'))
        

if __name__ == '__main__':
    school = School()
    msg_type = input().strip()
    if msg_type == "INFECTED":
        school.send_records()
    elif msg_type == "AUTHENTICATE":
        msg_sig = input().strip()
        verdict = school.verify(msg_sig)
        if verdict:
            print('OK')
        else:
            print('NO')
    elif msg_type == "UPDATE":
        revocation_list = pickle.loads(b64decode(input().strip().encode()))
        school.update_revocation_list(revocation_list)
