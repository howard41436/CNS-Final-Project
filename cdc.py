#!/usr/bin/env python3
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.PKSig import PKSig
from charm.schemes.grpsig.groupsig_bgls04 import *
from charm.core.engine.util import objectToBytes, bytesToObject
from pwn import remote
import os
import sys
import socket
import signal
import pickle
import csv

BUILDINGS = {1: "DerTian", 2: "MingDa", 3: "XiaoFu"}
GS_PROTOCOL = 'ShortSig'
GROUP = PairingGroup('MNT224')
SCHOOL_IP = '127.0.0.1'
SCHOOL_PORT = 8989
RID_INEDX = 0
BUILDING_INDEX = 1
TIMESTAMP_INDEX = 2
SIGNATURE_INDEX = 3

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
        signature = bytesToObject(signature, self.group)
        return self.gs_protocol.open(self.gpk, self.gmsk, msg, signature)
class Cdc:
    def __init__(self):
        self.oracle = Oracle()
        self.school = remote(SCHOOL_IP, SCHOOL_PORT)
    def read_database(self):
        return csv.reader(open('database_cdc.csv','r', newline=''))
    def find_patient_footprint(self, data, sickuid):
        signature = data[SIGNATURE_INDEX].strip()
        msg = f'{data[BUILDING_INDEX].strip()}||{data[TIMESTAMP_INDEX].strip()}'
        identifier = objectToBytes(self.oracle.open(msg,signature), self.oracle.group)
        identity = self.oracle.dic[identifier]
        return (sickuid.count(identity) > 0)
    def waiting_infected_event(self):
        while True:
            msg = input('Type aaa to trigger a infected event !! ')
            if msg.strip() == "aaa":
                self.school.sendline("INFECTED")
                break
    def recv_school_data(self):
        num = int( self.school.recvline().decode().strip() )
        for i in range(num):
            if not os.path.exists('database_cdc.csv'):
                header = 'rid, building, timestamp, signature\n'
                open('database_cdc.csv', 'w').write(header)
            data = self.school.recvline().decode()
            open('database_cdc.csv', 'a').write(data)

if __name__ == '__main__':
    cdc = Cdc()
    cdc.waiting_infected_event()
    cdc.recv_school_data()

    patient_number = int(input('How many patients today? '))
    sickuid=[]
    print("please enter the patient's uid: ", end ='')
    for i in range(patient_number):
        sickuid.append(int(input()))
    database = cdc.read_database()
    # skip header
    next(database)
    for data in database:
        danger = cdc.find_patient_footprint(data,sickuid)
        if danger:
            print(f'{data[BUILDING_INDEX]}, {data[TIMESTAMP_INDEX]}')
