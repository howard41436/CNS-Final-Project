from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.grpsig.groupsig_bgls04 import ShortSig
from charm.core.engine.util import objectToBytes, bytesToObject
from pwn import remote, context
from datetime import datetime
import sys
import os
import pickle
import csv

BUILDINGS = {1: "DerTian", 2: "MingDa", 3: "XiaoFu"}
GS_PROTOCOL = 'ShortSig'
GROUP = PairingGroup('MNT224')
SCHOOL_IP = '127.0.0.1'
SCHOOL_PORT = 8989
BUILDING_INDEX = 0
TIMESTAMP_INDEX = 1
SIGNATURE_INDEX = 2

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
        identifier =  self.gs_protocol.open(self.gpk, self.gmsk, msg, signature)
        identity = self.dic[objectToBytes(identifier, self.group)]
        return identity
class CDC:
    def __init__(self):
        self.oracle = Oracle()
        self.school = remote(SCHOOL_IP, SCHOOL_PORT)
        self.records = []
        self.patient_list = []
        self.patient_footprint = []
        self.risk_day_building = set()
        self.quarantine_list = []

    def trigger_diagnosed_event(self, patient_list):
        self.school.sendline("INFECTED")
        self.patient_list = patient_list
        self.recv_records()
        self.find_patient_footprint()
        self.find_quarantine_list()
        return self.patient_footprint, self.quarantine_list

    def recv_records(self):
        num = int(self.school.recvline().decode())
        for i in range(num):
            record = eval(self.school.recvline().decode())
            self.records.append(record)

    def find_patient_footprint(self):
        for record in self.records:
            building, timestamp, signature = record
            msg = f'{building}||{timestamp}'
            identity = self.oracle.open(msg, signature)
            if identity in self.patient_list:
                self.patient_footprint.append((identity, building, timestamp))
                dataday = datetime.strptime(timestamp, "%Y%m%d%H%M").date()
                self.risk_day_building.add((dataday, building))

    def find_quarantine_list(self):
        quarantine_set = set()
        for record in self.records:
            building, timestamp, signature = record
            msg = f'{building}||{timestamp}'
            dataday = datetime.strptime(timestamp, "%Y%m%d%H%M").date()
            if (dataday, building) in self.risk_day_building:
                identity = self.oracle.open(msg, signature)
                if not identity in self.patient_list:
                    quarantine_set.add(identity)
        self.quarantine_list = list(quarantine_set)

if __name__ == '__main__':
    cdc = CDC()
    line = input("Please enter the student id of the patients (separated by comma): ")
    patient_list = list(map(int, line.split(',')))
    patient_footprint, quarantine_list = cdc.trigger_diagnosed_event(patient_list)
    print('Patient footprint:', *patient_footprint, sep = '\n')
    print('Quarantine list:')
    print(quarantine_list)
    