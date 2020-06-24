from charm.schemes.grpsig.groupsig_bgls04 import ShortSig
from VLR import VLRSig
from charm.core.engine.util import objectToBytes, bytesToObject
from pwn import remote, context
from datetime import datetime
from base64 import b64encode
from const import *
import sys
import os
import pickle
import csv

def gettime():
    return datetime.strftime(datetime.now(), "%Y%m%d%H%M")

class Oracle:
    def __init__(self):
        self.group = GROUP
        self.gs_protocol = eval(GS_PROTOCOL)(self.group)
        self.path = f'parameters/{GS_PROTOCOL.lower()}'
        gpk_path = os.path.join(self.path, 'public/gpk')
        self.gpk = bytesToObject(open(gpk_path, 'rb').read(), self.group)
        gmsk_path = os.path.join(self.path, 'gm/gmsk')
        self.gmsk = bytesToObject(open(gmsk_path, 'rb').read(), self.group)
        if GS_PROTOCOL == 'ShortSig':
            dic_path = os.path.join(self.path, 'gm/identity.pkl')
            self.dic = pickle.load(open(dic_path, 'rb'))
        elif GS_PROTOCOL == 'VLRSig':
            tokens_path = os.path.join(self.path, 'gm/tokens')
            self.tokens = bytesToObject(open(tokens_path, 'rb').read(), self.group)

    def open(self, msg, signature, time_period):
        signature = bytesToObject(signature, self.group)
        if GS_PROTOCOL == 'ShortSig':
            identifier =  self.gs_protocol.open(self.gpk, self.gmsk, msg, signature)
            identity = self.dic[objectToBytes(identifier, self.group)]
        if GS_PROTOCOL == 'VLRSig':
            identity = self.gs_protocol.open(self.gpk, self.tokens, signature, time_period)
        return identity

    def revoke(self, rl, j):
        RL = self.gs_protocol.revoke(self.gpk, self.tokens, rl, j)
        RL = [objectToBytes(rt, self.group) for rt in RL]
        return RL

class CDC:
    def __init__(self):
        self.oracle = Oracle()
        self.school = remote(SCHOOL_IP, SCHOOL_PORT)
        self.records = []
        self.patient_list = []
        self.patient_footprint = []
        self.risk_day_building = set()
        self.quarantine_list = []
        if GS_PROTOCOL == 'VLRSig':
            self.revocation_lists = [[] for _ in range(TOTAL_TIME)]
            if os.path.exists('revocation_lists.pkl'):
                self.revocation_lists = pickle.load(open('revocation_lists.pkl', 'rb'))

    def __del__(self):
        self.school.close()

    def trigger_diagnosed_event(self, patient_list):
        self.school.sendline("INFECTED")
        self.patient_list = patient_list
        self.recv_records()
        self.find_patient_footprint()
        self.find_quarantine_list()
        revoke_identity_list = self.patient_list + self.quarantine_list
        if GS_PROTOCOL == 'VLRSig':
            timestamp = gettime()
            current_day = datetime.strptime(timestamp, "%Y%m%d%H%M").date()
            initial_day = datetime.strptime("20200101", "%Y%m%d").date()
            time_period = (current_day - initial_day).days
            for j in range(time_period, time_period + QUARANTINE_DAYS + 1):
                rl = self.oracle.revoke(revoke_identity_list, j)
                self.revocation_lists[j] += rl
                self.revocation_lists[j] = list(set(self.revocation_lists[j]))

            pickle.dump(self.revocation_lists, open('revocation_lists.pkl', 'wb'))

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
            current_day = datetime.strptime(timestamp, "%Y%m%d%H%M").date()
            initial_day = datetime.strptime("20200101", "%Y%m%d").date()
            time_period = (current_day - initial_day).days
            identity = self.oracle.open(msg, signature, time_period)
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
                current_day = datetime.strptime(timestamp, "%Y%m%d%H%M").date()
                initial_day = datetime.strptime("20200101", "%Y%m%d").date()
                time_period = (current_day - initial_day).days
                identity = self.oracle.open(msg, signature, time_period)
                if not identity in self.patient_list:
                    quarantine_set.add(identity)
        self.quarantine_list = list(quarantine_set)

    def send_revocation_list(self):
        self.school.sendline("UPDATE")
        timestamp = gettime()
        current_day = datetime.strptime(timestamp, "%Y%m%d%H%M").date()
        initial_day = datetime.strptime("20200101", "%Y%m%d").date()
        time_period = (current_day - initial_day).days
        rl = self.revocation_lists[time_period]
        self.school.sendline(b64encode(pickle.dumps(rl)))

if __name__ == '__main__':
    cdc = CDC()
    choice = 2
    if GS_PROTOCOL == 'VLRSig':
        print("Please choose the operation:")
        print("1) send today's revocation list to school.")
        print("2) trigger a diagnosed event.")
        choice = int(input())
    if choice == 1:
        cdc.send_revocation_list()
    elif choice == 2:
        line = input("Please enter the student id of the patients (separated by comma): ")
        patient_list = list(map(int, line.split(',')))
        patient_footprint, quarantine_list = cdc.trigger_diagnosed_event(patient_list)
        print('Patient footprint:', *patient_footprint, sep = '\n')
        print('Quarantine list:')
        print(quarantine_list)
    else:
        print('Invalid option.')
    