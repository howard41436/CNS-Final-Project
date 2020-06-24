from charm.schemes.grpsig.groupsig_bgls04 import ShortSig
from VLR import VLRSig
from charm.core.engine.util import objectToBytes, bytesToObject
from pwn import remote, context
from datetime import datetime
from const import *
import sys
import os
import random

context.log_level = 'error'

def gettime():
    return datetime.strftime(datetime.now(), "%Y%m%d%H%M")

class Oracle:
    def __init__(self, uid):
        self.group = GROUP
        self.gs_protocol = eval(GS_PROTOCOL)(self.group)
        self.path = f'parameters/{GS_PROTOCOL.lower()}'
        gpk_path = os.path.join(self.path, 'public/gpk')
        self.gpk = bytesToObject(open(gpk_path, 'rb').read(), self.group)
        sk_path = os.path.join(self.path, f'users/{uid:02d}/sk')
        self.sk = bytesToObject(open(sk_path, 'rb').read(), self.group)

    def sign(self, msg, time_period):
        if GS_PROTOCOL == "ShortSig":
            signature = self.gs_protocol.sign(self.gpk, self.sk, msg)
        elif GS_PROTOCOL == "VLRSig":
            signature = self.gs_protocol.sign(self.gpk, self.sk, time_period, msg)
        return objectToBytes(signature, self.group)

class Student:
    def __init__(self, uid):
        self.oracle = Oracle(uid)
        self.uid = uid
        self.school = remote(SCHOOL_IP, SCHOOL_PORT)

    def __del__(self):
        self.school.close()

    def authenticate(self, msg, signature):
        self.school.sendline("AUTHENTICATE")
        payload = f'{msg},{signature.decode()}'.encode()
        self.school.sendline(payload)
        return self.school.recvline().decode().strip() == 'OK'

    def enter_building(self, build, current_time):
        msg = f'{build}||{current_time}'
        current_day = datetime.strptime(current_time, "%Y%m%d%H%M").date()
        initial_day = datetime.strptime("20200101", "%Y%m%d").date()
        time_period = (current_day - initial_day).days
        signature = self.oracle.sign(msg, time_period)
        verdict = self.authenticate(msg, signature)
        return verdict

if __name__ == '__main__':
    uid = int(input('Please enter your student id: '))
    student = Student(uid)
    print('Please enter the building you are entering:')
    for k in BUILDINGS:
        print(f'{k}) {BUILDINGS[k]}')
    building = int(input())
    current_time = input('Please enter the time now (press <ENTER> for current system time): ')
    if not current_time.strip():
        current_time = gettime()
    verdict = student.enter_building(BUILDINGS[building], current_time)
    if verdict:
        print('Entered the building successfully.')
    else:
        print('You are rejected.')
