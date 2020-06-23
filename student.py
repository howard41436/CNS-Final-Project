from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.grpsig.groupsig_bgls04 import ShortSig
from charm.core.engine.util import objectToBytes, bytesToObject
from pwn import remote, context
from datetime import datetime
import sys
import os
import random

BUILDINGS = {1: "DerTian", 2: "MingDa", 3: "XiaoFu"}
GS_PROTOCOL = 'ShortSig'
GROUP = PairingGroup('MNT224')
SCHOOL_IP = '127.0.0.1'
SCHOOL_PORT = 8989
context.log_level = 'error'

def gettime():
    return datetime.strftime(datetime.now(), "%Y%m%d%H%M")

class Oracle:
    def __init__(self, uid):
        self.group = PairingGroup('MNT224')
        self.gs_protocol = eval(GS_PROTOCOL)(self.group)
        self.path = f'parameters/{GS_PROTOCOL.lower()}'
        gpk_path = os.path.join(self.path, 'public/gpk')
        self.gpk = bytesToObject(open(gpk_path, 'rb').read(), self.group)
        sk_path = os.path.join(self.path, f'users/{uid:02d}/sk')
        self.sk = bytesToObject(open(sk_path, 'rb').read(), self.group)

    def sign(self, msg):
        signature = self.gs_protocol.sign(self.gpk, self.sk, msg)
        return objectToBytes(signature, self.group)

class Student:
    def __init__(self, uid):
        self.oracle = Oracle(uid)
        self.uid = uid
        self.school = remote(SCHOOL_IP, SCHOOL_PORT)

    def authenticate(self, msg, signature):
        self.school.sendline("AUTHENTICATE")
        payload = f'{msg},{signature.decode()}'.encode()
        self.school.sendline(payload)
        return self.school.recvline().decode().strip() == 'OK'

    def enter_building(self, build, current_time):
        msg = f'{build}||{current_time}'
        signature = self.oracle.sign(msg)
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
