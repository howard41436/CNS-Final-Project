from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.grpsig.groupsig_bgls04 import ShortSig
from charm.core.engine.util import objectToBytes, bytesToObject
from pwn import remote
import sys
import os
import time
import random

BUILDINGS = {1: "DerTian", 2: "MingDa", 3: "XiaoFu"}
GS_PROTOCOL = 'ShortSig'
GROUP = PairingGroup('MNT224')
SCHOOL_IP = '127.0.0.1'
SCHOOL_PORT = 8989

def gettime():
    return time.strftime("%Y%m%d%H%M", time.localtime(time.time()))

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
        payload = f'{msg},{signature.decode()}'.encode()
        self.school.sendline(payload)
        return self.school.recvline().decode().strip() == 'OK'

    def enter_building(self, build, current_time):
        #current_time = gettime()
        msg = f'{build}||{current_time}'
        signature = self.oracle.sign(msg)
        verdict = self.authenticate(msg, signature)
        return verdict
    def gettime(self):
        # can define by yourself
        
        # key by yourself
        Time = input('%Y%m%d%H%M (12 chars ex.202012290123) ').strip()
        if len(Time) != 12:
            exit()
        # random
        ''' 
        a1 = (2020,1,1,0,0,0,0,0,0)
        a2 = (2020,6,30,23,59,59,0,0,0)
        start = time.mktime(a1)
        end = time.mktime(a2)
        date_touple = time.localtime(random.randint(start, end))
        Time =  time.strftime("%Y%m%d%H%M", date_touple)
        '''
        return Time

if __name__ == '__main__':
    uid = int(input('Please enter your student id: '))
    student = Student(uid)
    print('Please enter the building you are entering:')
    for k in BUILDINGS:
        print(f'{k}) {BUILDINGS[k]}')
    building = int(input())
    current_time = student.gettime()
    verdict = student.enter_building(BUILDINGS[building], current_time)
    if verdict:
        print('Entered the building successfully.')
    else:
        print('You are rejected.')
