#!/usr/bin/env python3
from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.grpsig.groupsig_bgls04 import ShortSig
from charm.core.engine.util import objectToBytes, bytesToObject
from pwn import remote
import sys
import os
import time

BUILDINGS = {1: "DerTian", 2: "MingDa", 3: "XiaoFu"}
GS_PROTOCOL = 'ShortSig'
GROUP = PairingGroup('MNT224')

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

    def verify(self, msg_sig):
        msg, signature = msg_sig.split(',')
        signature = bytesToObject(signature, self.group)
        return self.is_valid(msg) and \
               self.gs_protocol.verify(self.gpk, msg, signature)

class School:
    def __init__(self):
        self.oracle = Oracle()

    def verify(self, msg_sig):
        return self.oracle.verify(msg_sig)

if __name__ == '__main__':
    school = School()
    msg_sig = input()
    verdict = school.verify(msg_sig)
    if verdict:
        print('OK')
    else:
        print('NO')
