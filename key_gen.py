from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.PKSig import PKSig
from charm.schemes.grpsig.groupsig_bgls04 import ShortSig
from charm.core.engine.util import objectToBytes, bytesToObject
import os
import pickle
group = PairingGroup('MNT224')
USER_NUM = 100
oracle = ShortSig(group)
(gpk, gmsk, sks) = oracle.keygen(USER_NUM)

path = 'parameters/shortsig'

os.makedirs(f'{path}/public', exist_ok = True)
os.makedirs(f'{path}/gm', exist_ok = True)
for i in range(100):
    os.makedirs(f'{path}/users/{i:02d}', exist_ok = True)

open(f'{path}/public/gpk', 'wb').write(objectToBytes(gpk, group))
open(f'{path}/gm/gmsk', 'wb').write(objectToBytes(gmsk, group))
identity = {}
for i in range(USER_NUM):
    sk = objectToBytes(sks[i], group)
    identity[sk] = i
    open(f'{path}/users/{i:02d}/sk', 'wb').write(sk)
pickle.dump(identity, open(f'{path}/gm/identity.pkl', 'wb'))