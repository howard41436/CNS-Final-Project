from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.PKSig import PKSig
from charm.schemes.grpsig.groupsig_bgls04 import *
import pickle
"""
>>> group = PairingGroup('MNT224')
>>> n = 3    # how manu users are in the group
>>> user = 1 # which user's key we will sign a message with
>>> shortSig = ShortSig(group)
>>> (global_public_key, global_master_secret_key, user_secret_keys) = shortSig.keygen(n)
>>> msg = 'Hello World this is a message!'
>>> signature = shortSig.sign(global_public_key, user_secret_keys[user], msg)
>>> shortSig.verify(global_public_key, msg, signature)
True
"""
group = PairingGroup('MNT224')
n = 100    # how manu users are in the group
shortSig = ShortSig(group)
(global_public_key, global_master_secret_key, user_secret_keys) = shortSig.keygen(n)

#f = open("keygendata.py",'w')
#f.write(f'global_public_key={global_public_key}\nglobal_master_secret_key={global_master_secret_key}\nuser_secret_keys={user_secret_keys}')

