from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.PKSig import PKSig
from charm.schemes.grpsig.groupsig_bgls04 import *

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
if __name__ == '__main__':
    #define parameters
    n = 10    # Numbers of user in the group
 
    group = PairingGroup('MNT224')
    shortSig = ShortSig(group)
    (public_key, master_secret_key, user_secret_keys) = shortSig.keygen(n)
    msg = 'Hello World'
    user = 1
    signature = shortSig.sign(public_key, user_secret_keys[user], msg)
    print(shortSig.verify(public_key, msg, signature))
