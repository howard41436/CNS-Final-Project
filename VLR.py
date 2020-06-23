from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.PKSig import PKSig
from charm.core.engine.util import objectToBytes, bytesToObject
import bitarray  #pip3 install bitarray
import random

debug=False
class VLRSig(PKSig):
    def __init__(self, groupObj):
        PKSig.__init__(self)
        global group
        group = groupObj

    def keygen(self, n=0, time=100, lamb=10):
        g1, g2 = group.random(G1), group.random(G2)
        g1_til = group.random(G1)
        g1_hat = group.random(G1)

        gamma = group.random(ZR)
        w = g2 ** gamma
        T1 = pair(g1, g2)
        T2 = pair(g1_til, g2)
        T3 = pair(g1_hat, g2)
        T4 = pair(g1_hat, w)
        order = group.order()
        want_order = group.init(ZR, (order-1)//2)
        unit = group.init(ZR, 1)
        h = []
        for i in range(time):
            while True:
                hh = group.random(ZR)
                if hh**want_order == unit:
                    h.append(hh)
                    break
        gpk = { 'g1':g1, 'g2':g2, 'g1t':g1_til, 'g1h':g1_hat, 'w':w, 
                'T1':T1, 'T2':T2, 'T3':T3, 'T4':T4, 'lambda':lamb, 'h':h }
        gmsk = { 'gamma':gamma }

        if n==0:
            return (gpk, gmsk)
        else:
            f = [group.random(ZR) for i in range(n)]             # User's private key, only stored by user
            F = [g1_til**f[i] for i in range(n)]                 # User's identity, only stored by group manager
            x = [group.random(ZR) for i in range(n)]             # User's credential, stored by both
            A = [(g1*F[i]) ** ~(gamma + x[i]) for i in range(n)] # User's credential, stored by both
            
            gsk = [{ 'f': f[i], 'F': F[i], 'A': A[i], 'x': x[i] } for i in range(n)]
            return (gpk, gmsk, gsk)
    
    def sign(self, gpk, gsk, j, M):
        g1, g2, g1h, T1, T2, T3, T4, lamb, h_j = (gpk['g1'], gpk['g2'], gpk['g1h'], gpk['T1'],          
                                                gpk['T2'], gpk['T3'], gpk['T4'], gpk['lambda'], gpk['h'][j])
        f, A, x = gsk['f'], gsk['A'], gsk['x']
        B = group.random(G1)
        J = B**f
        K = B**x
        L = B**(h_j**x)
        a = group.random(ZR)
        b = a*x
        T = A*(g1h**a)
        rf = group.random(ZR)
        rx = group.random(ZR)
        ra = group.random(ZR)
        rb = group.random(ZR)
        r = [group.random(ZR) for i in range(lamb)]
        R1 = B**rf
        R2 = B**rx
        R3 = (pair(T, g2)**(-rx))*(T2**rf)*(T3**rb)*(T4**ra)
        R4 = (K**ra)*(B**(-rb))
        V = [B**r[i] for i in range(lamb)]
        W = [B**(h_j**r[i]) for i in range(lamb)]
        
        for i in range(lamb):
            print(i, V[i])
        
        c = group.hash((B, J, K, L, T, R1, R2, R3, R4, j, M), ZR)
        d = [c]
        for i in range(lamb):
            d.append(V[i])
            d.append(W[i])
        d = group.hash(tuple(d), ZR)
        bytes_d = objectToBytes(d, group)
        sf = rf + c*f
        sx = rx + c*x
        sa = ra + c*a
        sb = rb + c*b
        ba = bitarray.bitarray()
        ba.frombytes(bytes_d)
        s = [int(r[i])-ba[i]*int(x) for i in range(lamb)]
        Q = h_j**x
        '''
        for i in range(lamb):
            #print(i, ba[i], r[i], s[i]+x)
            print(i, h_j**(s[i]+x), (h_j**(s[i])*(h_j**x)))
        
        #W_ = [L**(h_j**s[i]) for i in range(lamb)]
        W__ = [((B**(1-ba[i]))*(L**ba[i]))**(h_j**s[i]) for i in range(lamb)]
        
        for i in range(lamb):
            print(i, ba[i], W__[i])
        '''
        
        sigma = {'B':B, 'J':J, 'K':K, 'L':L, 'T':T, 'c':c, 
                'd':d, 'sf':sf, 'sx':sx, 'sa':sa, 'sb':sb, 's':s}
        return sigma

    def verify(self, gpk, M, sigma, j, RL):
        g2, w, T1, T2, T3, T4, lamb, h_j = (gpk['g2'], gpk['w'], gpk['T1'], gpk['T2'], 
                                            gpk['T3'], gpk['T4'], gpk['lambda'], gpk['h'][j])
        B, J, K, L, T, c, d, sf, sx, sa, sb, s = (sigma['B'], sigma['J'], sigma['K'], sigma['L'], sigma['T'], sigma['c'], 
                                                sigma['d'], sigma['sf'], sigma['sx'], sigma['sa'], sigma['sb'], sigma['s'])
        R1_ = (B**sf)*(J**(-c))
        R2_ = (B**sx)*(K**(-c))
        R3_ = (pair(T, g2)**(-sx))*(T2**sf)*(T3**sb)*(T4**sa)*(T1**c)*(pair(T, w)**(-c))
        R4_ = (K**sa)*(B**(-sb))
        c_ = group.hash((B, J, K, L, T, R1_, R2_, R3_, R4_, j, M), ZR)
        if c!=c_:
            print('c=', c)
            print('c_=', c_)
            return False
        bytes_d = objectToBytes(d, group)
        ba = bitarray.bitarray()
        ba.frombytes(bytes_d)
        V_ = [(B**s[i])*(K**ba[i]) for i in range(lamb)]
        W_ = [((B**(1-ba[i]))*(L**ba[i]))**(h_j**s[i]) for i in range(lamb)]
        
        for i in range(lamb):
            print(i, ba[i], V_[i])
        '''
        for i in range(lamb):
            print(i, L**(h_j**s[i]))
        '''
        d_ = [c]
        for i in range(lamb):
            d_.append(V_[i])
            d_.append(W_[i])
        d_ = group.hash(tuple(d_), ZR)
        if d!=d_:
            print('d=', d)
            print('d_=', d_)
            return False
        for rt in RL:
            if L == B**rt:
                print('rt=', rt)
                return False
        return True

    def open(self, gpk, gsk, sigma, j):
        h_j = gpk['h'][j]
        B, L = sigma['B'], sigma['L']
        for i in range(len(gsk)):
            if L == B**(h_j**gsk[i]['x']):
                return {'token': gsk[i]['x'], 'identity': gsk[i]['F']}
        return None

    def revoke(self, gpk, rl, j):
        h_j = gpk['h'][j]
        RL = []
        for rt in rl:
            RL.append(h_j**rt)
        return RL

if __name__=='__main__':
    group = PairingGroup('MNT224')
    n = 3
    user = 1
    total_time = 100
    safe_paremeter = 10
    vlrsig = VLRSig(group)
    (global_public_key, global_master_secret_key, user_secret_keys) = vlrsig.keygen(n, total_time, safe_paremeter)
    #print(user_secret_keys[user])
    revoke_credential_list = []
    time_period = 0
    time_token = global_public_key['h'][time_period]
    #print(time_token)
    revoke_token_list = vlrsig.revoke(global_public_key, revoke_credential_list, time_period)
    msg = 'Hello World this is a message!'
    signature = vlrsig.sign(global_public_key, user_secret_keys[user], time_period, msg)
    valid = vlrsig.verify(global_public_key, msg, signature, time_period, revoke_token_list)
    print(valid)
    find_user = vlrsig.open(global_public_key, user_secret_keys, signature, time_period)
    revoke_credential_list.append(find_user['token'])
    #tomorrow
    '''
    time_period = 1
    revoke_token_list = vlrsig.revoke(global_public_key, revoke_credential_list, time_period)
    msg = 'Hello World this is a message!'
    signature = vlrsig.sign(global_public_key, user_secret_keys[user], time_period, msg)
    valid = vlrsig.verify(global_public_key, msg, signature, time_period, revoke_token_list)
    print(valid)
    '''