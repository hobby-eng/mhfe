# AUD-044 fun probe: the candidates of the public container same-length-zero-12 with words 1 and 2
# missing, their BIP32 master key fingerprints computed with no code of mhfe, and the candidates that
# share one. 262,144 BIP39 seeds; the birthday bound gives about eight pairs.
import hashlib, hmac, multiprocessing, sys, json
W = open('tests/spec/scripts/bip39-english.txt').read().split()
P = 2**256 - 2**32 - 977
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
# Jacobian arithmetic, as one inverse per multiplication is far quicker.
def dbl(p):
    X,Y,Z=p
    if not Y: return (0,0,0)
    S=4*X*Y*Y%P; M=3*X*X%P
    X2=(M*M-2*S)%P
    return (X2,(M*(S-X2)-8*Y**4)%P,2*Y*Z%P)
def add(p,q):
    if not p[2]: return q
    if not q[2]: return p
    U1=p[0]*q[2]**2%P; U2=q[0]*p[2]**2%P; S1=p[1]*q[2]**3%P; S2=q[1]*p[2]**3%P
    if U1==U2:
        return dbl(p) if S1==S2 else (0,0,0)
    H=U2-U1; R=S2-S1; H2=H*H%P; H3=H*H2%P; U=U1*H2%P
    X=(R*R-H3-2*U)%P
    return (X,(R*(U-X)-S1*H3)%P,H*p[2]*q[2]%P)
TABLE=[]
q=(G[0],G[1],1)
for i in range(256):
    TABLE.append(q); q=dbl(q)
def mul(k):
    r=(0,0,0)
    for i in range(256):
        if k>>i&1: r=add(r,TABLE[i])
    z=pow(r[2],-1,P)
    return (r[0]*z*z%P, r[1]*z*z*z%P)
exec(open('../tmp/aud044/fun/independent_addresses.py').read().split('# RIPEMD-160, pure')[1].split('def keccak256')[0].split('\n',1)[1])
assert ripemd160(b'abc').hex()=='8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'
def fingerprint(phrase):
    seed=hashlib.pbkdf2_hmac('sha512',phrase.encode(),b'mnemonic',2048)
    I=hmac.new(b'Bitcoin seed',seed,hashlib.sha512).digest()
    p=mul(int.from_bytes(I[:32],'big'))
    pub=bytes([2+(p[1]&1)])+p[0].to_bytes(32,'big')
    return ripemd160(hashlib.sha256(pub).digest())[:4].hex()
assert fingerprint('abandon '*11+'about')=='73c5da0a'
BASE='renew alert there knife dose allow fashion casino kiwi lens sister bless'.split()
REST=[W.index(w) for w in BASE[2:]]
def candidates():
    tail=0
    for n in REST: tail=(tail<<11)|n
    out=[]
    for a in range(2048):
        for b in range(2048):
            v=(a<<121)|(b<<110)|tail
            raw=v.to_bytes(17,'big',signed=False) if False else None
            bits=v
            ent=(bits>>4).to_bytes(16,'big')
            if hashlib.sha256(ent).digest()[0]>>4==bits&15:
                out.append((a,b))
    return out
def text(c): return ' '.join([W[c[0]],W[c[1]]]+BASE[2:])
def work(c): return fingerprint(text(c))
if __name__=='__main__':
    cs=candidates()
    print(len(cs),'candidates',flush=True)
    seen={}; pairs=[]
    with multiprocessing.Pool(int(sys.argv[1])) as pool:
        for i,f in enumerate(pool.imap(work,cs,chunksize=256)):
            if f in seen: pairs.append((seen[f],i,f))
            else: seen[f]=i
            if i%50000==0: print(i,flush=True)
    print(len(pairs),'pairs')
    for a,b,f in pairs:
        print(f, a, b, '|', text(cs[a]), '|', text(cs[b]))
