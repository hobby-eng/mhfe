# AUD-044 fun probe: an independent derivation of the addresses of the public phrase "abandon ...
# about", written from BIP32, BIP44/49/84/86, BIP173/350, EIP-55, CashAddr, DIP17/18 and the coins'
# prefixes, with no code of mhfe. It prints "<coin> <address> <path>" for `fun-probes addresses`.
import hashlib, hmac, unicodedata

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0]:
        if (a[1] + b[1]) % P == 0: return None
        s = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        s = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (s * s - a[0] - b[0]) % P
    return (x, (s * (a[0] - x) - a[1]) % P)
def mul(k, p=G):
    r = None
    while k:
        if k & 1: r = add(r, p)
        p = add(p, p); k >>= 1
    return r
def ser(p): return bytes([2 + (p[1] & 1)]) + p[0].to_bytes(32, 'big')

# RIPEMD-160, pure, as OpenSSL may leave it out.
def ripemd160(data):
    r1=[11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    r2=[8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
    z1=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    z2=[5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    K1=[0,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e]; K2=[0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0]
    f=lambda j,x,y,z:[x^y^z,(x&y)|(~x&z),(x|~y)^z,(x&z)|(y&~z),x^(y|~z)][j//16]&0xffffffff
    rol=lambda x,n:((x<<n)|(x>>(32-n)))&0xffffffff
    h=[0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0]
    m=data+b'\x80'+b'\0'*((55-len(data))%64)+(8*len(data)).to_bytes(8,'little')
    for o in range(0,len(m),64):
        x=[int.from_bytes(m[o+i:o+i+4],'little') for i in range(0,64,4)]
        a,b,c,d,e=h; A,B,C,D,E=h
        for j in range(80):
            t=(rol((a+f(j,b,c,d)+x[z1[j]]+K1[j//16])&0xffffffff,r1[j])+e)&0xffffffff
            a,e,d,c,b=e,d,rol(c,10),b,t
            t=(rol((A+f(79-j,B,C,D)+x[z2[j]]+K2[j//16])&0xffffffff,r2[j])+E)&0xffffffff
            A,E,D,C,B=E,D,rol(C,10),B,t
        t=(h[1]+c+D)&0xffffffff; h[1]=(h[2]+d+E)&0xffffffff; h[2]=(h[3]+e+A)&0xffffffff
        h[3]=(h[4]+a+B)&0xffffffff; h[4]=(h[0]+b+C)&0xffffffff; h[0]=t
    return b''.join(v.to_bytes(4,'little') for v in h)
assert ripemd160(b'abc').hex()=='8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'

def keccak256(data):
    RC=[0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
    ROT=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
    M=(1<<64)-1
    rol=lambda x,n:((x<<n)|(x>>(64-n)))&M if n else x
    rate=136
    p=bytearray(data)+b'\x01'+b'\0'*((rate-len(data)-1)%rate)
    p[-1]|=0x80
    s=[[0]*5 for _ in range(5)]
    for o in range(0,len(p),rate):
        for i in range(rate//8):
            s[i%5][i//5]^=int.from_bytes(p[o+8*i:o+8*i+8],'little')
        for rc in RC:
            c=[s[x][0]^s[x][1]^s[x][2]^s[x][3]^s[x][4] for x in range(5)]
            d=[c[(x+4)%5]^rol(c[(x+1)%5],1) for x in range(5)]
            s=[[s[x][y]^d[x] for y in range(5)] for x in range(5)]
            b=[[0]*5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    b[y][(2*x+3*y)%5]=rol(s[x][y],ROT[x][y])
            s=[[b[x][y]^((~b[(x+1)%5][y])&b[(x+2)%5][y]) for y in range(5)] for x in range(5)]
            s[0][0]^=rc
    return b''.join(s[i%5][i//5].to_bytes(8,'little') for i in range(4))
assert keccak256(b'').hex()=='c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'

sha=lambda b:hashlib.sha256(b).digest()
h160=lambda b:ripemd160(sha(b))
B58='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
RIPPLE='rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'
def b58check(payload, alphabet=B58):
    data=payload+sha(sha(payload))[:4]
    n=int.from_bytes(data,'big'); s=''
    while n: n,r=divmod(n,58); s=alphabet[r]+s
    return alphabet[0]*(len(data)-len(data.lstrip(b'\0')))+s
CH='qpzry9x8gf2tvdw0s3jn54khce6mua7l'
def polymod(v):
    gen=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]; c=1
    for x in v:
        t=c>>25; c=((c&0x1ffffff)<<5)^x
        for i in range(5):
            if (t>>i)&1: c^=gen[i]
    return c
def bech32(hrp, data, const):
    exp=[ord(x)>>5 for x in hrp]+[0]+[ord(x)&31 for x in hrp]
    pm=polymod(exp+data+[0]*6)^const
    return hrp+'1'+''.join(CH[d] for d in data+[(pm>>5*(5-i))&31 for i in range(6)])
def to5(b):
    acc=bits=0; out=[]
    for x in b:
        acc=(acc<<8)|x; bits+=8
        while bits>=5:
            bits-=5; out.append((acc>>bits)&31)
    if bits: out.append((acc<<(5-bits))&31)
    return out
def segwit(hrp,v,prog): return bech32(hrp,[v]+to5(prog),1 if v==0 else 0x2bc830a3)
def cashaddr(h):
    payload=[x for x in to5(bytes([0])+h)]
    pre=[ord(c)&31 for c in 'bitcoincash']+[0]
    v=pre+payload+[0]*8
    c=1
    for d in v:
        t=c>>35; c=((c&0x07ffffffff)<<5)^d
        for i,g in enumerate([0x98f2bc8e61,0x79b76d99e2,0xf33e5fb3c4,0xae2eabe2a8,0x1e4f43e470]):
            if (t>>i)&1: c^=g
    c^=1
    return 'bitcoincash:'+''.join(CH[d] for d in payload)+''.join(CH[(c>>5*(7-i))&31] for i in range(8))

phrase='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
seed=hashlib.pbkdf2_hmac('sha512',unicodedata.normalize('NFKD',phrase).encode(),b'mnemonic',2048)
def derive(path):
    I=hmac.new(b'Bitcoin seed',seed,hashlib.sha512).digest()
    k,c=int.from_bytes(I[:32],'big'),I[32:]
    for step in path:
        hard=step>=2**31
        data=(b'\0'+k.to_bytes(32,'big') if hard else ser(mul(k)))+step.to_bytes(4,'big')
        I=hmac.new(c,data,hashlib.sha512).digest()
        k=(int.from_bytes(I[:32],'big')+k)%N; c=I[32:]
    return k
def parse(s):
    out=[]
    for p in s.split('/')[1:]:
        out.append(int(p[:-1])+2**31 if p.endswith("'") else int(p))
    return out
def pub(k): return ser(mul(k))
def eth(k):
    p=mul(k); return keccak256(p[0].to_bytes(32,'big')+p[1].to_bytes(32,'big'))[12:]
def eip55(a):
    lo=a.hex(); h=keccak256(lo.encode()).hex()
    return '0x'+''.join(c.upper() if int(h[i],16)>=8 else c for i,c in enumerate(lo))
def taproot(k):
    p=mul(k)
    if p[1]&1: p=(p[0],P-p[1])
    x=p[0].to_bytes(32,'big'); tag=sha(b'TapTweak')
    t=int.from_bytes(sha(tag+tag+x),'big')
    return add(p,mul(t))[0].to_bytes(32,'big')
wsh=lambda k:h160(b'\0\x14'+h160(pub(k)))
rows=[]
def row(coin,addr,path): rows.append(f"{coin} {addr} {path}")
K=lambda s:derive(parse(s))
for s in ["m/44'/0'/0'/0/0","m/44'/0'/9'/1/99"]: row('bitcoin',b58check(b'\0'+h160(pub(K(s)))),s)
for s in ["m/49'/0'/0'/0/0","m/49'/0'/1'/1/7"]: row('bitcoin',b58check(b'\x05'+wsh(K(s))),s)
for s in ["m/84'/0'/0'/0/0","m/84'/0'/9'/0/99"]: row('bitcoin',segwit('bc',0,h160(pub(K(s)))),s)
for s in ["m/86'/0'/0'/0/0","m/86'/0'/0'/1/3"]: row('bitcoin',segwit('bc',1,taproot(K(s))),s)
s="m/44'/1'/0'/0/0"; row('bitcoin',b58check(b'\x6f'+h160(pub(K(s)))),s)
s="m/49'/1'/0'/0/0"; row('bitcoin',b58check(b'\xc4'+wsh(K(s))),s)
s="m/84'/1'/0'/0/0"; row('bitcoin',segwit('tb',0,h160(pub(K(s)))),s)
s="m/86'/1'/0'/0/0"; row('bitcoin',segwit('tb',1,taproot(K(s))),s)
s="m/44'/60'/0'/0/5"; row('ethereum',eip55(eth(K(s))),s); row('ethereum','0x'+eth(K(s)).hex(),s)
s="m/44'/61'/0'/0/0"; row('ethereum-classic',eip55(eth(K(s))),s)
s="m/44'/60'/0'/0/0"; row('ethereum-classic',eip55(eth(K(s))),s); row('injective',bech32('inj',to5(eth(K(s))),1),s)
s="m/44'/144'/0'/0/0"; row('xrp',b58check(b'\0'+h160(pub(K(s))),RIPPLE),s)
s="m/44'/195'/0'/0/0"; row('tron',b58check(b'\x41'+eth(K(s))),s)
s="m/44'/133'/0'/0/0"; row('zcash',b58check(b'\x1c\xb8'+h160(pub(K(s)))),s)
s="m/44'/3'/0'/0/0"; row('dogecoin',b58check(b'\x1e'+h160(pub(K(s)))),s)
s="m/44'/145'/0'/0/0"; row('bitcoin-cash',cashaddr(h160(pub(K(s)))),s); row('bitcoin-cash',b58check(b'\0'+h160(pub(K(s)))),s)
s="m/44'/0'/0'/0/1"; row('bitcoin-cash',cashaddr(h160(pub(K(s)))),s)
s="m/44'/2'/0'/0/0"; row('litecoin',b58check(b'\x30'+h160(pub(K(s)))),s)
s="m/49'/2'/0'/0/0"; row('litecoin',b58check(b'\x32'+wsh(K(s))),s); row('litecoin',b58check(b'\x05'+wsh(K(s))),s)
s="m/84'/2'/0'/0/0"; row('litecoin',segwit('ltc',0,h160(pub(K(s)))),s)
s="m/44'/118'/0'/0/0"; row('cosmos',bech32('cosmos',to5(h160(pub(K(s)))),1),s)
s="m/44'/5'/0'/0/0"; row('dash',b58check(b'\x4c'+h160(pub(K(s)))),s)
s="m/9'/5'/17'/0'/0'/0"; row('dash',bech32('dash',to5(b'\xb0'+h160(pub(K(s)))),0x2bc830a3),s)
s="m/9'/5'/17'/3'/1'/42"; row('dash',bech32('dash',to5(b'\xb0'+h160(pub(K(s)))),0x2bc830a3),s)
s="m/9'/1'/17'/0'/0'/0"; row('dash',bech32('tdash',to5(b'\xb0'+h160(pub(K(s)))),0x2bc830a3),s)
print('\n'.join(rows))
# Leading zeros (BIP32 test vector 4's point): a parent key below 2^248 and its hardened child, whose
# HMAC input must keep the zero byte. Written to a file of its own for `fun-probes addresses`.
lines=[]
for i in range(0,3000):
    k=K(f"m/44'/0'/{i}'")
    if k < 2**248:
        s=f"m/44'/0'/{i}'/5'"
        lines.append(f"bitcoin {b58check(b'\0'+h160(pub(K(s))))} at {s}")
        if len(lines)==3: break
open('../tmp/aud044/fun/work/leading-zero.txt','w').write('\n'.join(lines)+'\n')
