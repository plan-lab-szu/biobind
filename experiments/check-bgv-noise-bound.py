"""Exact arithmetic for a source-derived sufficient bound; not a SEAL execution."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import random

ROOT = Path(__file__).resolve().parents[1]

def mul(a, b):
    n = len(a)
    out = [0]*n
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[(i+j) % n] += x*y*(1 if i+j < n else -1)
    return out

def add(a, b):
    return [x+y for x,y in zip(a,b)]

def center(x, modulus):
    return (x+modulus//2) % modulus-modulus//2

def toy_check():
    # Small integer-ring model of public encryption, BGV zero switching,
    # plaintext lift, accumulation and product. NOT SEAL/NTT/BatchEncoder.
    rng = random.Random(20261031)
    n,p,r,q = 4,17,1009,2**61-1
    B = p*(n+3)
    checked = 0
    for trial in range(100):
        s = [rng.randrange(-1,2) for _ in range(n)]
        a = [rng.randrange(q*r) for _ in range(n)]
        epk = [rng.randrange(-21,22) for _ in range(n)]
        pk0 = [(-v-p*e) % (q*r) for v,e in zip(mul(a,s),epk)]
        def encrypt(m):
            u = [rng.randrange(-1,2) for _ in range(n)]
            e0,e1 = [[rng.randrange(-21,22) for _ in range(n)] for _ in range(2)]
            c0 = [(x+p*e) % (q*r) for x,e in zip(mul(pk0,u),e0)]
            c1 = [(x+p*e) % (q*r) for x,e in zip(mul(a,u),e1)]
            def switch(poly):
                result=[]
                for c in poly:
                    residue=c % r
                    k=(-residue*pow(r,-1,p)) % p
                    delta=residue+r*k
                    assert delta % p == 0 and 0 <= delta < r*p
                    result.append(((c-delta)//r) % q)
                return result
            d0,d1 = switch(c0),switch(c1)
            phase=[center(v,q) for v in add(add(d0,m),mul(d1,s))]
            assert max(map(abs,phase)) <= B
            assert all((x-y) % p == 0 for x,y in zip(phase,m))
            return phase
        query = [[rng.randrange(-(p//2),p//2+1) for _ in range(n)] for _ in range(4)]
        query_phase = [encrypt(m) for m in query]
        accum, plain_accum = [[0]*n for _ in range(4)], [[0]*n for _ in range(4)]
        for count in range(1,17):
            for dim in range(4):
                m=[rng.randrange(-(p//2),p//2+1) for _ in range(n)]
                accum[dim]=add(accum[dim],encrypt(m))
                plain_accum[dim]=add(plain_accum[dim],m)
            if count not in (1,2,8,16): continue
            answer, expected = [0]*n,[0]*n
            for dim in range(4):
                answer=add(answer,mul(query_phase[dim],accum[dim]))
                expected=add(expected,mul(query[dim],plain_accum[dim]))
            assert max(map(abs,answer)) <= 4*count*n*B*B < q//2
            assert all((x-y) % p == 0 for x,y in zip(answer,expected))
            checked += 1
    return checked

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out',type=Path,required=True)
    args=ap.parse_args()
    if args.out.exists(): raise SystemExit('Preserve previous results; use a new path')
    witness=ROOT/'results/experiments/bgv-repair-r3-f3-64-20261030/FaceNet-3/parameters.json'
    previous=json.loads(witness.read_text())
    primes=previous['coeff_modulus']
    assert [x.bit_length() for x in primes] == [60,50,50,50]
    N,L,K,p_upper=8192,512,16384,2**48
    q=math.prod(primes[:-1]); r=primes[-1]
    A=21*(2*N+1)
    assert r>A
    B=p_upper*(N+3)
    final=L*K*N*B**2
    assert 2*final < q
    report={
        'kind':'static sufficient-condition arithmetic plus toy integer-ring checks; not SEAL runtime',
        'profile':'Unified512-2', 'N':N,'L':L,'K':K,'plainUpperBoundExclusive':p_upper,
        'coefficientPrimesRequired':primes,'dataModulusProduct':q,
        'preSwitchNoiseCoefficientBound':A,'freshPhaseBoundConservative':B,
        'queryPhaseBound':final,'strictNoWrapCheck':2*final<q,
        'Q_over_twice_bound':str(q/(2*final)),
        'wholeBitsConservativeMargin':(q//(2*final)).bit_length()-1,
        'maxKCertifiedByThisBound':(q-1)//(2*L*N*B**2),
        'toyChecks':toy_check(),
        'modulusWitness':witness.relative_to(ROOT).as_posix(),
        'modulusWitnessSHA256':hashlib.sha256(witness.read_bytes()).hexdigest(),
        'requires':['CBD noise coefficients bounded by 21; ternary secret and ephemeral keys',
                    'official SEAL 4.1.2 asymmetric zero encryption with one special-prime drop',
                    'exact listed coefficient primes; 48-bit plaintext prime; correction factor 1',
                    'at most K fresh enrollment ciphertexts per row, all at same level/key',
                    'L ciphertext products summed; no rotations, relinearization, later switching or refresh',
                    'honest constrained encryption; C1 admissible plaintext packing',
                    'correct software/CRT/NTT implementation; independent review still pending'],
        'fullSEALCapacityExecuted':False,
        'securityProofOrIndependentReview':False,
    }
    args.out.parent.mkdir(parents=True,exist_ok=True)
    with args.out.open('x',encoding='utf-8') as f:json.dump(report,f,indent=2)
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
