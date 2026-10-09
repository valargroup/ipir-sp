import math
import smallp_model as m
N=49_925_853; D=2048
PROD=(236_544,81_920,229_376)  # upload, download, published c1 (56-bit, 16 blocks)
print("L blocks rows(padded) bq br | upload  xUp | down | per-query total xTot | masks@27 masks@min(ba) | breakeven queries vs prod (27b, minba)")
for L in (3,4,5,6,8):
    best=[]
    for blocks in range(8,140):
        C=D*blocks; per=(C*L)//256; R=math.ceil(N/per); Rp=math.ceil(R/D)*D
        sk=m.sig_keys(2,19)
        sol=None
        for br in range(L+1,L+4):
            for bq in range(10,50):
                if m.ok(L,Rp,bq,br,27,sk,False): sol=(bq,br); break
            if sol: break
        if not sol: continue
        bq,br=sol
        ba=next(b for b in range(10,55) if m.ok(L,Rp,bq,br,b,sk,False))
        up=36+27_648+math.ceil(Rp*bq/8); down=68+math.ceil(C*br/8)
        if down>PROD[1]+68: continue
        pub27=36+math.ceil(2*C*27/8); pubmin=36+math.ceil(2*C*ba/8)
        best.append((up+down,blocks,Rp,bq,br,up,down,pub27,pubmin,ba))
    best.sort()
    for t in best[:2]:
        tot,blocks,Rp,bq,br,up,down,pub27,pubmin,ba=t
        save=PROD[0]+PROD[1]-tot
        print(f"{L} {blocks:3d} {Rp:6d} {bq} {br} | {up:7,} {PROD[0]/up:4.2f} | {down:6,} | {tot:7,} {(PROD[0]+PROD[1])/tot:4.2f} | {pub27:9,} {pubmin:9,}(ba={ba}) | {(pub27-PROD[2])/save:4.1f} {(pubmin-PROD[2])/save:4.1f}")
