import json, sys
from sage.all import log, oo
from estimator import LWE, ND, RC
def run(name, n, q, xs, xe, m):
    params = LWE.Parameters(n=n, q=q, Xs=xs, Xe=xe, m=m)
    best = {}
    for label, model in [('MATZOV', RC.MATZOV), ('ADPS16', RC.ADPS16)]:
        res = []
        for attack in ['primal_usvp','primal_bdd','dual_hybrid']:
            kw = dict(red_cost_model=model)
            if attack.startswith('primal'): kw['red_shape_model']='gsa'
            try:
                r = getattr(LWE, attack)(params, **kw)
                res.append((float(log(r['rop'],2)), attack, int(r['beta'])))
            except Exception as e:
                res.append((float('inf'), attack+':'+str(e)[:40], 0))
        best[label] = min(res)
    print(json.dumps(dict(profile=name, n=n, log2q=float(log(q,2)), m=m, **{k: dict(log2_rop=round(v[0],1), attack=v[1], beta=v[2]) for k,v in best.items()})), flush=True)
cfgs = sys.argv[1:]
G = ND.DiscreteGaussian
if 'native' in cfgs:
    run('native-gaussian-q54', 2048, 2**54, G(6.4), G(6.4), 36864)
if 'prod' in cfgs:
    run('prod-gaussian-q56', 2048, 72057594037641217, G(6.4), G(6.4), 40960)
if 'lit' in cfgs:
    # ReinsPIRe public code setting (per survey agent): q=2^52, uniform ternary secret, error variance 40
    run('reinspire-code-q52-ternary', 2048, 2**52, ND.Uniform(-1,1), G(40**0.5), 2*2048)
    # DNSPIR (ePrint 2026/1872): N=2^11, log q~51, sparse secret h=128, sigma 3.2
    run('dnspir-q51-sparse128', 2048, 2**51, ND.SparseTernary(2048, 64, 64), G(3.2), 2*2048)
    # SandwichPIR (ePrint 2026/1816): n=2048, q<2^32, error std 0.5 (secret distribution assumed = error)
    run('sandwichpir-q32-sd0.5', 2048, 2**32, G(0.5), G(0.5), 2*2048)
