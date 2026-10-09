import json, sys, time
from sage.all import log
from estimator import LWE, ND, RC
params = LWE.Parameters(n=2048, q=72057594037641217, Xs=ND.DiscreteGaussian(6.4), Xe=ND.DiscreteGaussian(6.4), m=40960)
for attack in ['primal_usvp','primal_bdd','dual','dual_hybrid']:
    kw = dict(red_cost_model=RC.MATZOV)
    if attack.startswith('primal'): kw['red_shape_model']='gsa'
    r = getattr(LWE, attack)(params, **kw)
    print(attack, float(log(r['rop'],2)), r['beta'], flush=True)
