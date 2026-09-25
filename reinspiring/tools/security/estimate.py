"""Run with Sage Python and lattice-estimator 53da598 on PYTHONPATH.
Generic scalar-LWE diagnostics, not a proof for structured KDM-RLWE.
"""
import json
import time
from sage.all import log
from estimator import LWE, ND, RC

for name, q, xs, samples in [
    ('main-gaussian', 72057594037641217, ND.DiscreteGaussian(6.4), 40960),
    ('native-gaussian-l2', 2**54, ND.DiscreteGaussian(6.4), 36864),
    ('native-ternary-l2', 2**54, ND.Uniform(-1, 1), 36864),
]:
    params = LWE.Parameters(n=2048, q=q, Xs=xs, Xe=ND.DiscreteGaussian(6.4), m=samples)
    for label, model in [('MATZOV', RC.MATZOV), ('core-SVP-ADPS16', RC.ADPS16)]:
        for attack in ['primal_usvp', 'primal_bdd', 'dual', 'dual_hybrid']:
            start = time.monotonic()
            kwargs = dict(red_cost_model=model)
            if attack.startswith('primal'):
                kwargs['red_shape_model'] = 'gsa'
            try:
                result = getattr(LWE, attack)(params, **kwargs)
                print(json.dumps(dict(profile=name, model=label, attack=attack,
                    log2_rop=float(log(result['rop'], 2)), beta=int(result['beta']),
                    elapsed_s=time.monotonic()-start, details=str(result))), flush=True)
            except Exception as exc:
                print(json.dumps(dict(profile=name, model=label, attack=attack, error=str(exc))), flush=True)
