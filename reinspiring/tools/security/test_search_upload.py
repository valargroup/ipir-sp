import itertools
import unittest
from search_upload import allocations, correlated, digits, norm, Q

class UploadSearchTests(unittest.TestCase):
    def test_allocation_matches_exhaustive_search(self):
        amps=[7,103]
        actual=allocations(amps,108)
        brute={}
        for a,b in itertools.product(range(1,55),repeat=2):
            cost=sum(w*(0 if t==54 else 1<<(53-t)) for w,t in zip(amps,[a,b]))
            brute[a+b]=min(brute.get(a+b,cost),cost)
        self.assertEqual({k:v[0] for k,v in actual.items()},brute)
        self.assertEqual(actual[108],(0,[54,54]))

    def test_mixed_radix_reconstruction_and_ties(self):
        for widths in [[25],[27],[29],[12,27],[27,12],[19,19],[27,27]]:
            r=54-sum(widths)
            values=[0,1,Q//2-1,Q//2,Q-1]
            if r: values += [(1<<(r-1))-1,1<<(r-1),(1<<(r-1))+1]
            ds,rs=digits(values,widths)
            for i,v in enumerate(values):
                reconstructed=0;shift=r
                for w,limb in zip(widths,ds):
                    self.assertTrue(-(1<<(w-1))<=limb[i]<(1<<(w-1)))
                    reconstructed+=limb[i]<<shift;shift+=w
                self.assertEqual((reconstructed-v)%Q,rs[i]%Q)
                self.assertLessEqual(abs(rs[i]),(1<<(r-1)) if r else 0)

    def test_correlated_bound_covers_reused_variables(self):
        for a,b in [([1,0],[1,1]),([1,3,-7],[2,9,4]),([100,0],[100,0]),([100,0],[-100,0])]:
            bound=correlated(norm(a),norm(b));actual=norm(x+y for x,y in zip(a,b))
            for k in bound: self.assertGreaterEqual(bound[k],actual[k])
