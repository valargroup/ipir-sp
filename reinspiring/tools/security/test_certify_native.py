"""Run with python3 -m unittest discover -s reinspiring/tools/security."""
import unittest
import copy
import json
from pathlib import Path
import subprocess
import sys
from decimal import Decimal, localcontext
from fractions import Fraction as F
from certify_native import exp_upper, sampler_bounds, certified_bits, evaluate


class CertificateTests(unittest.TestCase):
    def test_rounded_public_mask_certificate_and_negative_bindings(self):
        evidence=Path(__file__).resolve().parents[3]/'bench-results/2026-09-25-no-extra-download'
        report=json.loads((evidence/'noise-32.json').read_text())
        result=evaluate(report)
        self.assertEqual(result['actual_profile']['certified_failure_bits'],375)
        self.assertEqual(result['actual_profile']['published_bytes'],262180)
        self.assertTrue(result['actual_profile']['no_extra_download'])
        report29=json.loads((evidence/'noise-29.json').read_text())
        accepted=evaluate(report29)['actual_profile']
        self.assertEqual(accepted['certified_failure_bits'],228)
        self.assertEqual(accepted['published_bytes'],237604)
        self.assertTrue(accepted['meets_128'])
        rejected=evaluate(json.loads((evidence/'noise-28.json').read_text()))['actual_profile']
        self.assertEqual(rejected['certified_failure_bits'],82)
        self.assertFalse(rejected['meets_128'])
        run=subprocess.run([sys.executable,str(Path(__file__).with_name('certify_native.py')),str(evidence/'noise-28.json')],capture_output=True,text=True)
        self.assertEqual(run.returncode,1)
        for mutation in ('format','bits','size','weights','missing_screen','sampler','sampler_hash'):
            bad=copy.deepcopy(report)
            if mutation=='sampler':
                bad['sampler_counts'][65][1]=str(int(bad['sampler_counts'][65][1])-1)
                bad['sampler_counts'][66][1]=str(int(bad['sampler_counts'][66][1])+1)
            if mutation=='sampler_hash': bad['sampler_sha256']='00'*32
            if mutation=='format': bad['format']='native-noise-two-mask-v1'
            if mutation=='bits': bad['published_mask_bits']=33
            if mutation=='size': bad['published_bytes']+=1
            if mutation=='weights': bad['blocks'][0]['weights']['l1']=str(int(bad['blocks'][0]['weights']['l1'])+1)
            if mutation=='missing_screen': bad['blocks'][0]['public_mask_screens'].pop()
            with self.assertRaises(ValueError): evaluate(bad)

    def test_recorded_one_mask_rounded_certificates_and_rejection(self):
        evidence=Path(__file__).resolve().parents[3]/'bench-results/2026-09-25-one-mask-rounded'
        for bits, expected, nbytes in ((54,429,221220),(29,333,118820),(28,161,114724)):
            report=json.loads((evidence/f'noise-{bits}.json').read_text())
            result=evaluate(report)
            self.assertEqual(result['format'],'native-certificate-rounded-v1')
            self.assertEqual(result['actual_profile']['certified_failure_bits'],expected)
            self.assertEqual(result['actual_profile']['published_bytes'],nbytes)
            self.assertTrue(result['actual_profile']['meets_128'])
        report=json.loads((evidence/'noise-28.json').read_text())
        for mutation in ('bits','size','weights','missing_screen','legacy_format'):
            bad=copy.deepcopy(report)
            if mutation=='bits': bad['published_mask_bits']=27
            if mutation=='size': bad['published_bytes']-=1
            if mutation=='weights': bad['blocks'][0]['weights']['max']=str(int(bad['blocks'][0]['weights']['max'])-1)
            if mutation=='missing_screen': bad['blocks'][0]['public_mask_screens'].pop(0)
            if mutation=='legacy_format': bad['format']='native-noise-v1'
            with self.assertRaises(ValueError): evaluate(bad)

    def test_recorded_two_mask_certificate_and_rejection(self):
        evidence=Path(__file__).resolve().parents[3]/'bench-results/2026-09-25-two-mask'
        report=json.loads((evidence/'noise.json').read_text())
        result=evaluate(report)
        self.assertEqual(result['format'],'native-certificate-two-mask-v1')
        self.assertEqual(result['actual_profile']['key_bytes'],27648)
        self.assertEqual(result['actual_profile']['certified_failure_bits'],436)
        bad=copy.deepcopy(report); bad['blocks'][0]['kh_l1']='1'
        with self.assertRaises(ValueError): evaluate(bad)
        bad=copy.deepcopy(report); bad['blocks'].pop()
        with self.assertRaises(ValueError): evaluate(bad)

    def test_recorded_full_response_certificates_and_rejection(self):
        evidence=Path(__file__).resolve().parents[3]/'bench-results/2026-09-25-reinspiring-kh-compression'
        for bits, expected in ((54,405),(48,345),(47,260),(46,112)):
            report=json.loads((evidence/f'noise-{bits}.json').read_text())
            result=evaluate(report)
            self.assertEqual(result['actual_profile']['certified_failure_bits'],expected)
            self.assertTrue(result['actual_profile']['meets_78'])
            self.assertEqual(result['actual_profile']['meets_128'],bits!=46)
            self.assertFalse(any(x['meets_78'] for x in result['one_limb_screen']))
        bad=copy.deepcopy(report); bad['blocks'].pop()
        with self.assertRaises(ValueError): evaluate(bad)
        bad=copy.deepcopy(report); bad['blocks'][0]['kh_l1']='-1'
        with self.assertRaises(ValueError): evaluate(bad)
        script=Path(__file__).with_name('certify_native.py')
        for target,code in ((78,0),(128,1)):
            run=subprocess.run([sys.executable,str(script),str(evidence/'noise-46.json'),'--require-bits',str(target)],capture_output=True,text=True)
            self.assertEqual(run.returncode,code,run.stderr)

    def test_exponential_rounds_up_including_tail(self):
        with localcontext() as ctx:
            ctx.prec = 100
            for x in (F(0),F(1,512),F(65,32),F(65,4),F(32)):
                bound = exp_upper(x)
                actual = (Decimal(x.numerator)/Decimal(x.denominator)).exp()
                upper = Decimal(bound.numerator)/Decimal(bound.denominator)
                self.assertGreaterEqual(upper,actual)
                self.assertLess(upper-actual,Decimal('1e-24'))

    def test_finite_biased_sampler_and_mgf(self):
        mean, bounds = sampler_bounds([(-1,2**62),(1,3*2**62)])
        self.assertEqual(mean,F(1,2))
        with localcontext() as ctx:
            ctx.prec = 60
            for a,c in bounds:
                for u in (-a,-a/2,a/2,a):
                    t=Decimal(u.numerator)/Decimal(u.denominator)
                    mgf=(-t).exp()/4+3*t.exp()/4
                    exponent=abs(u)*mean+c*u*u/2
                    upper=(Decimal(exponent.numerator)/Decimal(exponent.denominator)).exp()
                    self.assertGreaterEqual(upper,mgf)

    def test_certificate_rejects_exhausted_budget_and_accounts_for_union(self):
        mean,bounds=sampler_bounds([(-1,2**63),(1,2**63)])
        weights={'l1':1024,'l2_squared':1024,'max':1}
        one=certified_bits(weights,500,0,1,mean,bounds)
        many=certified_bits(weights,500,0,32768,mean,bounds)
        self.assertEqual(one-many,15)
        self.assertGreaterEqual(many,78)
        self.assertIsNone(certified_bits(weights,500,500,1,mean,bounds))
        self.assertLess(certified_bits(weights,500,450,32768,mean,bounds),78)
        with self.assertRaises(ValueError):
            sampler_bounds([(0,2**64-1)])


if __name__ == '__main__':
    unittest.main()
