"""Run with python3 -m unittest discover -s reinspiring/tools/security."""
import unittest
import copy
import json
from pathlib import Path
import subprocess
import sys
from decimal import Decimal, localcontext
from fractions import Fraction as F
from certify_native import exp_upper, sampler_bounds, certified_bits, evaluate, query_terms, query_transport, LN2_UPPER


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

    def test_recorded_dithered_query_certificates_and_rejection(self):
        evidence=Path(__file__).resolve().parents[3]/'bench-results/2026-10-09-dithered-query'
        for name, bits, rounding, expected in (
                ('one-mask-n49',49,'nearest',405),('one-mask-d44',44,'dithered',406),('one-mask-d43',43,'dithered',208),
                ('two-mask29-n49',49,'nearest',228),('two-mask29-d44',44,'dithered',230),('two-mask29-d43',43,'dithered',147),
                ('two-mask29-65536-n49',49,'nearest',158)):
            result=evaluate(json.loads((evidence/f'noise-{name}.json').read_text()))
            actual=result['actual_profile']
            self.assertEqual((actual['query_bits'],actual['query_rounding'],actual['certified_failure_bits']),(bits,rounding,expected))
            self.assertTrue(actual['meets_128'])
            self.assertEqual(len(result['query_screen']),11)
        big=evaluate(json.loads((evidence/'noise-two-mask29-65536-n49.json').read_text()))
        self.assertEqual(next(v['certified_failure_bits'] for v in big['query_screen'] if v['query_rounding']=='dithered' and v['query_bits']==49),295)
        self.assertEqual(big['smallest_screened_query_bits_128'],44)
        report=json.loads((evidence/'noise-one-mask-d43.json').read_text())
        for mutation in ('nearest','width','missing','small','large'):
            bad=copy.deepcopy(report)
            if mutation=='nearest': bad['query_rounding']='nearest'
            if mutation=='width': bad['query_bits']=50
            if mutation=='missing': del bad['blocks'][0]['query_l2_squared']
            if mutation=='small': bad['blocks'][0]['query_l2_squared']=str(int(bad['blocks'][0]['query_l1'])-1)
            if mutation=='large': bad['blocks'][0]['query_l2_squared']=str(int(bad['blocks'][0]['query_l1'])*65535+1)
            with self.assertRaises(ValueError): evaluate(bad)

    def test_dither_variance_enters_the_chernoff_exponent(self):
        mean,bounds=sampler_bounds([(-1,2**63),(1,2**63)])
        none={'l1':0,'l2_squared':0,'max':0}
        # Dither alone: exponent B²/(2V) = 100 nats; one coefficient costs one union bit.
        self.assertEqual(certified_bits(none,1000,0,1,mean,bounds,F(10**6,200)),
                         int(F(100)//LN2_UPPER)-1)
        self.assertEqual(certified_bits(none,1000,0,1,mean,bounds),1000000)
        weights={'l1':1024,'l2_squared':1024,'max':1}
        clean=certified_bits(weights,500,0,1,mean,bounds)
        noisy=certified_bits(weights,500,0,1,mean,bounds,1000)
        self.assertLess(noisy,clean)
        with self.assertRaises(ValueError):
            certified_bits(weights,500,0,1,mean,bounds,-1)

    def test_query_transport_terms_and_rejections(self):
        block={'query_l1':'100','query_l2_squared':'5000'}
        self.assertEqual(query_terms(block,10,49,False),(1600,0))
        self.assertEqual(query_terms(block,10,44,True),(0,F(5000*2**20,4)))
        for bits,rounding in ((49,'nearest'),(49,'dithered'),(48,'dithered'),(40,'dithered')):
            self.assertEqual(query_transport({'query_bits':bits,'query_rounding':rounding}),(bits,rounding=='dithered'))
        self.assertEqual(query_transport({'query_bits':49}),(49,False))
        for bits,rounding in ((48,'nearest'),(39,'dithered'),(50,'dithered'),(44,'floor')):
            with self.assertRaises(ValueError):
                query_transport({'query_bits':bits,'query_rounding':rounding})
        for bad in ({'query_l1':'100','query_l2_squared':'99'},
                    {'query_l1':'100','query_l2_squared':str(100*65535+1)},
                    {'query_l1':'100'},
                    {'query_l1':str(10*65535+1),'query_l2_squared':'1'}):
            with self.assertRaises(ValueError):
                query_terms(bad,10,44,True)


if __name__ == '__main__':
    unittest.main()
