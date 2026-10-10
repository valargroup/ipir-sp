"""Run with python3 -m unittest discover -s reinspiring/tools/security."""
import unittest
import copy
import json
from pathlib import Path
import subprocess
import sys
from decimal import Decimal, localcontext
from fractions import Fraction as F
from certify_native import exp_upper, sampler_bounds, certified_bits, evaluate, query_terms, query_transport, report_format, REPORT_FORMATS, LN2_UPPER


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
            report=json.loads((evidence/f'noise-{name}.json').read_text())
            self.assertEqual(report['format'].endswith('-dithered-v1'),rounding=='dithered')
            result=evaluate(report)
            actual=result['actual_profile']
            self.assertEqual((actual['query_bits'],actual['query_rounding'],actual['certified_failure_bits']),(bits,rounding,expected))
            self.assertTrue(actual['meets_128'])
            self.assertEqual(len(result['query_screen']),11)
        big=evaluate(json.loads((evidence/'noise-two-mask29-65536-n49.json').read_text()))
        self.assertEqual(next(v['certified_failure_bits'] for v in big['query_screen'] if v['query_rounding']=='dithered' and v['query_bits']==49),295)
        self.assertEqual(big['smallest_screened_query_bits_128'],44)
        report=json.loads((evidence/'noise-one-mask-d43.json').read_text())
        for mutation in ('nearest','unlabelled','nearest_format','width','missing','small','large'):
            bad=copy.deepcopy(report)
            if mutation=='nearest': bad['query_rounding']='nearest'
            if mutation=='unlabelled': del bad['query_rounding']
            if mutation=='nearest_format': bad['format']='native-noise-v1'
            if mutation=='width': bad['query_bits']=50
            if mutation=='missing': del bad['blocks'][0]['query_l2_squared']
            if mutation=='small': bad['blocks'][0]['query_l2_squared']=str(int(bad['blocks'][0]['query_l1'])-1)
            if mutation=='large': bad['blocks'][0]['query_l2_squared']=str(int(bad['blocks'][0]['query_l1'])*65535+1)
            with self.assertRaises(ValueError): evaluate(bad)

    def test_report_format_must_match_query_rounding(self):
        # Nearest reports keep the formats that predate dithering.
        self.assertEqual(sorted(f for f,(_,_,d) in REPORT_FORMATS.items() if not d),
                         ['native-noise-rounded-v1','native-noise-two-mask-rounded-v1',
                          'native-noise-two-mask-v1','native-noise-v1'])
        self.assertEqual(report_format({'format':'native-noise-two-mask-rounded-dithered-v1','query_rounding':'dithered'}),(True,True))
        self.assertEqual(report_format({'format':'native-noise-v1'}),(False,False))
        for fmt,rounding in (('native-noise-dithered-v1','nearest'),('native-noise-dithered-v1',None),
                             ('native-noise-v1','dithered'),('native-noise-two-mask-v1','dithered'),
                             ('native-noise-dithered','dithered'),('native-noise-v1-dithered','dithered')):
            report={'format':fmt} if rounding is None else {'format':fmt,'query_rounding':rounding}
            with self.assertRaises(ValueError):
                report_format(report)
        evidence=Path(__file__).resolve().parents[3]/'bench-results/2026-10-09-dithered-query'
        for name,fmt in (('one-mask-n49','native-noise-dithered-v1'),('one-mask-d43','native-noise-v1'),
                         ('two-mask29-n49','native-noise-two-mask-rounded-dithered-v1'),
                         ('two-mask29-d44','native-noise-two-mask-rounded-v1')):
            bad=json.loads((evidence/f'noise-{name}.json').read_text())
            bad['format']=fmt
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


class SmallPlaintextTests(unittest.TestCase):
    root = Path(__file__).resolve().parents[3] / 'bench-results'

    def load(self, path):
        return json.loads((self.root / path).read_text())

    def test_recorded_certificates_are_byte_identical(self):
        evidence = self.root / '2026-10-09-dithered-query'
        pairs = 0
        for cert in sorted(evidence.glob('certificate-*.json')):
            report = json.loads((evidence / cert.name.replace('certificate-', 'noise-')).read_text())
            self.assertEqual(json.dumps(evaluate(report), indent=2) + '\n', cert.read_text(), cert.name)
            pairs += 1
        self.assertEqual(pairs, 7)

    def p8_report(self):
        # Exact-mask two-mask report, retargeted to p = 2^8 with a one-digit
        # gadget and 10-bit responses. Query weights are rescaled to entries < 2^8.
        report = self.load('2026-09-25-two-mask/noise.json')
        report.update(p_bits=8, ell=1, gadget_bits=27, dropped_bits=27, response_bits=10)
        for block in report['blocks']:
            block['query_l1'] = str(report['rows'] * 127)
        return report

    def test_p8_one_digit_profile_terms(self):
        report = self.p8_report()
        actual = evaluate(report)['actual_profile']
        self.assertEqual(actual['key_bytes'], 13824)
        self.assertEqual((actual['p_bits'], actual['ell'], actual['gadget_bits']), (8, 1, 27))
        self.assertEqual(actual['response_bits'], 10)
        self.assertEqual(actual['response_bytes'], 68 + report['cols'] * 10 // 8)
        # Radius q/2^9 and response term 2^43: deterministic includes 2^43.
        self.assertGreaterEqual(int(actual['max_deterministic_error']), 1 << 43)
        self.assertIsNotNone(actual['certified_failure_bits'])

    def test_p8_rejects_out_of_range_reports(self):
        for mutation in ('entries', 'response_low', 'response_high', 'p12', 'gadget', 'dropped', 'query_floor'):
            bad = self.p8_report()
            if mutation == 'entries':
                bad['blocks'][0]['query_l1'] = str(bad['rows'] * 255 + 1)
            if mutation == 'response_low':
                bad['response_bits'] = 8
            if mutation == 'response_high':
                bad['response_bits'] = 15
            if mutation == 'p12':
                bad['p_bits'] = 12
            if mutation == 'gadget':
                bad['gadget_bits'] = 28
            if mutation == 'dropped':
                bad['dropped_bits'] = 26
            if mutation == 'query_floor':
                bad['format'] = 'native-noise-two-mask-dithered-v1'
                bad['query_rounding'] = 'dithered'
                bad['query_bits'] = 23
            with self.assertRaises(ValueError, msg=mutation):
                evaluate(bad)

    def test_screens_match_actual_and_bound_worst_case(self):
        report = self.load('2026-10-09-dithered-query/noise-two-mask29-d43.json')
        result = evaluate(report, screens=True)
        screens = result['screens']
        self.assertTrue(screens['counterfactual'])
        self.assertEqual([v['published_mask_bits'] for v in screens['mask_screen']], list(range(27, 33)))
        self.assertEqual([v['response_bits'] for v in screens['response_screen']], list(range(17, 23)))
        actual = result['actual_profile']
        at29 = next(v for v in screens['mask_screen'] if v['published_mask_bits'] == 29)
        at22 = next(v for v in screens['response_screen'] if v['response_bits'] == 22)
        self.assertEqual(at29['certified_failure_bits'], actual['certified_failure_bits'])
        self.assertEqual(at22['certified_failure_bits'], actual['certified_failure_bits'])
        worst = screens['worst_case_query']['certified_failure_bits']
        self.assertTrue(worst is None or worst <= actual['certified_failure_bits'])
        for point in screens['width_frontier']:
            self.assertGreaterEqual(point['certified_failure_bits'], 128)
            self.assertGreaterEqual(point['query_bits'], 40)
        # Default output is unchanged by the flag apart from the added key.
        plain = evaluate(report)
        del result['screens']
        self.assertEqual(result, plain)
