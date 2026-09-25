"""Conservative finite-sampler Chernoff certificate, using exact integers/rationals.

Input is native_noise's public snapshot report, not measured decryption errors.
The arithmetic certificate is conditional on correct exported weights and fresh
independent sampler draws (the usual idealization of the cryptographic PRNG).
It is neither a lattice-security estimate nor independent cryptographic review.
"""
import argparse
import json
import sys
import hashlib
from pathlib import Path
from fractions import Fraction as F

SCALE = 1 << 192
LN2_UPPER = F(693147180559945310, 10**18)


def ceil_div(a, b):
    return (a + b - 1) // b


def exp_upper(x):
    """Upper bound exp(x), x>=0, with upward fixed-point Taylor arithmetic."""
    assert 0 <= x <= 32
    term = total = SCALE
    for k in range(1, 129):
        term = ceil_div(term * x.numerator, x.denominator * k)
        total += term
    next_term = F(term) * x / 129
    # All subsequent term ratios are <= x/130 < 1.
    tail = next_term / (1 - x / 130)
    return F(total + ceil_div(tail.numerator, tail.denominator), SCALE)


def sampler_bounds(counts):
    """E exp(uX) <= exp(u E[X] + C(a)u²/2), for |u|<=a.

    Expanding after the linear term and using absolute moments gives
    C(a)=2 E[exp(a|X|)-1-a|X|]/a². No ideal-Gaussian approximation is used.
    """
    counts = [(int(x), int(n)) for x, n in counts]
    if not counts or any(n < 0 for _, n in counts) or sum(n for _, n in counts) != 2**64:
        raise ValueError("invalid sampler counts")
    if max(abs(x) for x, _ in counts) > 128:
        raise ValueError("unsupported sampler support")
    mean = abs(F(sum(x*n for x, n in counts), 2**64))
    bounds = []
    for denominator in (512, 256, 128, 64, 32, 16, 8, 4):
        a = F(1, denominator)
        moment = sum(n*(exp_upper(a*abs(x))-1-a*abs(x)) for x, n in counts if n)
        bounds.append((a, 2*moment/F(2**64)/a**2))
    return mean, bounds


def certified_bits(weights, radius, deterministic, cols, mean, bounds):
    """Integer lower bound on -log2(full-response failure probability).

    Each row uses an envelope of L1, squared L2 and maximum original weights.
    Union bound requires no independence between response coefficients/blocks.
    """
    l1, s2, maximum = (int(weights[k]) for k in ('l1', 'l2_squared', 'max'))
    if min(l1, s2, maximum, radius, deterministic) < 0 or cols <= 0:
        raise ValueError("invalid norms/dimensions")
    if maximum > l1 or s2 > l1*maximum or (s2 == 0) != (l1 == 0):
        raise ValueError("inconsistent norms")
    budget = F(radius-deterministic)-mean*l1
    if budget <= 0:
        return None
    if s2 == 0 or all(c == 0 for _,c in bounds):
        return 1000000  # zero random error: deterministic budget alone suffices
    if maximum == 0:
        raise ValueError("inconsistent norms")
    exponent = F(0)
    for a, c in bounds:
        tilt = min(budget/(c*s2), a/maximum)
        exponent = max(exponent, tilt*budget-c*tilt**2*s2/2)
    # 2*cols <= 2^union_bits; LN2_UPPER deliberately rounds up.
    union_bits = (2*cols-1).bit_length()
    return max(0, int(exponent // LN2_UPPER)-union_bits)


def validate_native_sampler(report):
    """Require the exact frozen distribution used by native clients/errors.

    Legacy local reports may omit the digest, but their complete multiplicities
    must still match. A self-declared hash never substitutes for this comparison.
    """
    table = [int(x) for x in (Path(__file__).resolve().parents[2] / 'src/native_gaussian_cdf.txt').read_text().split()]
    digest = hashlib.sha256(b''.join(x.to_bytes(8, 'little') for x in table)).hexdigest()
    counts, previous = [], 0
    for i, threshold in enumerate(table):
        end = threshold + 1
        counts.append((i - 65, end - previous))
        previous = end
    counts[65] = (0, counts[65][1] + 2**64 - previous)
    if [(int(x), int(n)) for x, n in report['sampler_counts']] != counts:
        raise ValueError('native sampler distribution does not match frozen CDF')
    if report.get('sampler_sha256', digest) != digest:
        raise ValueError('native sampler identity mismatch')
    return digest


def evaluate(report):
    validate_native_sampler(report)
    if report.get('format') in ('native-noise-two-mask-v1','native-noise-two-mask-rounded-v1'):
        return evaluate_two_mask(report)
    rounded = report['format'] == 'native-noise-rounded-v1'
    if report['format'] != 'native-noise-v1' and not rounded:
        raise ValueError('unknown report format')
    d, qb, pb = (int(report[k]) for k in ('d', 'q_bits', 'p_bits'))
    cols = int(report['cols'])
    mask_bits = int(report.get('published_mask_bits', 64))
    if rounded:
        # One-mask rounded publication: 54 is lossless bit-packing, 28..32 is
        # modulus switching. The block weights must equal the selected screen.
        if mask_bits != 54 and mask_bits not in range(28, 33):
            raise ValueError('invalid one-mask public precision')
        if report.get('published_bytes') != 36 + (cols*mask_bits+7)//8:
            raise ValueError('public-mask byte count mismatch')
        for block in report['blocks']:
            screens = block.get('public_mask_screens', [])
            if sorted(v['bits'] for v in screens) != list(range(24, 33)):
                raise ValueError('incomplete one-mask precision screens')
            if mask_bits != 54 and next(v['weights'] for v in screens if v['bits'] == mask_bits) != block['weights']:
                raise ValueError('rounded mask weights/precision mismatch')
    elif mask_bits != 64:
        raise ValueError('legacy report with nonlegacy mask precision')
    if (d,qb,pb) != (2048,54,16) or cols <= 0 or cols % d or len(report['blocks']) != cols//d:
        raise ValueError('unsupported profile or incomplete block coverage')
    if report['query_bits'] != 49 or report['response_bits'] != 22:
        raise ValueError('unsupported transport')
    if not 40 <= report['kh_bits'] <= 54 or report['rows'] <= 0 or report['rows'] % d:
        raise ValueError('unsupported precision or row count')
    for block in report['blocks']:
        if not 0 <= int(block['query_l1']) <= report['rows']*65535 or not 0 <= int(block['kh_l1']) <= 2*d*2**18:
            raise ValueError('invalid deterministic weight budget')
        if sorted(v['bits'] for v in block['one_limb']) != list(range(25,30)):
            raise ValueError('incomplete candidate coverage')
    mean, bounds = sampler_bounds(report['sampler_counts'])
    support = max(abs(int(x)) for x,n in report['sampler_counts'] if int(n))
    radius = 1 << (qb-pb-1)
    def assess(bits, candidate=None):
        scores = []
        max_deterministic = 0
        for block in report['blocks']:
            deterministic = support*d*d + int(block['query_l1'])*16 + (1 << 31)
            if candidate is None:
                deterministic += int(block['kh_l1'])*(0 if bits == 54 else 1 << (53-bits))
                weights = block['weights']
            else:
                weights = next(v['weights'] for v in block['one_limb'] if v['bits'] == candidate)
            max_deterministic = max(max_deterministic, deterministic)
            scores.append(certified_bits(weights,radius,deterministic,cols,mean,bounds))
        score = None if any(x is None for x in scores) else min(scores)
        return {'certified_failure_bits':score, 'meets_78':score is not None and score>=78,
                'meets_128':score is not None and score>=128,
                'max_deterministic_error':str(max_deterministic)}
    compression = [{'kh_bits':t, 'key_bytes':2048*2*(54+t)//8, **assess(t)} for t in range(40,55)]
    one_limb = [{'digit_bits':b,'discarded_bits':54-b,**assess(54,b)} for b in range(25,30)]
    # Other precisions change setup identity and therefore the actual mask trace.
    # These sweep results are counterfactual screening; rerun native_noise at the
    # selected precision before calling it a certificate for that profile.
    actual = dict(next(v for v in compression if v['kh_bits']==report['kh_bits']))
    if rounded:
        actual.update(published_mask_bits=mask_bits, published_bytes=report['published_bytes'])
    return {'format':'native-certificate-rounded-v1' if rounded else 'native-certificate-v1','setup_id':report['setup_id'],
            'database_sha256':report['database_sha256'],'sampler_sha256':validate_native_sampler(report),'actual_kh_bits':report['kh_bits'],
            'actual_profile':actual,
            'compression_screen':compression,'one_limb_screen':one_limb,
            'smallest_screened_bits_78':next((v['kh_bits'] for v in compression if v['meets_78']),None),
            'smallest_screened_bits_128':next((v['kh_bits'] for v in compression if v['meets_128']),None)}


def evaluate_two_mask(report):
    rounded = report['format'] == 'native-noise-two-mask-rounded-v1'
    mask_bits = report.get('published_mask_bits',64)
    # 54 is lossless bit-packing: same weights as exact publication.
    if (rounded and mask_bits != 54 and mask_bits not in range(27,33)) or (not rounded and mask_bits!=64):
        raise ValueError('invalid public-mask precision or format')
    d, qb, pb = (int(report[k]) for k in ('d', 'q_bits', 'p_bits'))
    cols, rows = int(report['cols']), int(report['rows'])
    if (d, qb, pb) != (2048, 54, 16) or cols <= 0 or cols % d or rows <= 0 or rows % d:
        raise ValueError('unsupported two-mask profile')
    if len(report['blocks']) != cols // d or report['query_bits'] != 49 or report['response_bits'] != 22 or report['kh_bits'] != 54:
        raise ValueError('incomplete two-mask report')
    published_bytes=36+((2*cols*mask_bits+7)//8)
    if rounded and report.get('published_bytes')!=published_bytes:
        raise ValueError('public-mask byte count mismatch')
    mean, bounds = sampler_bounds(report['sampler_counts'])
    support = max(abs(int(x)) for x, n in report['sampler_counts'] if int(n))
    scores, max_deterministic = [], 0
    for block in report['blocks']:
        query_l1 = int(block['query_l1'])
        if not 0 <= query_l1 <= rows * 65535 or int(block['kh_l1']) != 0 or block['one_limb']:
            raise ValueError('invalid two-mask block')
        if rounded:
            screens=block.get('public_mask_screens',[])
            if sorted(v['bits'] for v in screens)!=list(range(27,33)) or (mask_bits!=54 and next(v['weights'] for v in screens if v['bits']==mask_bits)!=block['weights']):
                raise ValueError('rounded mask weights/precision mismatch')
        deterministic = support*d*d + query_l1*16 + (1 << 31)
        max_deterministic = max(max_deterministic, deterministic)
        scores.append(certified_bits(block['weights'], 1 << (qb-pb-1), deterministic, cols, mean, bounds))
    score = None if any(x is None for x in scores) else min(scores)
    actual = {'key_bytes':d*2*qb//8, 'certified_failure_bits':score,
              'meets_78':score is not None and score >= 78,
              'meets_128':score is not None and score >= 128,
              'max_deterministic_error':str(max_deterministic)}
    if rounded:
        actual.update(published_mask_bits=mask_bits,published_bytes=published_bytes,no_extra_download=published_bytes<=36+cols*8)
    return {'format':'native-certificate-two-mask-rounded-v1' if rounded else 'native-certificate-two-mask-v1','setup_id':report['setup_id'],
            'database_sha256':report['database_sha256'],'sampler_sha256':validate_native_sampler(report),'actual_profile':actual}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report')
    parser.add_argument('--require-bits', type=int, default=128,
                        help='exit unsuccessfully unless the actual profile meets this target (default: 128)')
    args = parser.parse_args()
    with open(args.report) as f:
        result = evaluate(json.load(f))
    print(json.dumps(result,indent=2))
    score = result['actual_profile']['certified_failure_bits']
    if score is None or score < args.require_bits:
        print('Actual profile does not meet the requested correctness bound.',file=sys.stderr)
        sys.exit(1)
