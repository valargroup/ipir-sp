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


def certified_bits(weights, radius, deterministic, cols, mean, bounds, dither=0):
    """Integer lower bound on -log2(full-response failure probability).

    Each row uses an envelope of L1, squared L2 and maximum original weights.
    `dither` is the variance proxy of an extra zero-mean error that is
    sub-Gaussian for every tilt given all sampler draws (dithered query
    rounding). Union bound requires no independence between response
    coefficients/blocks.
    """
    l1, s2, maximum = (int(weights[k]) for k in ('l1', 'l2_squared', 'max'))
    dither = F(dither)
    if min(l1, s2, maximum, radius, deterministic, dither) < 0 or cols <= 0:
        raise ValueError("invalid norms/dimensions")
    if maximum > l1 or s2 > l1*maximum or (s2 == 0) != (l1 == 0):
        raise ValueError("inconsistent norms")
    budget = F(radius-deterministic)-mean*l1
    if budget <= 0:
        return None
    if dither == 0 and (s2 == 0 or all(c == 0 for _,c in bounds)):
        return 1000000  # zero random error: deterministic budget alone suffices
    if maximum == 0 and s2 != 0:
        raise ValueError("inconsistent norms")
    exponent = F(0)
    for a, c in bounds:
        # The sampler bound needs lambda*M <= a; the dither bound holds for all lambda.
        variance = c*s2 + dither
        tilt = budget/variance if maximum == 0 else min(budget/variance, a/maximum)
        exponent = max(exponent, tilt*budget-variance*tilt**2/2)
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


# Plaintext widths the two-mask checker supports. p = 2^16 values are the
# recorded profile; p = 2^8 is the small-plaintext research profile. Floors
# bound the screened/accepted dithered query and rounded public-mask widths.
PROFILES = {
    16: {'query_floor': 40, 'mask_floor': 27},
    8: {'query_floor': 24, 'mask_floor': 16},
}
LEGACY_GADGET = {'ell': 2, 'gadget_bits': 19}


def two_mask_profile(report):
    """Validated (p_bits, profile, ell, gadget_bits, response_bits) of a two-mask report."""
    pb = int(report['p_bits'])
    if pb not in PROFILES:
        raise ValueError('unsupported two-mask profile')
    ell = int(report.get('ell', LEGACY_GADGET['ell']))
    gadget = int(report.get('gadget_bits', LEGACY_GADGET['gadget_bits']))
    qb = int(report['q_bits'])
    if not 1 <= ell <= 8 or not 1 <= gadget <= 27 or not 0 <= qb - ell*gadget <= 27:
        raise ValueError('unsupported gadget')
    if 'dropped_bits' in report and int(report['dropped_bits']) != max(0, qb - ell*gadget):
        raise ValueError('inconsistent gadget')
    rb = int(report['response_bits'])
    if rb not in range(pb + 1, pb + 7):
        raise ValueError('unsupported transport')
    return pb, PROFILES[pb], ell, gadget, rb


# Format -> (two_mask, rounded public masks, dithered query). Dithered reports
# have their own formats, so checkers that predate dithering reject them.
REPORT_FORMATS = {f'native-noise{m}{r}{q}-v1': (bool(m), bool(r), bool(q))
                  for m in ('', '-two-mask') for r in ('', '-rounded') for q in ('', '-dithered')}


def report_format(report):
    """Validated (two_mask, rounded) mode; the format must match the query rounding."""
    if report.get('format') not in REPORT_FORMATS:
        raise ValueError('unknown report format')
    two_mask, rounded, dithered = REPORT_FORMATS[report['format']]
    if dithered != (report.get('query_rounding', 'nearest') == 'dithered'):
        raise ValueError('query rounding/report format mismatch')
    return two_mask, rounded


def query_transport(report, floor=40):
    """Validated (bits, dithered) query transport; 49-bit nearest is legacy."""
    bits, rounding = report['query_bits'], report.get('query_rounding', 'nearest')
    if (bits, rounding) == (49, 'nearest'):
        return bits, False
    if rounding == 'dithered' and bits in range(floor, 50):
        return bits, True
    raise ValueError('unsupported transport')


def query_terms(block, rows, bits, dithered, entry_max=65535):
    """Deterministic budget and variance proxy for query-body transport.

    Nearest rounding reserves its worst case, 2^(53-bits) times the column L1,
    assuming no independence. Dithered errors are independent, zero-mean and in
    an interval of width 2^(54-bits) given every sampler draw, so Hoeffding's
    lemma adds 2^(2(54-bits))/4 times the column squared L2 to the variance.
    """
    l1 = int(block['query_l1'])
    if not 0 <= l1 <= rows*entry_max:
        raise ValueError('invalid deterministic weight budget')
    if not dithered:
        return l1 << (53-bits), 0
    if 'query_l2_squared' not in block:
        raise ValueError('missing query weights')
    s2 = int(block['query_l2_squared'])
    if not l1 <= s2 <= l1*entry_max:
        raise ValueError('invalid query weights')
    return 0, F(s2 << (2*(54-bits)), 4)


def query_screen(report, assess, floor=40):
    """Counterfactual query precisions on this report's weights and setup."""
    if not all('query_l2_squared' in block for block in report['blocks']):
        return None  # legacy reports cannot screen dithered transport
    rows = int(report['rows'])
    return [{'query_bits':bits, 'query_rounding':'dithered' if dithered else 'nearest',
             'query_bytes':(rows*bits+7)//8, **assess((bits, dithered))}
            for bits, dithered in [(49, False)] + [(b, True) for b in range(49, floor - 1, -1)]]


def evaluate(report, screens=False):
    validate_native_sampler(report)
    two_mask, rounded = report_format(report)
    if two_mask:
        return evaluate_two_mask(report, rounded, screens)
    if screens:
        raise ValueError('--screens supports two-mask reports only')
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
    query = query_transport(report)
    if report['response_bits'] != 22:
        raise ValueError('unsupported transport')
    if not 40 <= report['kh_bits'] <= 54 or report['rows'] <= 0 or report['rows'] % d:
        raise ValueError('unsupported precision or row count')
    rows = int(report['rows'])
    for block in report['blocks']:
        query_terms(block, rows, *query)
        if not 0 <= int(block['kh_l1']) <= 2*d*2**18:
            raise ValueError('invalid deterministic weight budget')
        if sorted(v['bits'] for v in block['one_limb']) != list(range(25,30)):
            raise ValueError('incomplete candidate coverage')
    mean, bounds = sampler_bounds(report['sampler_counts'])
    support = max(abs(int(x)) for x,n in report['sampler_counts'] if int(n))
    radius = 1 << (qb-pb-1)
    def assess(bits, candidate=None, query=query):
        scores = []
        max_deterministic = 0
        for block in report['blocks']:
            query_budget, dither = query_terms(block, rows, *query)
            deterministic = support*d*d + query_budget + (1 << 31)
            if candidate is None:
                deterministic += int(block['kh_l1'])*(0 if bits == 54 else 1 << (53-bits))
                weights = block['weights']
            else:
                weights = next(v['weights'] for v in block['one_limb'] if v['bits'] == candidate)
            max_deterministic = max(max_deterministic, deterministic)
            scores.append(certified_bits(weights,radius,deterministic,cols,mean,bounds,dither))
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
    actual.update(query_bits=query[0], query_rounding=report.get('query_rounding','nearest'),
                  query_bytes=(rows*query[0]+7)//8)
    if rounded:
        actual.update(published_mask_bits=mask_bits, published_bytes=report['published_bytes'])
    screen = query_screen(report, lambda q: assess(report['kh_bits'], query=q))
    return {'format':'native-certificate-rounded-v1' if rounded else 'native-certificate-v1','setup_id':report['setup_id'],
            'database_sha256':report['database_sha256'],'sampler_sha256':validate_native_sampler(report),'actual_kh_bits':report['kh_bits'],
            'actual_profile':actual,
            'compression_screen':compression,'one_limb_screen':one_limb,
            'smallest_screened_bits_78':next((v['kh_bits'] for v in compression if v['meets_78']),None),
            'smallest_screened_bits_128':next((v['kh_bits'] for v in compression if v['meets_128']),None),
            'query_screen':screen,
            'smallest_screened_query_bits_128':min((v['query_bits'] for v in screen or [] if v['meets_128']),default=None)}


def evaluate_two_mask(report, rounded, screens=False):
    pb, profile, ell, gadget, rb = two_mask_profile(report)
    legacy = (pb, ell, gadget, rb) == (16, 2, 19, 22)
    mask_floor, query_floor = profile['mask_floor'], profile['query_floor']
    mask_bits = report.get('published_mask_bits',64)
    # 54 is lossless bit-packing: same weights as exact publication.
    if (rounded and mask_bits != 54 and mask_bits not in range(mask_floor,33)) or (not rounded and mask_bits!=64):
        raise ValueError('invalid public-mask precision or format')
    d, qb = (int(report[k]) for k in ('d', 'q_bits'))
    cols, rows = int(report['cols']), int(report['rows'])
    if (d, qb) != (2048, 54) or cols <= 0 or cols % d or rows <= 0 or rows % d:
        raise ValueError('unsupported two-mask profile')
    query = query_transport(report, query_floor)
    if len(report['blocks']) != cols // d or report['kh_bits'] != qb:
        raise ValueError('incomplete two-mask report')
    entry_max = (1 << pb) - 1
    published_bytes=36+((2*cols*mask_bits+7)//8)
    if rounded and report.get('published_bytes')!=published_bytes:
        raise ValueError('public-mask byte count mismatch')
    mean, bounds = sampler_bounds(report['sampler_counts'])
    support = max(abs(int(x)) for x, n in report['sampler_counts'] if int(n))
    for block in report['blocks']:
        if int(block['kh_l1']) != 0 or block['one_limb']:
            raise ValueError('invalid two-mask block')
        if rounded:
            screens_present=block.get('public_mask_screens',[])
            if sorted(v['bits'] for v in screens_present)!=list(range(mask_floor,33)) or (mask_bits!=54 and next(v['weights'] for v in screens_present if v['bits']==mask_bits)!=block['weights']):
                raise ValueError('rounded mask weights/precision mismatch')
    radius = 1 << (qb-pb-1)
    def assess(query, response=rb, weights_of=lambda block: block['weights'], worst=False):
        scores, max_deterministic = [], 0
        for block in report['blocks']:
            if worst:
                # Data-independent column norms: every entry at p-1.
                block = dict(block, query_l1=str(rows*entry_max), query_l2_squared=str(rows*entry_max**2))
            query_budget, dither = query_terms(block, rows, *query, entry_max=entry_max)
            deterministic = support*d*d + query_budget + (1 << (qb-1-response))
            max_deterministic = max(max_deterministic, deterministic)
            scores.append(certified_bits(weights_of(block), radius, deterministic, cols, mean, bounds, dither))
        score = None if any(x is None for x in scores) else min(scores)
        return {'certified_failure_bits':score,
                'meets_78':score is not None and score >= 78,
                'meets_128':score is not None and score >= 128,
                'max_deterministic_error':str(max_deterministic)}
    actual = {'key_bytes':ell*d*qb//8, **assess(query), 'query_bits':query[0],
              'query_rounding':report.get('query_rounding','nearest'), 'query_bytes':(rows*query[0]+7)//8}
    screen = query_screen(report, assess, query_floor)
    if rounded:
        actual.update(published_mask_bits=mask_bits,published_bytes=published_bytes,no_extra_download=published_bytes<=36+cols*8)
    if not legacy:
        actual.update(p_bits=pb, ell=ell, gadget_bits=gadget, response_bits=rb,
                      response_bytes=68+(cols*rb+7)//8)
    result = {'format':'native-certificate-two-mask-rounded-v1' if rounded else 'native-certificate-two-mask-v1','setup_id':report['setup_id'],
            'database_sha256':report['database_sha256'],'sampler_sha256':validate_native_sampler(report),'actual_profile':actual,
            'query_screen':screen,
            'smallest_screened_query_bits_128':min((v['query_bits'] for v in screen or [] if v['meets_128']),default=None)}
    if screens:
        result['screens'] = width_screens(report, assess, query, rb, mask_bits, mask_floor, query_floor,
                                          ell*d*qb//8, rows, cols, pb)
    return result


def width_screens(report, assess, query, rb, mask_bits, mask_floor, query_floor, key_bytes, rows, cols, pb):
    """Counterfactual widths on this report's weights. Every width is bound into
    the setup ID, so a chosen combination must be regenerated and certified."""
    if not all('query_l2_squared' in b and 'public_mask_screens' in b for b in report['blocks']):
        raise ValueError('screens need dithered query weights and public-mask screens')
    def mask_weights(bits):
        return lambda block: next(v['weights'] for v in block['public_mask_screens'] if v['bits'] == bits)
    masks = list(range(mask_floor, 33))
    responses = list(range(pb + 1, pb + 7))
    def smallest_query(response, mask):
        lo, hi = query_floor, 49
        if not assess((hi, True), response, mask_weights(mask))['meets_128']:
            return None
        while lo < hi:  # certified bits increase with query precision
            mid = (lo + hi) // 2
            if assess((mid, True), response, mask_weights(mask))['meets_128']:
                hi = mid
            else:
                lo = mid + 1
        return lo
    frontier = []
    for response in responses:
        for mask in masks:
            bits = smallest_query(response, mask)
            if bits is None:
                continue
            request = 36 + key_bytes + (rows*bits+7)//8
            response_bytes = 68 + (cols*response+7)//8
            published = 36 + (2*cols*mask+7)//8
            frontier.append({'response_bits': response, 'published_mask_bits': mask, 'query_bits': bits,
                             'request_bytes': request, 'response_bytes': response_bytes,
                             'published_bytes': published,
                             'certified_failure_bits': assess((bits, True), response, mask_weights(mask))['certified_failure_bits']})
    actual_mask = mask_bits if mask_bits in masks else None
    return {
        'counterfactual': True,
        'mask_screen': [{'published_mask_bits': m, **assess(query, rb, mask_weights(m))} for m in masks],
        'response_screen': [{'response_bits': r, **assess(query, r, mask_weights(actual_mask) if actual_mask else (lambda b: b['weights']))}
                            for r in responses],
        'width_frontier': frontier,
        'worst_case_query': assess(query, rb, worst=True),
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report')
    parser.add_argument('--require-bits', type=int, default=128,
                        help='exit unsuccessfully unless the actual profile meets this target (default: 128)')
    parser.add_argument('--screens', action='store_true',
                        help='two-mask only: add counterfactual mask/response screens, the width frontier '
                             'and a data-independent worst-case query bound')
    args = parser.parse_args()
    with open(args.report) as f:
        result = evaluate(json.load(f), screens=args.screens)
    print(json.dumps(result,indent=2))
    score = result['actual_profile']['certified_failure_bits']
    if score is None or score < args.require_bits:
        print('Actual profile does not meet the requested correctness bound.',file=sys.stderr)
        sys.exit(1)
