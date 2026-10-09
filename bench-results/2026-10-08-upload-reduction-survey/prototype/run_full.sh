#!/bin/zsh
set -u
S=/private/tmp/claude-501/-Users-roman-projects-ipir-sp--claude-worktrees-pir-bandwidth-reduction-c696a5/3f0c46d1-0fc2-4a1b-b9e7-639e74785817/scratchpad
cd $S/proto
export RAYON_NUM_THREADS=8
# L=4 (p=2^4), 64 blocks, two-mask, 2 limbs, 27-bit masks, 23-bit query, 5-bit response
PROTO_PBITS=4 PROTO_QUERY_BITS=23 PROTO_RESPONSE_BITS=5 /usr/bin/time -l target/release/examples/native_noise 24576 131072 54 27 --two-mask > $S/exp/noise-p4.json 2> $S/exp/noise-p4.err
python3 reinspiring/tools/security/certify_native.py $S/exp/noise-p4.json --require-bits 128 > $S/exp/cert-p4.json 2>&1
echo "cert exit $?" >> $S/exp/cert-p4.json
PROTO_QUERY_BITS=23 PROTO_RESPONSE_BITS=5 /usr/bin/time -l target/release/examples/native_e2e 24576 131072 4 2 6 1 0 27 > $S/exp/e2e-p4.jsonl 2> $S/exp/e2e-p4.err
echo done > $S/exp/DONE
