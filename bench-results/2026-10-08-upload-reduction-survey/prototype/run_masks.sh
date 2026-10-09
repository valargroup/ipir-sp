#!/bin/zsh
set -u
S=/private/tmp/claude-501/-Users-roman-projects-ipir-sp--claude-worktrees-pir-bandwidth-reduction-c696a5/3f0c46d1-0fc2-4a1b-b9e7-639e74785817/scratchpad
cd $S/proto
export RAYON_NUM_THREADS=8 PROTO_PBITS=4 PROTO_QUERY_BITS=23 PROTO_RESPONSE_BITS=5
for cfg in "2 19" "1 27"; do
  set -- ${=cfg}; ell=$1; base=$2
  export PROTO_ELL=$ell PROTO_BASE=$base
  target/release/examples/native_noise 24576 131072 54 20 --two-mask > $S/exp/noise-p4-l$ell-m20.json 2> $S/exp/noise-p4-l$ell-m20.err
  python3 reinspiring/tools/security/certify_native.py $S/exp/noise-p4-l$ell-m20.json --require-bits 128 > $S/exp/cert-p4-l$ell-m20.json 2>&1
  echo "cert exit $?" >> $S/exp/cert-p4-l$ell-m20.json
done
# quiet timing runs (nothing else running), 20-bit masks
for cfg in "2 19" "1 27"; do
  set -- ${=cfg}; ell=$1; base=$2
  export PROTO_ELL=$ell PROTO_BASE=$base
  target/release/examples/native_e2e 24576 131072 4 $ell 10 1 0 20 > $S/exp/e2e-p4-l$ell-m20.jsonl 2> $S/exp/e2e-p4-l$ell-m20.err
done
# matched baseline on this host: current native p16 two-mask 29-bit
unset PROTO_PBITS PROTO_QUERY_BITS PROTO_RESPONSE_BITS PROTO_ELL PROTO_BASE
target/release/examples/native_e2e 28672 32768 16 2 10 1 0 29 > $S/exp/e2e-baseline-p16.jsonl 2> $S/exp/e2e-baseline-p16.err
echo done > $S/exp/DONE-masks
