#!/bin/zsh
set -u
S=/private/tmp/claude-501/-Users-roman-projects-ipir-sp--claude-worktrees-pir-bandwidth-reduction-c696a5/3f0c46d1-0fc2-4a1b-b9e7-639e74785817/scratchpad
cd $S/proto
export RAYON_NUM_THREADS=8 PROTO_QUERY_BITS=31 PROTO_RESPONSE_BITS=5
# noise export: profile p=2^12 with uniform 12-bit entries (upper-bounds merged c <= 3855)
PROTO_PBITS=12 PROTO_ELL=1 PROTO_BASE=27 target/release/examples/native_noise 12288 131072 54 20 --two-mask > $S/exp/noise-radix-l1-m20.json 2> $S/exp/noise-radix-l1-m20.err
target/release/examples/native_radix 12288 131072 1 27 13 20 > $S/exp/radix-l1-m20.jsonl 2> $S/exp/radix-l1-m20.err
echo done > $S/exp/DONE-radix
