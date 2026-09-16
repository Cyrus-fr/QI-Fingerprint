"""Audit Stage 4: is cohort membership observable, or does it read the generator class?

Runs the FULL pipeline on the PUBLIC-ONLY view of the corpus -- generator_id,
bias_type, d, true_k and gen_index all ABSENT -- so anything it decides is provably
from (key_id, Qx, Qy, curve, h, r, s) alone. Ground truth is loaded separately,
used only to score.
"""

import tempfile
from collections import defaultdict

from qi_fingerprint.corpus import Corpus
from qi_fingerprint.generator import build_corpus
from qi_fingerprint.pipeline import run

corpus = build_corpus("secp256k1", seed=7)
tmp = tempfile.mkdtemp()
corpus.save(tmp)

public = Corpus.load(tmp, with_truth=False)  # NO ground-truth fields
assert all(k.bias_type is None and k.generator_id is None and k.d is None for k in public.keys)
assert all(s.true_k is None and s.gen_index is None for s in public.signatures)
print("pipeline input carries NO ground truth (asserted).\n")

truth = {k.key_id: k.bias_type for k in corpus.keys}      # scoring only
gen_id = {k.key_id: k.generator_id for k in corpus.keys}  # scoring only

result = run(public)
report = result.report

# 1) What groups 52's cohort, and by what observable signal?
cohort = next((sorted(c) for c in report.cohorts if 52 in c), [])
sbk = public.sigs_by_key()
r_to_members = defaultdict(set)
for kid in cohort:
    for s in sbk[kid]:
        r_to_members[s.r].add(kid)
linking = {r: sorted(ks) for r, ks in r_to_members.items() if len(ks) >= 2}

print("cohort containing key 52 (observable r-collision component):")
print(f"  members      : {cohort}")
print(f"  true bias    : {sorted({truth[k] for k in cohort})}")
print(f"  true gen_id  : {sorted({gen_id[k] for k in cohort})}")
print(f"  linked by    : {len(linking)} shared r-value(s)")
for r, ks in sorted(linking.items())[:1]:
    print(f"    e.g. r={hex(r)[:20]}... carried by keys {ks}")

# 2) Do observable cohorts recover the true (generator) cohorts? (GT used only to score)
print("\ncohort purity -- observable cohort -> distinct true generator_ids:")
pure = 0
for c in sorted(report.cohorts, key=min):
    gids = {gen_id[k] for k in c}
    pure += int(len(gids) == 1)
    print(f"  {sorted(c)} -> gen_id {sorted(gids)}  [{'PURE' if len(gids) == 1 else 'MIXED'}]")
print(f"  {pure}/{len(report.cohorts)} observable cohorts are single-generator")

# 3) Propagation-only accuracy (keys labelled by propagation, not by their own crack)
prop = [(kid, a) for kid, a in result.attributions.items() if a.source == "propagated"]
correct = sum(1 for kid, a in prop if a.label == truth[kid])
print(f"\npropagated keys (source=='propagated'): {len(prop)}")
print(f"  correct vs truth: {correct}/{len(prop)} = {100 * correct / max(len(prop), 1):.1f}%")

# 4) GT-invariance: identical output with GT present vs absent -> GT is never read.
full = run(corpus)
same_cohorts = sorted(map(sorted, report.cohorts)) == sorted(map(sorted, full.report.cohorts))
same_attr = {k: (a.label, a.source) for k, a in result.attributions.items()} == {
    k: (a.label, a.source) for k, a in full.attributions.items()
}
print(f"\npublic-only run  ==  with-truth run:  cohorts={same_cohorts}  attributions={same_attr}")
