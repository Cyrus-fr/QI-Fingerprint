"""Phase B: turning an r-collision candidate into a verified recovery.

Two things are being pinned here.

The first is that recovery works end to end on transactions the extractor has
never seen: scan -> refetch -> recompute z from the prevout script -> verify gate
-> ``d*G == Q``. Including the mixed-sign case, where the same-sign formula alone
returns a wrong key that the gate rejects -- the failure that would otherwise
read as "nothing found" on a real corpus.

The second is §9: a recovered private key must not reach stdout, a log, a return
value or disk. `Confirmation` has no field for it, and the tests below check the
rendered report for the actual scalar rather than trusting that.
"""

import pytest

from qi_fingerprint.ingest.address import p2pkh_address
from qi_fingerprint.ingest.control import (
    Confirmation,
    ControlError,
    confirm_candidate,
)
from qi_fingerprint.ingest.extract import PrevOut
from qi_fingerprint.ingest.hunt import find_candidates, scan_block
from qi_fingerprint.ingest.sources import BlockRecord
from qi_fingerprint.ingest.validate import IngestGateError
from synth_bitcoin import CURVE, build_signed_tx

N = CURVE.n
D = 0xB1A5_C0DE_1234_5678_9ABC_DEF0_1122_3344
K = 0x5EED_0F_C0FFEE_1234_5678_9ABC_DEF0_2233


class StubSource:
    """A `BlockSource` over hand-built blocks.

    `BlockRecord.check()` is deliberately not called: these blocks carry no proof
    of work, and what is under test is the extraction and recovery path. The
    check that matters here still runs -- `confirm_candidate` puts every
    signature through the same `ecdsa_verify` gate the corpus builder uses.
    """

    def __init__(self, blocks: dict[int, list]) -> None:
        self._blocks = {
            height: BlockRecord(height, f"{height:064x}", b"\x00" * 80, txs)
            for height, txs in blocks.items()
        }
        self.fetches = 0

    def block(self, height: int) -> BlockRecord:
        self.fetches += 1
        if height not in self._blocks:
            raise KeyError(height)
        return self._blocks[height]


def _reuse_across_blocks(nonce_a: int, nonce_b: int, *, compressed=True):
    """Two blocks, one key, one shared nonce (up to the sign given)."""
    tx_a, prevouts_a = build_signed_tx(
        D, [nonce_a], funding=[(b"\x11" * 32, 0)], compressed=compressed
    )
    tx_b, prevouts_b = build_signed_tx(
        D, [nonce_b], funding=[(b"\x22" * 32, 1)], compressed=compressed
    )
    source = StubSource({100: [(tx_a, prevouts_a)], 140: [(tx_b, prevouts_b)]})

    sites = scan_block([tx_a], 100) + scan_block([tx_b], 140)
    candidates = find_candidates(sites)
    assert len(candidates) == 1, "the two signatures must share an r"
    return candidates[0], source


def test_same_sign_reuse_is_recovered():
    candidate, source = _reuse_across_blocks(K, K)
    result = confirm_candidate(candidate, source)

    assert result.recovered
    assert result.detail == "same-sign pair"
    assert result.provenance == tuple(
        (s.txid, s.vin) for s in sorted(candidate.sites, key=lambda s: s.height)
    )


def test_mixed_sign_reuse_is_recovered_and_named():
    """The §8 case. Signing the second input with -k is exactly what BIP146
    normalisation does to an on-chain signature."""
    candidate, source = _reuse_across_blocks(K, N - K)
    result = confirm_candidate(candidate, source)

    assert result.recovered
    assert result.detail == "mixed-sign pair -- required the s1+s2 branch"


def test_mixed_sign_pair_would_be_missed_without_the_low_s_branch():
    """Proves the previous test is not passing for an unrelated reason: the
    pre-§8 same-sign formula genuinely fails on this pair."""
    from qi_fingerprint.ingest.control import _same_sign_suffices
    from qi_fingerprint.ingest.extract import extract_tx

    candidate, source = _reuse_across_blocks(K, N - K)
    sigs = []
    for height in candidate.heights:
        for tx, prevouts in source.block(height).txs:
            sigs.extend(extract_tx(tx, prevouts, height)[0])

    Q = CURVE.point(candidate.qx, candidate.qy)
    assert not _same_sign_suffices(CURVE, sigs[0], sigs[1], Q)


def test_distinct_nonces_are_not_recoverable():
    """A candidate is a claim, not a finding: the gate is what decides."""
    tx_a, prevouts_a = build_signed_tx(D, [K], funding=[(b"\x11" * 32, 0)])
    tx_b, prevouts_b = build_signed_tx(D, [K + 1], funding=[(b"\x22" * 32, 1)])
    source = StubSource({100: [(tx_a, prevouts_a)], 140: [(tx_b, prevouts_b)]})

    sites = scan_block([tx_a], 100) + scan_block([tx_b], 140)
    assert find_candidates(sites) == []  # no r-collision to begin with


def test_the_address_is_the_one_that_was_spent_from():
    candidate, source = _reuse_across_blocks(K, K)
    result = confirm_candidate(candidate, source)
    Q = CURVE.pubkey(D)
    assert result.addresses == (p2pkh_address(Q.x, Q.y, compressed=True),)


def test_both_encodings_are_reported_when_both_were_used():
    """One key spending as compressed in one input and uncompressed in another
    is one key and two addresses."""
    tx_a, prevouts_a = build_signed_tx(
        D, [K], funding=[(b"\x11" * 32, 0)], compressed=True
    )
    tx_b, prevouts_b = build_signed_tx(
        D, [K], funding=[(b"\x22" * 32, 1)], compressed=False
    )
    source = StubSource({100: [(tx_a, prevouts_a)], 140: [(tx_b, prevouts_b)]})
    candidate = find_candidates(scan_block([tx_a], 100) + scan_block([tx_b], 140))[0]

    result = confirm_candidate(candidate, source)
    Q = CURVE.pubkey(D)
    assert result.recovered
    assert set(result.addresses) == {
        p2pkh_address(Q.x, Q.y, compressed=True),
        p2pkh_address(Q.x, Q.y, compressed=False),
    }


# --------------------------------------------------------------------------- #
# §9: the recovered key must not escape
# --------------------------------------------------------------------------- #


def test_confirmation_has_no_field_for_a_private_key():
    """The rule expressed as a type rather than as a promise."""
    fields = set(Confirmation.__dataclass_fields__)
    assert fields == {"candidate", "recovered", "addresses", "verified_sigs", "detail"}
    assert not any("key" in f or f == "d" for f in fields)


def test_the_recovered_scalar_appears_nowhere_in_the_report():
    candidate, source = _reuse_across_blocks(K, K)
    result = confirm_candidate(candidate, source)
    assert result.recovered

    rendered = "\n".join([result.format(), repr(result)])
    for encoding in (f"{D:x}", f"{D:064x}", str(D)):
        assert encoding.lower() not in rendered.lower()
    # the nonce is equally sensitive -- it yields d directly
    for encoding in (f"{K:x}", f"{K:064x}", str(K)):
        assert encoding.lower() not in rendered.lower()


def test_the_report_carries_what_a_reader_needs_to_check_it():
    """Provenance and address, which is the whole permitted output."""
    candidate, source = _reuse_across_blocks(K, K)
    rendered = confirm_candidate(candidate, source).format()

    assert "RECOVERED (d*G == Q)" in rendered
    for site in candidate.sites:
        assert f"{site.txid}:{site.vin}" in rendered
    assert p2pkh_address(CURVE.pubkey(D).x, CURVE.pubkey(D).y, True) in rendered


def test_no_http_request_in_the_package_can_carry_a_body():
    """"Cannot broadcast" as a structural property, not a word search.

    Publishing a transaction to any node or explorer API requires a request with
    a body -- a POST. Every request this package makes is a bodyless GET, so
    there is no call site that could push anything back to the network. Checked
    on the syntax tree, because grepping for scary words flags the docstrings
    that promise the opposite.
    """
    import ast
    import pathlib

    package = pathlib.Path(__file__).resolve().parent.parent / "qi_fingerprint"
    inspected = 0
    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = ast.unparse(node.func)
            if not (target.endswith("Request") or target.endswith("urlopen")):
                continue
            inspected += 1
            keywords = {kw.arg for kw in node.keywords}
            assert "data" not in keywords, f"{path.name}: request carries a body"
            assert "method" not in keywords, f"{path.name}: request overrides the verb"
            # urlopen(req, timeout=...) / Request(url, headers=...): the second
            # positional parameter of both is `data`.
            assert len(node.args) <= 1, f"{path.name}: positional request body"
    assert inspected >= 2, "found no request call sites -- the check went vacuous"


def test_an_ingested_corpus_carries_no_private_key_column():
    """`KeyRecord` has a ground-truth `d` field for synthetic corpora. Real
    ingest must leave it empty, so a recovered key has nowhere to be persisted
    even by accident."""
    from qi_fingerprint.ingest.bitcoin import build_corpus
    from qi_fingerprint.ingest.extract import extract_tx

    tx, prevouts = build_signed_tx(D, [K, K])
    sigs, _skips = extract_tx(tx, prevouts, 100)
    corpus, provenance = build_corpus(sigs)

    assert corpus.keys and all(key.d is None for key in corpus.keys)
    assert all(key.bias_type is None for key in corpus.keys)
    assert all(sig.true_k is None for sig in corpus.signatures)
    assert not any(
        "priv" in field or field == "d" for field in vars(provenance[0])
    )


# --------------------------------------------------------------------------- #
# Failure paths
# --------------------------------------------------------------------------- #


def test_a_tampered_prevout_script_fails_the_gate():
    """A hostile or buggy source changes the scriptCode, which changes z. The
    control must refuse rather than report a failed recovery as 'key is safe'."""
    tx_a, prevouts_a = build_signed_tx(D, [K], funding=[(b"\x11" * 32, 0)])
    tx_b, prevouts_b = build_signed_tx(D, [K], funding=[(b"\x22" * 32, 1)])
    corrupt = bytearray(prevouts_b[0].script_pubkey)
    corrupt[5] ^= 0xFF

    source = StubSource(
        {
            100: [(tx_a, prevouts_a)],
            140: [(tx_b, [PrevOut(prevouts_b[0].value, bytes(corrupt))])],
        }
    )
    candidate = find_candidates(scan_block([tx_a], 100) + scan_block([tx_b], 140))[0]

    with pytest.raises((IngestGateError, ControlError)):
        confirm_candidate(candidate, source)


def test_an_unextractable_candidate_raises_rather_than_returning_false():
    """The scan's shape filter is looser than the extractor. If the two disagree
    that is a bug to surface, not a negative result to report."""
    tx_a, prevouts_a = build_signed_tx(D, [K], funding=[(b"\x11" * 32, 0)])
    tx_b, prevouts_b = build_signed_tx(D, [K], funding=[(b"\x22" * 32, 1)])
    # Replace the second prevout with a script the extractor will not classify
    # as P2PKH, so extract_tx skips it entirely.
    source = StubSource(
        {
            100: [(tx_a, prevouts_a)],
            140: [(tx_b, [PrevOut(prevouts_b[0].value, b"\x51")])],
        }
    )
    candidate = find_candidates(scan_block([tx_a], 100) + scan_block([tx_b], 140))[0]

    with pytest.raises(ControlError, match="re-extraction"):
        confirm_candidate(candidate, source)
