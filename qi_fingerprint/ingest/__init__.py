"""Ingest real signature corpora into the pipeline's `Corpus` format.

Everything the pipeline consumes has, until now, been produced by
``qi_fingerprint.generator`` -- which is exactly the limitation the README states:
green tests prove internal consistency, not real-world efficacy. This package
converts real Bitcoin transactions into the same `Corpus` the synthetic generator
emits, so ``qi run --corpus <dir>`` can operate on data this project did not make.

Layout, and the reason for it:

    codec.py     PURE  bytes -> varints, script pushes, DER signatures, pubkeys
    tx.py        PURE  bytes -> Tx, and back; txid, merkle root, header, PoW
    sighash.py   PURE  Tx + index + scriptCode -> z, the digest actually signed
    extract.py   PURE  one input -> (r, s, z, Q) or a counted skip
    validate.py  PURE  the ecdsa_verify gate
    sources.py   IO    the ONLY module that opens a socket
    bitcoin.py   GLUE  orchestration and corpus assembly

Only `sources` performs IO, so every other module is a pure function of bytes and
is testable offline with no network and no monkeypatching.
"""
