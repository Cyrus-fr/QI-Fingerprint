"""QI-Fingerprint: ECDSA nonce-bias triage over unlabeled signature corpora.

Pipeline stages:
    Screen      -> population statistics flag low-entropy cohorts (no key needed)
    Crack       -> HNP + LLL/BKZ lattice recovery, gated on d*G == Q
    Fingerprint -> reconstruct true nonces, classify the root-cause bias
    Propagate   -> attribute the diagnosis across the cohort
"""

__version__ = "0.1.0"
