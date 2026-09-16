"""Pinned mainnet fixtures for the SegWit v0 and P2PK extraction paths.

Real transactions, captured as hex constants so the test suite needs no network
and no data files. Every `z` here was produced by this package and then confirmed
with `ecdsa_verify` against the on-chain signature, so these are known-answer
tests rather than self-fulfilling snapshots -- which matters more here than
anywhere else in the suite, because a *synthetic* SegWit signature cannot
validate BIP143 at all: signing a digest we computed ourselves and verifying
against it passes whatever the digest was.

Note `AMOUNT` on the two witness cases. BIP143 commits to the value of the output
being spent, so these fixtures also pin the amount, and
`test_ingest_segwit.py` asserts that perturbing it by one satoshi breaks
verification.

Regenerate only from real chain data; never hand-edit a value.
"""

# --------------------------------------------------------------------------- #
# Native P2WPKH -- block 800,000
# --------------------------------------------------------------------------- #
P2WPKH_HEIGHT = 800000
P2WPKH_TXID = "d41f5de48325e79070ccd3a23005f7a3b405f3ce1faa4df09f6d71770497e9d5"
P2WPKH_RAW = (
    "020000000001016504bf2c6f9736a3af23a9693e81ef69a70e974f91c6ef3d2e38b7bedd"
    "db92a90100000000ffffffff02e42f0200000000002251202d618c1f73d5133fdc97d545"
    "bfbf55b4cba2ab2a9d41e4596b1df6b8ea9d93480b7404000000000016001464dbbc84f1"
    "2f32699ca5010faa618d6a25559b6f02483045022100f404e977e0a3dee1e9da7708db6c"
    "e6f3cbe80e6ffbbb6364bd2c725af200520a02201faca96001ac7f82fcea71e03b29deea"
    "ac6525c3bb8abe3b3c64544af16b69850121025b1b8e6cd2ebc837fc57928c688b9b4d19"
    "2f9001d03d1831510a6e511ca3fa5e00000000"
)
P2WPKH_PREVOUT_SPK = "001464dbbc84f12f32699ca5010faa618d6a25559b6f"
P2WPKH_AMOUNT = 604308
P2WPKH_Z = 0x78ADC06E6508558B031920FD7B49D5F877D75DE112E8174F4B1F8457D9CD2A8A

# --------------------------------------------------------------------------- #
# P2SH-wrapped P2WPKH -- block 800,000
# --------------------------------------------------------------------------- #
P2SH_P2WPKH_HEIGHT = 800000
P2SH_P2WPKH_TXID = "7110dd4fbc69136c243988d415a210fde0ad460fcd74080ebc83f330c45bf45f"
P2SH_P2WPKH_RAW = (
    "020000000001011aad797ee1f04ee744a36ccbd399c71e981717f586eb03ccd163b4d2f0"
    "bb5257000000001716001474d064027dd228e80a49957c744532e91fe8bc7affffffff02"
    "18790000000000002251208c92e5000e6e02c459f5da1508b8b51df6d375e4f6997c8c2f"
    "02fb9051c5e4750c6200000000000017a9147ebd5e5726b9f53038176541ad99d34a87c6"
    "667c8702483045022100cf8412f9114bd483c58cdba5d95ea3764c82dd05839127dead7c"
    "1a67d69945490220030ea21e373c339b0e1f3c5dfb3d207d358b6881ed4b22891c6431f5"
    "9a45c7cb0121032961838aee846d4ca1ac6f0dcf77c616eeaf9798e249b6e9ebab5ff9c8"
    "ccd63200000000"
)
P2SH_P2WPKH_PREVOUT_SPK = "a9147ebd5e5726b9f53038176541ad99d34a87c6667c87"
P2SH_P2WPKH_AMOUNT = 74000
P2SH_P2WPKH_Z = 0xDD3AC7432252A67A0CB8100660E2C948D6C1D7BFAA1BA70A310E7D5B72A8498A
#: The 22-byte witness program the scriptSig pushes; it must hash160 to the
#: 20 bytes inside the P2SH scriptPubKey above, or the input opens nothing.
P2SH_P2WPKH_REDEEM = "001474d064027dd228e80a49957c744532e91fe8bc7a"

# --------------------------------------------------------------------------- #
# Legacy P2PK -- block 250,000, an uncompressed key in the output being spent
# --------------------------------------------------------------------------- #
P2PK_HEIGHT = 250000
P2PK_TXID = "dfc26b9bc22610474c5369fbb0ba010d4ca18aba2162558a992746806f52ee81"
P2PK_RAW = (
    "010000000190f65b482976e41c311ceec14a61984f9907578b452b0c1a0f1c8bb4411475"
    "0600000000494830450220463a72fe8c63d033401748c3c5bc7826d3980dcfa2c0375a66"
    "9a1cf3565b81f4022100d96898f5fbd558cfbe13a23bad3ba31c05c8e5c36e386d131717"
    "4add6c24c7f301ffffffff022adbb7f400000000434104a39b9e4fbd213ef24bb9be69de"
    "4a118dd0644082e47c01fd9159d38637b83fbcdc115a5d6e970586a012d1cfe3e3a8b1a3"
    "d04e763bdc5a071c0e827c0bd834a5ac40420f00000000001976a914a7df68aa5cb81a41"
    "09f4d130505c1e06bd276aa688ac00000000"
)
#: <pubkey> OP_CHECKSIG. The public key lives HERE, not in the scriptSig, which
#: is why a P2PK input cannot be found by the prevout-free hunt.
P2PK_PREVOUT_SPK = (
    "4104a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbcdc11"
    "5a5d6e970586a012d1cfe3e3a8b1a3d04e763bdc5a071c0e827c0bd834a5ac"
)
P2PK_AMOUNT = 4106689898
