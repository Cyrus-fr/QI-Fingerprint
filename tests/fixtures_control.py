"""The Phase B positive control: a real mainnet key with genuine nonce reuse.

Discovered, not remembered. `tools/find_reuse.py` scanned blocks 250,000-252,500
of the Bitcoin main chain -- 527,292 signatures -- and found exactly one same-key
r-collision. This is it, pinned so the recovery path can never silently stop
working.

    block   252,474   000000000000004c9303d897ab63bac9978a3058f2b253acf50062056e4c5830
    time    2013-08-16T15:43:44Z
    tx      f92d4310ccc12bc41d2e51ab17b80c942a9343fce7a63a41e3d2db646fe05661
    inputs  0 and 1, both spending 19qnLpn9it7csR9sEay1XrFyfAmUNoXYk4

Both inputs carry the *same* r, so both were signed with the same nonce -- inside
one transaction, by one wallet, five days after the Android `SecureRandom`
advisory of 2013-08-11 that the plan named as the era to hunt in.

Reproduce with:

    docker compose run --rm pipeline python tools/find_reuse.py \\
        --start 252474 --end 252474

**Everything here is public chain data**: the transaction as it was mined, the
scripts of the outputs it spends, and the (r, s, z, Q) each input commits to.
The private key is deliberately absent. It is recomputable from these values in
microseconds -- which is the whole point of the control, and exactly why it is
not written down. See the safety note in `qi_fingerprint/ingest/control.py`.
"""

BLOCK_HEIGHT = 252474
BLOCK_HASH = "000000000000004c9303d897ab63bac9978a3058f2b253acf50062056e4c5830"
BLOCK_TIME_UTC = "2013-08-16T15:43:44"
TXID = "f92d4310ccc12bc41d2e51ab17b80c942a9343fce7a63a41e3d2db646fe05661"
ADDRESS = "19qnLpn9it7csR9sEay1XrFyfAmUNoXYk4"

RAW_TX = (
    "0100000002202c2cbf50cf74604b1ed6cbe3540d35ebdf5464b0ea8bc325545afe9c918515"
    "000000008a473044022023897537d4d2d674e842ed82bf119d4d99c082810b30b4ee4a21a6"
    "ca7b6c7f05022077113e3b32ab8ff4758c7de0e9fa396ee44e9191981c13cdd6fcf0615bcb"
    "3bc0014104f5ea0caf16f55ebaf94d64b24634974df283d4856d730b01619f76cf73ee59a6"
    "6e98c6b5af43b8ed9ebfc010e529a4137a17f5dcb8dc23a00971ce40ea898380ffffffff58"
    "51d13c672e00d039ed7f89780ab937dc72423fb2367098f396c9265802ccbc000000008a47"
    "3044022023897537d4d2d674e842ed82bf119d4d99c082810b30b4ee4a21a6ca7b6c7f0502"
    "204c6c16c97ec41d01c6db38502859106063b79b299bce03fb497f9d1994ffd7b2014104f5"
    "ea0caf16f55ebaf94d64b24634974df283d4856d730b01619f76cf73ee59a66e98c6b5af43"
    "b8ed9ebfc010e529a4137a17f5dcb8dc23a00971ce40ea898380ffffffff0240420f000000"
    "00001976a91406f1b6716309948fa3b07b0a6b66804fdfd6873188ac08aa10000000000019"
    "76a91460fad2651ffb2c655f941de9338fe9a302f7c16888ac00000000"
)

#: Both inputs spend the same P2PKH output script -- one address, one key.
PREVOUT_SCRIPTS = [
    "76a91460fad2651ffb2c655f941de9338fe9a302f7c16888ac",
    "76a91460fad2651ffb2c655f941de9338fe9a302f7c16888ac",
]

#: The shared nonce's r. Identical across both inputs: that is the whole finding.
SHARED_R = 0x23897537D4D2D674E842ED82BF119D4D99C082810B30B4EE4A21A6CA7B6C7F05

#: (vin, hashtype, r, s, z, Qx, Qy, pubkey_len, low_s)
REUSE_INPUTS = [
    (
        0,
        0x01,
        0x23897537D4D2D674E842ED82BF119D4D99C082810B30B4EE4A21A6CA7B6C7F05,
        0x77113E3B32AB8FF4758C7DE0E9FA396EE44E9191981C13CDD6FCF0615BCB3BC0,
        0x11A702B01730287DC6D2D6581FD2E44859134552668C5EF72CC37F0CDDC9AFD2,
        0xF5EA0CAF16F55EBAF94D64B24634974DF283D4856D730B01619F76CF73EE59A6,
        0x6E98C6B5AF43B8ED9EBFC010E529A4137A17F5DCB8DC23A00971CE40EA898380,
        65,
        True,
    ),
    (
        1,
        0x01,
        0x23897537D4D2D674E842ED82BF119D4D99C082810B30B4EE4A21A6CA7B6C7F05,
        0x4C6C16C97EC41D01C6DB38502859106063B79B299BCE03FB497F9D1994FFD7B2,
        0x16995B9D987FF01E8FFB79AE3C33BAC365F6B9C8DD048050FA810A171C048579,
        0xF5EA0CAF16F55EBAF94D64B24634974DF283D4856D730B01619F76CF73EE59A6,
        0x6E98C6B5AF43B8ED9EBFC010E529A4137A17F5DCB8DC23A00971CE40EA898380,
        65,
        True,
    ),
]
