"""Block sources. The ONLY module in this package that performs IO.

Everything else is a pure function of bytes, which is what makes the rest of the
ingest path testable offline with no network and no monkeypatching.

**Trust model.** A public API is untrusted, and every datum we depend on is
covered by a check we run ourselves:

    tx contents          -> recomputed txid must match
    the block's tx set   -> merkle root must match the header
    range contiguity     -> each header's prev_hash must chain to the last
    the chain is real    -> proof of work on each header
    prevout scriptPubKey -> the ECDSA verify gate (a wrong scriptCode changes z)

Only the very first block hash requires external trust, and PoW covers even that.
A hostile server cannot hand us a signature that verifies against a `z` we
computed from its own fabrication.
"""

from __future__ import annotations

import gzip
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Iterator, Protocol

from .extract import PrevOut
from .tx import (
    Tx,
    block_hash,
    check_pow,
    header_fields,
    merkle_root,
    parse_block,
    parse_tx,
)

USER_AGENT = "qi-fingerprint-ingest/0.1 (+research; read-only)"
CACHE_SCHEMA = 1
RAW_CACHE_SCHEMA = 1


class SourceError(RuntimeError):
    """The source could not supply a block, or supplied one that failed a check."""


def _check_self_authentication(
    height: int,
    claimed_hash: str,
    header: bytes,
    txids: list[bytes],
    *,
    verify_pow: bool = True,
) -> None:
    """Header self-hash, proof of work, merkle root.

    The whole trust model in one function, shared by every record type so the two
    cannot drift apart: this is what turns a third party's bytes into data. It
    covers only what a header commits to -- prevouts are not in the merkle tree
    and are checked elsewhere (ultimately by the ECDSA verify gate).
    """
    fields = header_fields(header)
    if block_hash(header)[::-1].hex() != claimed_hash:
        raise SourceError(f"height {height}: header does not hash to its own id")
    if verify_pow and not check_pow(header):
        raise SourceError(f"height {height}: header fails proof of work")
    if not txids:
        raise SourceError(f"height {height}: no transactions")
    if merkle_root(txids) != fields["merkle_root"]:
        raise SourceError(
            f"height {height}: merkle root mismatch -- the source's "
            f"transaction set is not the one this header commits to"
        )


@dataclass
class RawBlock:
    """A block with no prevout lookups.

    Enough to read scriptSigs -- so enough for the r-collision hunt, which needs
    only ``(r, pubkey)`` -- and deliberately *not* enough to compute a sighash.
    A `RawBlock` cannot produce a corpus; promoting a candidate to a finding
    requires refetching the implicated blocks in full.
    """

    height: int
    block_hash: str  # display order
    header: bytes
    txs: list[Tx]

    @property
    def prev_hash(self) -> str:
        """The predecessor's id, in display order -- ready to fetch by."""
        return header_fields(self.header)["prev_hash"][::-1].hex()

    def check(self, *, verify_pow: bool = True) -> None:
        _check_self_authentication(
            self.height,
            self.block_hash,
            self.header,
            [tx.txid for tx in self.txs],
            verify_pow=verify_pow,
        )


@dataclass
class BlockRecord:
    height: int
    block_hash: str  # display order
    header: bytes
    txs: list[tuple[Tx, list[PrevOut]]]

    def check(self, *, verify_pow: bool = True) -> None:
        """Self-authentication. Cheap, and it turns an untrusted feed into data."""
        _check_self_authentication(
            self.height,
            self.block_hash,
            self.header,
            [tx.txid for tx, _ in self.txs],
            verify_pow=verify_pow,
        )
        for tx, prevouts in self.txs:
            if len(prevouts) != len(tx.vin):
                raise SourceError(
                    f"height {self.height} {tx.txid_hex}: {len(prevouts)} prevouts "
                    f"for {len(tx.vin)} inputs"
                )


class BlockSource(Protocol):
    def block(self, height: int) -> BlockRecord: ...


class RawBlockSource(Protocol):
    def raw_block(self, height: int, block_hash: str | None = None) -> RawBlock: ...


# --------------------------------------------------------------------------- #
# Esplora
# --------------------------------------------------------------------------- #


class EsploraSource:
    """Blockstream/mempool.space Esplora. Read-only GETs, rate limited.

    One raw-block request gives the authoritative transaction bytes (so we never
    reconstruct a serialisation ourselves), and the paginated tx endpoint supplies
    each input's previous output.
    """

    PAGE = 25

    def __init__(
        self,
        base_url: str = "https://blockstream.info/api",
        rate_hz: float = 5.0,
        timeout: int = 30,
        retries: int = 4,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.min_interval = 1.0 / rate_hz if rate_hz > 0 else 0.0
        self.timeout = timeout
        self.retries = retries
        self._last_request = 0.0

    def _throttle(self) -> None:
        gap = time.monotonic() - self._last_request
        if gap < self.min_interval:
            time.sleep(self.min_interval - gap)
        self._last_request = time.monotonic()

    MAX_BACKOFF = 120.0

    def _get(self, path: str) -> bytes:
        url = f"{self.base_url}{path}"
        delay = 1.0
        last: Exception | None = None
        for _ in range(self.retries):
            self._throttle()
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return response.read()
            except urllib.error.HTTPError as exc:
                last = exc
                if exc.code not in (429, 500, 502, 503, 504):
                    raise SourceError(f"GET {url} -> HTTP {exc.code}") from exc
                if exc.code == 429:
                    # Rate limited. Back off *permanently*, not just for this
                    # request: a long scan that keeps hammering at the old rate
                    # will simply be limited again a few blocks later, which is
                    # how the first two hunts died mid-range.
                    self.min_interval = min(self.min_interval * 2 or 0.5, 8.0)
                    delay = max(delay, self._retry_after(exc))
            except (urllib.error.URLError, TimeoutError) as exc:
                last = exc
            time.sleep(delay)
            delay = min(delay * 2, self.MAX_BACKOFF)
        raise SourceError(f"GET {url} failed after {self.retries} attempts: {last}")

    @staticmethod
    def _retry_after(exc: urllib.error.HTTPError) -> float:
        """Honour a `Retry-After` header when the server sends one."""
        try:
            return max(0.0, float(exc.headers.get("Retry-After", 0)))
        except (TypeError, ValueError):
            return 0.0

    def raw_block(self, height: int, block_hash: str | None = None) -> RawBlock:
        """Header plus transactions, with no prevout lookups.

        Passing ``block_hash`` skips the height->hash lookup, halving the request
        count to one per block. Walking a range backwards makes that the normal
        case: every header names its predecessor, so only the first block needs
        resolving by height.

        Nothing is taken on trust for the saving. The record is built with the
        id we *asked* for, and `check()` refuses it unless the returned header
        actually hashes to that id -- so a server answering with some other
        block is caught, not silently ingested at the wrong height.
        """
        block_id = block_hash or self._get(f"/block-height/{height}").decode().strip()
        header, txs = parse_block(self._get(f"/block/{block_id}/raw"))
        record = RawBlock(height, block_id, header, txs)
        record.check()
        return record

    def block(self, height: int) -> BlockRecord:
        block_id = self._get(f"/block-height/{height}").decode().strip()
        header_and_txs = self._get(f"/block/{block_id}/raw")
        header, txs = parse_block(header_and_txs)

        prevouts_by_txid: dict[str, list[PrevOut]] = {}
        for start in range(0, len(txs), self.PAGE):
            page = json.loads(self._get(f"/block/{block_id}/txs/{start}"))
            for entry in page:
                prevouts_by_txid[entry["txid"]] = [
                    PrevOut(0, b"")
                    if vin.get("is_coinbase") or not vin.get("prevout")
                    else PrevOut(
                        int(vin["prevout"]["value"]),
                        bytes.fromhex(vin["prevout"]["scriptpubkey"]),
                    )
                    for vin in entry["vin"]
                ]

        paired: list[tuple[Tx, list[PrevOut]]] = []
        for tx in txs:
            txid = tx.txid_hex
            prevouts = prevouts_by_txid.get(txid)
            if prevouts is None:
                # Pagination dropped a transaction; better to fail than to ingest
                # a block we only partly understand.
                raise SourceError(f"height {height}: no prevouts returned for {txid}")
            paired.append((tx, prevouts))

        record = BlockRecord(height, block_id, header, paired)
        record.check()
        return record


# --------------------------------------------------------------------------- #
# Cache
# --------------------------------------------------------------------------- #


def _cache_path(cache_dir: str, height: int) -> str:
    return os.path.join(cache_dir, f"{height // 1000:05d}", f"{height:08d}.json.gz")


class CachedSource:
    """Disk cache in front of another source.

    The payload is normalised, not provider-shaped, so switching Esplora for a
    node later does not invalidate what is already on disk. Pass ``inner=None``
    for a strictly offline run.
    """

    def __init__(self, inner: BlockSource | None, cache_dir: str) -> None:
        self.inner = inner
        self.cache_dir = cache_dir

    def _read(self, height: int) -> BlockRecord | None:
        path = _cache_path(self.cache_dir, height)
        if not os.path.exists(path):
            return None
        try:
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                payload = json.load(handle)
            if payload.get("schema") != CACHE_SCHEMA:
                return None
            record = BlockRecord(
                height=payload["height"],
                block_hash=payload["hash"],
                header=bytes.fromhex(payload["header"]),
                txs=[
                    (
                        parse_tx(bytes.fromhex(entry["raw"])),
                        [PrevOut(v, bytes.fromhex(spk)) for v, spk in entry["prevouts"]],
                    )
                    for entry in payload["txs"]
                ],
            )
            record.check()
            return record
        except Exception:
            # A corrupt entry is refetched, never trusted.
            try:
                os.remove(path)
            except OSError:
                pass
            return None

    def _write(self, record: BlockRecord) -> None:
        path = _cache_path(self.cache_dir, record.height)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        payload = {
            "schema": CACHE_SCHEMA,
            "height": record.height,
            "hash": record.block_hash,
            "header": record.header.hex(),
            "txs": [
                {
                    "raw": tx.serialize().hex(),
                    "prevouts": [[p.value, p.script_pubkey.hex()] for p in prevouts],
                }
                for tx, prevouts in record.txs
            ],
        }
        tmp = f"{path}.tmp"
        with gzip.open(tmp, "wt", encoding="utf-8") as handle:
            json.dump(payload, handle)
        os.replace(tmp, path)  # atomic: an interrupted fetch never half-writes

    def block(self, height: int) -> BlockRecord:
        cached = self._read(height)
        if cached is not None:
            return cached
        if self.inner is None:
            raise SourceError(
                f"height {height} is not cached and this source is offline-only"
            )
        record = self.inner.block(height)
        self._write(record)
        return record


class FileSource(CachedSource):
    """Offline-only cache reader, for tests and reproducibility runs."""

    def __init__(self, cache_dir: str) -> None:
        super().__init__(None, cache_dir)


class RawCachedSource:
    """The same disk cache, for prevout-free blocks.

    Kept in its own directory rather than sharing one with `CachedSource`: the
    payloads differ, and a half-populated entry that looked complete would be a
    silent way to lose prevouts. A wide hunt is worth caching because the scan
    is the part you re-run while widening the range.
    """

    def __init__(self, inner: RawBlockSource | None, cache_dir: str) -> None:
        self.inner = inner
        self.cache_dir = cache_dir

    def _read(self, height: int) -> RawBlock | None:
        path = _cache_path(self.cache_dir, height)
        if not os.path.exists(path):
            return None
        try:
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                payload = json.load(handle)
            if payload.get("schema") != RAW_CACHE_SCHEMA:
                return None
            record = RawBlock(
                height=payload["height"],
                block_hash=payload["hash"],
                header=bytes.fromhex(payload["header"]),
                txs=[parse_tx(bytes.fromhex(raw)) for raw in payload["txs"]],
            )
            record.check()
            return record
        except Exception:
            try:
                os.remove(path)  # a corrupt entry is refetched, never trusted
            except OSError:
                pass
            return None

    def _write(self, record: RawBlock) -> None:
        path = _cache_path(self.cache_dir, record.height)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        payload = {
            "schema": RAW_CACHE_SCHEMA,
            "height": record.height,
            "hash": record.block_hash,
            "header": record.header.hex(),
            "txs": [tx.serialize().hex() for tx in record.txs],
        }
        tmp = f"{path}.tmp"
        with gzip.open(tmp, "wt", encoding="utf-8") as handle:
            json.dump(payload, handle)
        os.replace(tmp, path)

    def raw_block(self, height: int, block_hash: str | None = None) -> RawBlock:
        """Serve from disk if possible, otherwise fetch and store.

        When the caller names a ``block_hash`` -- which the backwards walk always
        does -- a cached entry only counts as a hit if it *is* that block. A
        height alone is not an identity across a reorg, and silently returning
        the wrong side of one would corrupt the scan.
        """
        cached = self._read(height)
        if cached is not None and (block_hash is None or cached.block_hash == block_hash):
            return cached
        if self.inner is None:
            raise SourceError(
                f"height {height} is not cached and this source is offline-only"
            )
        record = self.inner.raw_block(height, block_hash)
        self._write(record)
        return record


# --------------------------------------------------------------------------- #
# Ranges
# --------------------------------------------------------------------------- #


def _walk(fetch, start: int, end: int):
    """Yield `start..end` inclusive, checking each header chains to the last.

    The forward traversal, used where the source must be asked for each height
    separately (the full-prevout path, whose per-block cost dwarfs the lookup).
    """
    previous = None
    for height in range(start, end + 1):
        record = fetch(height)
        if previous is not None:
            expected = block_hash(previous.header)
            if header_fields(record.header)["prev_hash"] != expected:
                raise SourceError(
                    f"height {height} does not chain to {height - 1} -- "
                    f"the range is not contiguous"
                )
        yield record
        previous = record


def iter_blocks(source: BlockSource, start: int, end: int) -> Iterator[BlockRecord]:
    """Yield blocks `start..end` inclusive, with prevouts."""
    yield from _walk(source.block, start, end)


def iter_raw_blocks(source: RawBlockSource, start: int, end: int) -> Iterator[RawBlock]:
    """Yield blocks `end..start`, **descending**, without prevouts (hunt only).

    Only the top block is resolved by height; every one after it is fetched by
    the id its successor's header already gave us. That halves the request count
    to one per block, which is what makes a wide hunt affordable.

    Contiguity stops being a check and becomes structural: a block is fetched
    *because* its successor named it, and `RawBlock.check()` refuses a record
    whose header does not hash to the id requested. There is no way to receive a
    block that does not chain -- as opposed to receiving one and noticing after.

    The descending order is deliberate and visible to callers; the r-collision
    index does not care which direction the range is walked.
    """
    record = source.raw_block(end)
    yield record
    for height in range(end - 1, start - 1, -1):
        record = source.raw_block(height, record.prev_hash)
        yield record
