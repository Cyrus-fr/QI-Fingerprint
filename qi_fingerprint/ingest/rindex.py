"""An on-disk r-index, so a scan can be wide enough to matter and can be resumed.

`ReuseIndex` keeps a `SigSite` per distinct ``(key, r)``. Measured on the real
structure that costs ~682 bytes per signature -- 490 MB for the 719k signatures
already scanned, and **9.5 GB** for the ~14M in the 20k-block window the Android
`SecureRandom` incident actually spans. Slotting the dataclass and shortening the
txid save 12%; they do not change the answer. A fixed-width record does:

    layout                              B/site    719k      ~14M
    dataclass + str txid                   682   490 MB   9.55 GB
    + slots=True                           639   459 MB   8.95 GB
    + slots + bytes txid                   599   431 MB   8.39 GB
    numpy record (this module)              24    17 MB   0.34 GB

**The prefix is a filter; the exact recheck is the decision.** `hunt.ReuseIndex`
argues -- correctly -- that an r-collision in a forensic tool should not come with
a probability attached, and that principle is untouched here. What is stored is
the top 64 bits of ``r``; what is *reported* is only a collision whose full
256-bit ``r`` and both public keys have been re-derived from refetched blocks. At
14M signatures the expected number of spurious prefix matches is

    (1.4e7)^2 / 2 * 2^-64  ~=  5e-6

so a wasted refetch is a once-in-200,000-scans event, and it costs two block
fetches rather than a wrong answer.

Nothing here stores a txid. ``site_idx`` is the position of the site within
``scan_block(txs, height)``, which is a pure function of the block bytes -- so
refetching the block and re-running it reproduces the site exactly, and 64 bytes
of hex per signature never has to be written down.

The record file doubles as the checkpoint: it is append-only, and the sidecar
names the lowest height already scanned. `iter_raw_blocks` descends, so completed
work is a contiguous suffix and resuming means continuing downward.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Iterable, Iterator, Sequence

import numpy as np

from .hunt import SigSite, scan_block

#: 24 bytes exactly, no padding. Little-endian so the file is portable.
RECORD = np.dtype(
    [("r_hi", "<u8"), ("q_hi", "<u8"), ("height", "<u4"), ("site_idx", "<u4")]
)

#: How many bits of r and Qx are kept. See the module docstring on why truncation
#: does not weaken the finding.
PREFIX_SHIFT = 192

_FLUSH_EVERY = 50_000  # records buffered before touching the disk


def prefix(value: int) -> int:
    """Top 64 bits of a 256-bit scalar."""
    return (value >> PREFIX_SHIFT) & 0xFFFF_FFFF_FFFF_FFFF


@dataclass(frozen=True)
class IndexState:
    """What a partially-complete scan knows about itself."""

    start: int
    end: int
    lowest_done: int | None  # None => nothing scanned yet
    n_sites: int

    @property
    def complete(self) -> bool:
        return self.lowest_done is not None and self.lowest_done <= self.start

    @property
    def resume_from(self) -> int:
        """The next height to scan, walking downward."""
        if self.lowest_done is None:
            return self.end
        return self.lowest_done - 1


@dataclass(frozen=True)
class PrefixHit:
    """Two records whose ``r`` prefixes match. A lead, not yet a finding."""

    r_hi: int
    same_key_prefix: bool  # equal q_hi -- likely same key, still to be confirmed
    locations: tuple[tuple[int, int], ...]  # (height, site_idx) per record


def _sidecar_path(path: str) -> str:
    return path + ".json"


class RIndexWriter:
    """Append-only writer over the record file, with a resumable sidecar."""

    def __init__(self, path: str, start: int, end: int, resume: bool = False) -> None:
        self.path = path
        self.start = start
        self.end = end
        self._buffer: list[tuple[int, int, int, int]] = []
        self._lowest_done: int | None = None
        self._n_sites = 0

        existing = read_state(path, start, end) if resume else None
        if existing is not None:
            self._lowest_done = existing.lowest_done
            self._n_sites = existing.n_sites

        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        if existing is None:
            # Not resuming: start the file over. Appending to a stale index would
            # silently double-count and manufacture collisions out of nothing.
            open(path, "wb").close()

    # -- writing --------------------------------------------------------------

    @property
    def n_sites(self) -> int:
        return self._n_sites + len(self._buffer)

    @property
    def state(self) -> IndexState:
        return IndexState(self.start, self.end, self._lowest_done, self.n_sites)

    def add_block(self, height: int, sites: Sequence[SigSite]) -> None:
        """Record one block's signatures. ``sites`` must be `scan_block` order."""
        for site_idx, site in enumerate(sites):
            self._buffer.append(
                (prefix(site.r), prefix(site.qx), height, site_idx)
            )
        # Heights arrive descending, so the lowest seen is the resume point.
        if self._lowest_done is None or height < self._lowest_done:
            self._lowest_done = height
        if len(self._buffer) >= _FLUSH_EVERY:
            self.flush()

    def flush(self) -> None:
        """Persist the buffer and the sidecar. Safe to call at any point."""
        if self._buffer:
            block = np.array(self._buffer, dtype=RECORD)
            with open(self.path, "ab") as handle:
                handle.write(block.tobytes())
            self._n_sites += len(self._buffer)
            self._buffer.clear()
        self._write_sidecar()

    def _write_sidecar(self) -> None:
        payload = {
            "start": self.start,
            "end": self.end,
            "lowest_done": self._lowest_done,
            "n_sites": self._n_sites,
        }
        tmp = _sidecar_path(self.path) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
        os.replace(tmp, _sidecar_path(self.path))  # atomic: a torn sidecar is a lie

    def __enter__(self) -> "RIndexWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.flush()


def read_state(path: str, start: int, end: int) -> IndexState | None:
    """The sidecar for ``path``, or None if there is no usable checkpoint.

    A sidecar for a *different* range is not a checkpoint for this one; treating
    it as one would silently graft two scans together.
    """
    sidecar = _sidecar_path(path)
    if not (os.path.exists(path) and os.path.exists(sidecar)):
        return None
    try:
        with open(sidecar, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    if payload.get("start") != start or payload.get("end") != end:
        return None
    return IndexState(
        start=start,
        end=end,
        lowest_done=payload.get("lowest_done"),
        n_sites=int(payload.get("n_sites", 0)),
    )


def load_records(path: str) -> np.ndarray:
    """The whole index as a record array. 24 bytes per signature."""
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return np.empty(0, dtype=RECORD)
    return np.fromfile(path, dtype=RECORD)


def find_prefix_hits(records: np.ndarray) -> list[PrefixHit]:
    """Group records by ``r_hi`` and return every group of two or more.

    A sort, not a dict: 14M entries in a Python dict would cost more than the
    records themselves, while `np.argsort` runs in place over the record array.
    """
    if len(records) < 2:
        return []

    order = np.argsort(records["r_hi"], kind="stable")
    ordered = records[order]
    r_hi = ordered["r_hi"]

    # Boundaries of runs of equal r_hi.
    breaks = np.flatnonzero(r_hi[1:] != r_hi[:-1]) + 1
    starts = np.concatenate(([0], breaks))
    ends = np.concatenate((breaks, [len(ordered)]))

    hits: list[PrefixHit] = []
    for lo, hi in zip(starts, ends):
        if hi - lo < 2:
            continue
        group = ordered[lo:hi]
        hits.append(
            PrefixHit(
                r_hi=int(group["r_hi"][0]),
                same_key_prefix=bool(len(np.unique(group["q_hi"])) == 1),
                locations=tuple(
                    (int(row["height"]), int(row["site_idx"])) for row in group
                ),
            )
        )
    return sorted(hits, key=lambda h: h.locations)


def resolve_hit(hit: PrefixHit, source) -> list[SigSite]:
    """Refetch the implicated blocks and re-derive the exact sites.

    This is where a prefix match becomes -- or fails to become -- a real
    collision. `scan_block` is pure, so re-running it over the refetched block
    reproduces the same ordering the writer indexed.
    """
    by_height: dict[int, list[int]] = {}
    for height, site_idx in hit.locations:
        by_height.setdefault(height, []).append(site_idx)

    found: list[SigSite] = []
    for height, indices in sorted(by_height.items()):
        record = source.raw_block(height)
        sites = scan_block(record.txs, height)
        for site_idx in indices:
            if site_idx >= len(sites):
                raise IndexError(
                    f"height {height}: site {site_idx} of {len(sites)} -- the block "
                    f"scanned differently than when it was indexed"
                )
            found.append(sites[site_idx])
    return found


def confirm_hit(hit: PrefixHit, source) -> list[SigSite] | None:
    """Exact recheck. Returns the colliding sites, or None if the prefix lied.

    Two records can share 64 bits of ``r`` without sharing ``r``; that is the
    price of a 24-byte record, and it is paid here in two block fetches rather
    than in a false finding.
    """
    sites = resolve_hit(hit, source)
    exact: dict[int, list[SigSite]] = {}
    for site in sites:
        exact.setdefault(site.r, []).append(site)
    for _r, group in exact.items():
        distinct = {(s.txid, s.vin) for s in group}
        if len(distinct) > 1:
            return sorted(group, key=lambda s: (s.height, s.txid, s.vin))
    return None


def scan_to_index(
    source,
    path: str,
    start: int,
    end: int,
    *,
    resume: bool = False,
    on_block=None,
) -> IndexState:
    """Walk the range downward, writing one record per signature.

    With ``resume``, picks up below the lowest height already recorded. Returns
    the final state; call `find_prefix_hits` on `load_records` afterwards.
    """
    from .sources import iter_raw_blocks  # local: keeps this module IO-free to import

    writer = RIndexWriter(path, start, end, resume=resume)
    top = end
    if resume:
        state = writer.state
        if state.complete:
            writer.flush()
            return state
        top = state.resume_from
        if top < start:
            writer.flush()
            return writer.state

    with writer:
        for record in iter_raw_blocks(source, start, top):
            sites = scan_block(record.txs, record.height)
            writer.add_block(record.height, sites)
            if on_block is not None:
                on_block(record.height, len(sites), writer.n_sites)
    return writer.state


def iter_records(path: str) -> Iterator[tuple[int, int, int, int]]:
    """Plain-tuple view of the index, for tests and small inspections."""
    for row in load_records(path):
        yield (
            int(row["r_hi"]),
            int(row["q_hi"]),
            int(row["height"]),
            int(row["site_idx"]),
        )


def index_bytes_per_site() -> int:
    """The number the module docstring quotes, derived rather than asserted."""
    return RECORD.itemsize
