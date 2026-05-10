from __future__ import annotations

import csv
import random
import statistics
import time
from pathlib import Path
from typing import Any, Iterable


RESULTS_DIR = Path(__file__).resolve().parent / "results"


def now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def ns() -> int:
    return time.perf_counter_ns()


def elapsed_ms(start_ns: int) -> float:
    return (time.perf_counter_ns() - start_ns) / 1_000_000.0


def rng_from_seed(seed: int | None, repeat_index: int = 0) -> random.Random:
    if seed is None:
        return random.Random()
    return random.Random(seed + repeat_index * 1_000_003)


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def aggregate_rows(rows: list[dict[str, Any]], group_keys: Iterable[str]) -> list[dict[str, Any]]:
    keys = list(group_keys)
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(tuple(row.get(k) for k in keys), []).append(row)

    out: list[dict[str, Any]] = []
    skip = set(keys) | {"timestamp", "repeat_index"}
    for key_values, group in groups.items():
        agg: dict[str, Any] = {"timestamp": now_ts(), "repeat_index": "aggregate"}
        for k, v in zip(keys, key_values):
            agg[k] = v
        numeric_keys = [
            k for k, v in group[0].items()
            if k not in skip and isinstance(v, (int, float))
        ]
        for k in numeric_keys:
            vals = [float(r[k]) for r in group]
            agg[f"{k}_avg"] = statistics.fmean(vals)
            agg[f"{k}_stdev"] = statistics.stdev(vals) if len(vals) > 1 else 0.0
        out.append(agg)
    return out


def size_of_parts(*parts: bytes) -> int:
    return sum(4 + len(p) for p in parts)

