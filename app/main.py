import time
from hashlib import sha256
import os
import statistics as stats


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()

def benchmark_sha256(samples: int = 1_000_00) -> None:  # 100k by default
    payloads = [os.urandom(8) for _ in range(samples)]
    t0 = time.perf_counter()
    for p in payloads:
        sha256(p).hexdigest()
    t1 = time.perf_counter()
    elapsed = t1 - t0
    hps = samples / elapsed
    print(f"Hashed {samples:,} inputs in {elapsed:.3f}s → {hps:,.0f} hashes/sec")

    # Estimate time to exhaust all 8-digit numeric codes (10^8 combos)
    total = 100_000_000
    eta_sec = total / hps
    print(f"Estimated time to test 10^8 candidates: {eta_sec/60:.1f} min "
          f"({eta_sec/3600:.2f} h) on this machine (single process).")


if __name__ == "__main__":
    benchmark_sha256()
