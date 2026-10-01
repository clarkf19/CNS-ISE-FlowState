"""Evaluation harness (proposal section 4.4).

Measures:
  security    - attack-blocking effectiveness, replay detection rate,
                authentication-failure detection, baseline attack success
  performance - request latency (gateway vs plain baseline), handshake latency,
                throughput (1 and N concurrent clients), per-stage pipeline cost,
                primitive-level encryption overhead

  python -m eval.benchmark [--requests 500] [--clients 4] [--no-write]
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import threading
import time
from pathlib import Path

from attacks.runner import run_scenarios
from eval.baseline import PlainClient, PlainProxy, baseline_attacks
from eval.report import write_report
from flowstate.client import GatewayRejected, SecureClient
from flowstate.core import crypto
from flowstate.gateway.runtime import Stack, start_stack

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "eval" / "results"


def latency_stats(samples_s: list[float]) -> dict[str, float]:
    ms = sorted(s * 1000 for s in samples_s)

    def pct(p: float) -> float:
        return ms[min(len(ms) - 1, int(round(p / 100 * (len(ms) - 1))))]

    return {
        "n": len(ms),
        "mean_ms": statistics.fmean(ms),
        "p50_ms": pct(50),
        "p95_ms": pct(95),
        "p99_ms": pct(99),
        "max_ms": ms[-1],
    }


def _client(stack: Stack, client_id: str = "alice") -> SecureClient:
    ids = stack.identities
    return SecureClient(stack.gateway_addr, client_id, ids.client_keys[client_id], ids.gateway_pin)


# ---------------------------------------------------------------- performance


def measure_gateway_latency(stack: Stack, n: int) -> dict:
    samples = []
    with _client(stack) as c:
        c.handshake()
        for _ in range(n):
            t = time.perf_counter()
            c.request("balance")
            samples.append(time.perf_counter() - t)
    return latency_stats(samples)


def measure_baseline_latency(stack: Stack, proxy: PlainProxy, n: int) -> dict:
    samples = []
    c = PlainClient(proxy.address, "alice")
    for _ in range(n):
        t = time.perf_counter()
        c.request("balance")
        samples.append(time.perf_counter() - t)
    c.close()
    return latency_stats(samples)


def measure_handshake(stack: Stack, n: int) -> dict:
    samples = []
    for _ in range(n):
        with _client(stack) as c:
            t = time.perf_counter()
            c.handshake()
            samples.append(time.perf_counter() - t)
    return latency_stats(samples)


def measure_throughput(make_worker, clients: int, per_client: int, repeats: int = 3) -> dict:
    """Median of several runs, so one scheduler hiccup does not skew the comparison."""
    runs = sorted(
        (_throughput_once(make_worker, clients, per_client) for _ in range(repeats)),
        key=lambda r: r["req_per_s"],
    )
    return {**runs[len(runs) // 2], "runs_req_per_s": [r["req_per_s"] for r in runs]}


def _throughput_once(make_worker, clients: int, per_client: int) -> dict:
    errors: list[Exception] = []

    def run(i: int) -> None:
        try:
            make_worker(i)(per_client)
        except Exception as exc:  # recorded, reported in results
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(clients)]
    t = time.perf_counter()
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    elapsed = time.perf_counter() - t
    total = clients * per_client
    return {"clients": clients, "requests": total, "seconds": elapsed,
            "req_per_s": total / elapsed, "errors": len(errors)}


def gateway_worker(stack: Stack):
    ids = ["alice", "bob", "carol", "root"]

    def make(i: int):
        def work(n: int) -> None:
            with _client(stack, ids[i % len(ids)]) as c:
                c.handshake()
                for _ in range(n):
                    c.request("balance")
        return work
    return make


def baseline_worker(proxy: PlainProxy):
    def make(i: int):
        def work(n: int) -> None:
            c = PlainClient(proxy.address, "alice")
            for _ in range(n):
                c.request("balance")
            c.close()
        return work
    return make


def measure_primitives(iterations: int = 2000) -> dict:
    def timeit(fn, n=iterations) -> float:
        t = time.perf_counter()
        for _ in range(n):
            fn()
        return (time.perf_counter() - t) / n * 1e6  # microseconds

    out: dict[str, float] = {}
    sk = crypto.SigningKey.generate()
    vk = sk.public_key()
    msg = b"x" * 128
    sig = sk.sign(msg)
    out["ed25519_sign_us"] = timeit(lambda: sk.sign(msg), iterations // 4)
    out["ed25519_verify_us"] = timeit(lambda: vk.verify(sig, msg), iterations // 4)
    peer = crypto.EphemeralKeyPair().public_bytes()
    out["x25519_keygen_exchange_us"] = timeit(
        lambda: crypto.EphemeralKeyPair().exchange(peer), iterations // 4
    )
    out["hkdf_sha256_us"] = timeit(
        lambda: crypto.hkdf_sha256(b"s" * 32, salt=b"n" * 32, info=b"label")
    )
    key = crypto.AeadKey(crypto.random_bytes(32))
    nonce = crypto.random_bytes(12)
    for size in (64, 1024, 16384):
        pt = b"a" * size
        ct = key.seal(nonce, pt, b"aad")
        out[f"aes_gcm_seal_{size}B_us"] = timeit(lambda: key.seal(nonce, pt, b"aad"))
        out[f"aes_gcm_open_{size}B_us"] = timeit(lambda: key.open(nonce, ct, b"aad"))
    return out


# ---------------------------------------------------------------- security


def measure_replay_detection(stack: Stack, n: int) -> dict:
    with _client(stack) as c:
        c.handshake()
        captured = []
        for _ in range(n):
            req = c.build_request("balance")
            c.send_request(req)
            captured.append(req)
        rejected = 0
        for req in captured:
            try:
                c.send_request(req)
            except GatewayRejected:
                rejected += 1
    return {"replayed": n, "rejected": rejected, "detection_rate": rejected / n}


def measure_auth_failures(stack: Stack, n: int) -> dict:
    rejected = 0
    for i in range(n):
        forged = SecureClient(
            stack.gateway_addr, "alice", crypto.SigningKey.generate(), stack.identities.gateway_pin
        )
        try:
            with forged:
                forged.handshake()
        except GatewayRejected:
            rejected += 1
    return {"forged_handshakes": n, "rejected": rejected, "detection_rate": rejected / n}


# ---------------------------------------------------------------- main


def run(requests: int, clients: int) -> dict:
    results: dict = {
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "requests": requests,
            "clients": clients,
        }
    }

    attacks = run_scenarios()
    results["attacks"] = [r.__dict__ for r in attacks]
    results["attack_blocking_rate"] = sum(r.blocked for r in attacks) / len(attacks)
    results["legit_traffic_unaffected"] = all(r.legit_ok for r in attacks)

    with start_stack() as stack, PlainProxy(stack) as proxy:
        results["latency_gateway"] = measure_gateway_latency(stack, requests)
        results["latency_baseline"] = measure_baseline_latency(stack, proxy, requests)
        results["latency_handshake"] = measure_handshake(stack, max(10, requests // 10))
        per_client = max(1, requests // clients)
        results["throughput_gateway"] = measure_throughput(gateway_worker(stack), clients, per_client)
        results["throughput_baseline"] = measure_throughput(baseline_worker(proxy), clients, per_client)
        results["stage_mean_us"] = stack.gateway.stage_stats.mean_us()
        results["replay_detection"] = measure_replay_detection(stack, min(200, requests))
        results["auth_failure_detection"] = measure_auth_failures(stack, min(50, requests))
        results["baseline_attack_success"] = baseline_attacks(stack, proxy)

    results["primitives_us"] = measure_primitives()
    gw, base = results["latency_gateway"]["mean_ms"], results["latency_baseline"]["mean_ms"]
    results["overhead"] = {
        "added_latency_ms": gw - base,
        "relative_latency": gw / base if base else None,
        "throughput_ratio": results["throughput_gateway"]["req_per_s"]
        / results["throughput_baseline"]["req_per_s"],
    }
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="eval.benchmark")
    parser.add_argument("--requests", type=int, default=500)
    parser.add_argument("--clients", type=int, default=4)
    parser.add_argument("--no-write", action="store_true", help="print only, do not write files")
    args = parser.parse_args(argv)

    results = run(args.requests, args.clients)
    gw, base = results["latency_gateway"], results["latency_baseline"]
    print(f"attack blocking rate      {results['attack_blocking_rate']:.0%} "
          f"({len(results['attacks'])} scenarios)")
    print(f"replay detection rate     {results['replay_detection']['detection_rate']:.0%}")
    print(f"auth failure detection    {results['auth_failure_detection']['detection_rate']:.0%}")
    print(f"latency gateway / plain   {gw['mean_ms']:.3f} ms / {base['mean_ms']:.3f} ms (mean)")
    print(f"handshake latency         {results['latency_handshake']['mean_ms']:.3f} ms (mean)")
    print(f"throughput gateway/plain  {results['throughput_gateway']['req_per_s']:.0f} / "
          f"{results['throughput_baseline']['req_per_s']:.0f} req/s")
    print(f"baseline attacks succeeded: "
          f"{[k for k, v in results['baseline_attack_success'].items() if v]}")

    if not args.no_write:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        (RESULTS_DIR / "results.json").write_text(json.dumps(results, indent=2))
        write_report(results, ROOT / "docs" / "results.md")
        print(f"wrote {RESULTS_DIR / 'results.json'} and docs/results.md")
    ok = results["attack_blocking_rate"] == 1.0 and results["legit_traffic_unaffected"]
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
