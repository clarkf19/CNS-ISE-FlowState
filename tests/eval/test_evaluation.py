import pytest

from eval.baseline import PlainProxy, baseline_attacks
from eval.benchmark import latency_stats, run
from eval.report import render
from flowstate.gateway.runtime import start_stack


def test_latency_stats():
    s = latency_stats([0.001 * i for i in range(1, 101)])
    assert s["n"] == 100
    assert s["mean_ms"] == pytest.approx(50.5)
    assert s["p50_ms"] == pytest.approx(50.5, abs=1) and s["max_ms"] == pytest.approx(100)


def test_baseline_is_vulnerable():
    """The comparison only means something if the baseline really is attackable."""
    with start_stack() as stack, PlainProxy(stack) as proxy:
        assert all(baseline_attacks(stack, proxy).values())


def test_small_benchmark_run_and_report():
    results = run(requests=20, clients=2)
    assert results["attack_blocking_rate"] == 1.0
    assert results["replay_detection"]["detection_rate"] == 1.0
    assert results["auth_failure_detection"]["detection_rate"] == 1.0
    assert results["throughput_gateway"]["errors"] == 0
    assert set(results["stage_mean_us"]) == {"session", "decrypt", "replay", "freshness", "authorization"}
    md = render(results)
    assert "# Evaluation Results" in md and "mitm_tampering" in md
