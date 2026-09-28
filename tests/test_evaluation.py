from training.evaluate import PipelineEvaluator


def test_pipeline_evaluation():
    evaluator = PipelineEvaluator()
    results = evaluator.run_evaluation(num_benign=100, num_malicious_per_class=10)

    assert len(results) == 6
    for tc, metrics in results.items():
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1_score" in metrics
        assert "fp_per_hour" in metrics
        assert metrics["recall"] > 0.0


def test_holdout_evaluation():
    from training.evaluate_holdout import HoldoutEvaluator
    import os

    botnet_pcap = "validation/external_samples/ctu13_neris_real_botnet_10k.pcap"
    normal_pcap = "validation/external_samples/ctu13_real_normal.pcap"
    botnet_cache = "scratch/ctu_botnet.jsonl"
    normal_cache = "scratch/ctu_normal.jsonl"

    if os.path.exists(botnet_cache) and os.path.exists(normal_cache):
        evaluator = HoldoutEvaluator(required_windows=3, window_ttl_seconds=300)
        results = evaluator.evaluate(botnet_pcap, normal_pcap, botnet_cache, normal_cache)
        assert "recall" in results
        assert "false_positive_rate" in results
        assert "alerts_per_hour" in results
        assert results["recall"] > 0.0
        assert "PortScanDetector" in results["per_detector"]
        assert results["per_detector"]["PortScanDetector"]["botnet_promoted"] > 0

