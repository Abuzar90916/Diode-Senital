"""
=============================================================================
NOTICE: THIS FILE IS A CONVENIENCE WRAPPER.
The authoritative baseline scaffold has been renamed to:
  evaluate_detection_BASELINE_SCAFFOLD.py

This disclaimer makes explicit to judges and team members that this script
validates Person 1 & 2's feature engineering and streaming pipeline.
It is NOT the final AI/ML detector.
For production ML models, see Person 3's ThreatCore module (threatcore/).
=============================================================================
"""

import sys
import os

# Delegate directly to the renamed scaffold module
from evaluate_detection_BASELINE_SCAFFOLD import evaluate_pcap, evaluate_all, BaselineThreatClassifier

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Diode-Sentinel Baseline Scaffold Evaluator (Wrapper)")
    parser.add_argument("--pcap", type=str, help="Path to specific PCAP to evaluate")
    parser.add_argument("--all", action="store_true", help="Evaluate all 8 generated PCAP datasets")
    args = parser.parse_args()

    if args.pcap:
        evaluate_pcap(args.pcap)
    else:
        evaluate_all()
