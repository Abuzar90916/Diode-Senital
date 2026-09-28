"""
Integration test for schema drift:
Validates real exported JSONL records from diode-sentinel/run_pipeline.py against
the single canonical FlowFeatureRecord schema.
Fails loudly if the pipeline serialization output and the schema ever drift apart.
"""

import os
import sys
import tempfile
import pytest

# Ensure diode-sentinel is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from run_pipeline import run_pipeline
from schemas.flow_feature_record import FlowFeatureRecord


def test_real_exported_jsonl_validates_against_canonical_schema():
    pcap_path = os.path.join(BASE_DIR, "data_generation", "pcaps", "attack_c2_beacon.pcap")
    assert os.path.exists(pcap_path), f"PCAP fixture not found: {pcap_path}"

    with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".jsonl") as tf:
        out_jsonl = tf.name

    try:
        # Run real ingestion pipeline to export JSONL
        run_pipeline(pcap_path=pcap_path, output_records_file=out_jsonl, run_watchdog=False)

        assert os.path.exists(out_jsonl), "Exported JSONL was not generated"

        records_validated = 0
        with open(out_jsonl, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                # Validate against canonical FlowFeatureRecord schema
                record = FlowFeatureRecord.model_validate_json(line)

                # Strict validation of required fields and sub-objects
                assert record.flow_id, f"Line {line_idx}: flow_id is empty"
                assert record.src_ip, f"Line {line_idx}: src_ip is empty"
                assert record.dst_ip, f"Line {line_idx}: dst_ip is empty"
                assert record.protocol, f"Line {line_idx}: protocol is empty"
                assert record.volumetric is not None, f"Line {line_idx}: volumetric missing"
                assert record.timing is not None, f"Line {line_idx}: timing missing"
                assert record.dns_lexical is not None, f"Line {line_idx}: dns_lexical missing"
                assert record.crypto_metadata is not None, f"Line {line_idx}: crypto_metadata missing"
                assert record.fanout is not None, f"Line {line_idx}: fanout missing"
                assert record.volume_asymmetry is not None, f"Line {line_idx}: volume_asymmetry missing"

                records_validated += 1

        assert records_validated > 0, "No records were validated from the exported JSONL"
    finally:
        if os.path.exists(out_jsonl):
            try:
                os.remove(out_jsonl)
            except OSError:
                pass


def test_existing_jsonl_artifacts_validate():
    """If pre-exported JSONL artifacts exist at repo root, validate them all."""
    repo_root = BASE_DIR
    jsonl_files = ["beacon_features.jsonl", "dga_features.jsonl", "portscan_features.jsonl"]
    for jf in jsonl_files:
        path = os.path.join(repo_root, jf)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line_idx, line in enumerate(f):
                    line = line.strip()
                    if not line:
                        continue
                    rec = FlowFeatureRecord.model_validate_json(line)
                    assert rec.flow_id, f"{jf} line {line_idx}: invalid flow_id"
