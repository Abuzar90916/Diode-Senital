import os
import joblib
import numpy as np
import xgboost as xgb
from sklearn.ensemble import IsolationForest
from training.synthetic_data import generate_synthetic_flows
from schemas.alert_record import ThreatClass


def train_and_save_models(models_dir: str = "models") -> None:
    """
    Trains ML models (Isolation Forest for volumetric & fanout, XGBoost for DGA)
    and serializes the models to disk.
    """
    os.makedirs(models_dir, exist_ok=True)
    print(f"[Training] Generating synthetic training data...")
    dataset = generate_synthetic_flows(num_benign=400, num_malicious_per_class=60)

    # Extract features for volumetric Isolation Forest
    vol_feats = []
    # Extract features for XGBoost DGA classifier
    dga_X = []
    dga_y = []
    # Extract features for fanout Isolation Forest
    fanout_feats = []

    for rec, label, threat_class_str in dataset:
        vol = rec.volumetric
        vol_feats.append([vol.packet_rate_pps, vol.packet_count, vol.src_ip_entropy, vol.syn_ack_ratio])

        fan = rec.fanout
        fanout_feats.append([fan.dst_port_count, fan.dst_ip_count, fan.scan_rate_pps])

        if rec.dns_lexical:
            dns = rec.dns_lexical
            dga_X.append([dns.shannon_entropy, dns.query_length, dns.subdomain_count, dns.consonant_vowel_ratio])
            dga_y.append(1 if threat_class_str == ThreatClass.DGA_TUNNELLING.value else 0)

    # 1. Train Volumetric Isolation Forest
    print("[Training] Fitting Volumetric Isolation Forest...")
    iso_vol = IsolationForest(n_estimators=50, contamination=0.08, random_state=42)
    iso_vol.fit(np.array(vol_feats))
    joblib.dump(iso_vol, os.path.join(models_dir, "iso_volumetric.joblib"))

    # 2. Train Fanout Isolation Forest
    print("[Training] Fitting Fanout Isolation Forest...")
    iso_fanout = IsolationForest(n_estimators=40, contamination=0.05, random_state=42)
    iso_fanout.fit(np.array(fanout_feats))
    joblib.dump(iso_fanout, os.path.join(models_dir, "iso_fanout.joblib"))

    # 3. Train XGBoost DGA Classifier
    if dga_X:
        print("[Training] Fitting XGBoost DGA Classifier...")
        xgb_dga = xgb.XGBClassifier(n_estimators=30, max_depth=4, learning_rate=0.1, random_state=42)
        xgb_dga.fit(np.array(dga_X), np.array(dga_y))
        xgb_dga.save_model(os.path.join(models_dir, "xgb_dga.json"))

    print(f"[Training] All models trained and saved successfully to '{models_dir}/'!")


if __name__ == "__main__":
    train_and_save_models()
