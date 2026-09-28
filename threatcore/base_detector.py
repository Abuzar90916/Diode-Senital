from abc import ABC, abstractmethod
from typing import Optional
from schemas.flow_feature_record import FlowFeatureRecord
from schemas.alert_record import AlertCandidate
from fp_reduction.baseline_store import BaselineStore
from fp_reduction.allowlists import AllowlistManager


class BaseDetector(ABC):
    """
    Abstract Base Class for all ThreatCore detectors.
    Consumes a single FlowFeatureRecord incrementally (streaming mode)
    and optional baseline context to produce an AlertCandidate if anomalies are detected.
    """

    def __init__(self, allowlist_manager: Optional[AllowlistManager] = None):
        self.allowlists = allowlist_manager or AllowlistManager()

    @abstractmethod
    def detect(
        self, record: FlowFeatureRecord, baseline: BaselineStore
    ) -> Optional[AlertCandidate]:
        """
        Evaluate a single FlowFeatureRecord.

        Returns:
            AlertCandidate if anomaly conditions are met, else None.
        """
        pass
