from typing import Dict, Tuple, Optional, List
from datetime import datetime
from schemas.alert_record import AlertCandidate, Alert


class PersistenceFilter:
    """
    Sliding-window persistence tracker.
    Requires an anomaly candidate to persist across N consecutive sliding windows (default 3)
    before promoting it to a graded Alert object.
    """

    def __init__(self, required_windows: int = 3, window_ttl_seconds: int = 300, min_window_interval_sec: float = 2.0):
        self.required_windows = required_windows
        self.window_ttl_seconds = window_ttl_seconds
        self.min_window_interval_sec = min_window_interval_sec
        # Key: (host/src_ip, threat_class) -> dict of window history. A threat
        # can legitimately span many 5-tuples, especially during reconnaissance.
        self._persistence_tracker: Dict[Tuple[str, str], Dict[str, any]] = {}

    def _get_key(self, candidate: AlertCandidate) -> Tuple[str, str]:
        host_key = candidate.src_ip or candidate.host or "unknown_host"
        return (host_key, candidate.threat_class.value)

    def process_candidate(
        self, candidate: AlertCandidate, corroboration_count: int
    ) -> Tuple[bool, int, Optional[Alert]]:
        """
        Processes a corroborated AlertCandidate through sliding window persistence filter.

        Returns:
            (promoted: bool, persistence_windows: int, alert: Optional[Alert])
        """
        key = self._get_key(candidate)
        now = candidate.timestamp

        if key in self._persistence_tracker:
            record = self._persistence_tracker[key]
            last_seen = record["last_seen"]
            time_delta = (now - last_seen).total_seconds()

            # If last seen within TTL window and distinct from last recorded window
            if 0.0 <= time_delta <= self.window_ttl_seconds:
                if time_delta >= self.min_window_interval_sec or record["windows"] == 1:
                    record["windows"] += 1
                record["last_seen"] = now
                record["evidence_list"].append(candidate.raw_evidence)
                record["confidence_score"] = max(record["confidence_score"], candidate.confidence_score)
            else:
                # Reset window count if gap exceeds TTL or is backwards in time
                self._persistence_tracker[key] = {
                    "windows": 1,
                    "last_seen": now,
                    "first_seen": now,
                    "evidence_list": [candidate.raw_evidence],
                    "confidence_score": candidate.confidence_score,
                }
        else:
            self._persistence_tracker[key] = {
                "windows": 1,
                "last_seen": now,
                "first_seen": now,
                "evidence_list": [candidate.raw_evidence],
                "confidence_score": candidate.confidence_score,
            }

        tracker = self._persistence_tracker[key]
        current_windows = tracker["windows"]

        if current_windows >= self.required_windows:
            # Format supporting evidence in plain English with specific feature metrics
            flat_evidence: List[str] = []
            for sublist in tracker["evidence_list"]:
                for item in sublist:
                    if item not in flat_evidence:
                        flat_evidence.append(item)
            formatted_evidence = "; ".join(flat_evidence)

            alert = Alert(
                timestamp=now,
                flow_identifier=candidate.flow_identifier,
                threat_class=candidate.threat_class,
                confidence_score=tracker["confidence_score"],
                supporting_evidence=formatted_evidence,
                corroboration_count=corroboration_count,
                persistence_windows=current_windows,
                src_ip=candidate.src_ip,
                dst_ip=candidate.dst_ip,
                host=candidate.host or candidate.src_ip,
            )
            return True, current_windows, alert

        return False, current_windows, None

    def prune_stale_records(self, current_time: datetime) -> int:
        """Prunes stale tracker entries older than window TTL."""
        stale_keys = [
            k
            for k, v in self._persistence_tracker.items()
            if (current_time - v["last_seen"]).total_seconds() > self.window_ttl_seconds
        ]
        for k in stale_keys:
            del self._persistence_tracker[k]
        return len(stale_keys)
