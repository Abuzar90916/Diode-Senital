from typing import Dict, Tuple
from schemas.alert_record import AlertCandidate, ThreatClass


class CorroborationEngine:
    """
    Central corroboration enforcement engine.
    Ensures no single-signal alert is ever produced. Rejects any AlertCandidate
    with fewer than the required minimum independent signals (default 2).
    """

    def __init__(self, default_min_signals: int = 2):
        self.default_min_signals = default_min_signals
        # Per threat-class overrides if configured
        self.min_signals_per_class: Dict[ThreatClass, int] = {
            ThreatClass.DDOS: 2,
            ThreatClass.C2_BEACONING: 2,
            ThreatClass.DGA_TUNNELLING: 2,
            ThreatClass.ENCRYPTED_MALWARE: 2,
            ThreatClass.PORT_SCANNING: 2,
            ThreatClass.DATA_EXFILTRATION: 2,
        }

    def evaluate_candidate(self, candidate: AlertCandidate) -> Tuple[bool, int, str]:
        """
        Evaluates an AlertCandidate against corroboration rules.

        Returns:
            (passed: bool, valid_signal_count: int, reason: str)
        """
        required_signals = self.min_signals_per_class.get(
            candidate.threat_class, self.default_min_signals
        )
        
        # Deduplicate signals to ensure true independence
        unique_signals = list(dict.fromkeys(candidate.signals))
        valid_count = len(unique_signals)

        if valid_count < required_signals:
            reason = (
                f"REJECTED_SINGLE_SIGNAL: Candidate for {candidate.threat_class.value} "
                f"produced only {valid_count} signal(s) ({', '.join(unique_signals)}), "
                f"minimum required is {required_signals}."
            )
            return False, valid_count, reason

        # Construct concise evidence summary combining distinct signals
        evidence_summary = " | ".join(candidate.raw_evidence)
        reason = f"PASSED_CORROBORATION: {valid_count} independent signals verified ({evidence_summary})."
        return True, valid_count, reason
