from datetime import datetime
from enum import Enum
from typing import Optional, List
import uuid
from pydantic import BaseModel, Field


class ThreatClass(str, Enum):
    DDOS = "DDoS"
    C2_BEACONING = "C2_Beaconing"
    DGA_TUNNELLING = "DGA_Tunnelling"
    ENCRYPTED_MALWARE = "Encrypted_Malware"
    PORT_SCANNING = "Port_Scanning"
    DATA_EXFILTRATION = "Data_Exfiltration"


class AlertCandidate(BaseModel):
    timestamp: datetime
    flow_identifier: str
    threat_class: ThreatClass
    confidence_score: float  # 0.0 to 1.0
    raw_evidence: List[str]  # Detailed per-signal text descriptions with feature values
    signals: List[str]       # Distinct signal identifiers
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    domain: Optional[str] = None
    host: Optional[str] = None

    def model_post_init(self, __context):
        if self.host is None and self.src_ip is not None:
            self.host = self.src_ip
        elif self.src_ip is None and self.host is not None:
            self.src_ip = self.host


class Alert(BaseModel):
    timestamp: datetime
    flow_identifier: str
    threat_class: ThreatClass
    confidence_score: float  # 0.0–1.0
    supporting_evidence: str  # human-readable explainable text with exact feature values
    corroboration_count: int
    persistence_windows: int
    incident_id: Optional[str] = None
    alert_id: str = Field(default_factory=lambda: f"ALT-{uuid.uuid4().hex[:8].upper()}")
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    host: Optional[str] = None

    def model_post_init(self, __context):
        if self.host is None and self.src_ip is not None:
            self.host = self.src_ip
        elif self.src_ip is None and self.host is not None:
            self.src_ip = self.host
