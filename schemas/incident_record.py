from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel


class IncidentRecord(BaseModel):
    incident_id: str
    chain_pattern: str  # e.g., "recon_to_c2_to_exfil"
    constituent_alert_ids: List[str]
    severity_multiplier: float
    narrative: str
    first_seen: datetime
    last_seen: datetime
