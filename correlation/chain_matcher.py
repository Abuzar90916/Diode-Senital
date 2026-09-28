from datetime import datetime
from typing import List, Dict, Optional
import uuid
from schemas.alert_record import Alert, ThreatClass
from schemas.incident_record import IncidentRecord
from correlation.entity_graph import EntityGraph


class ChainMatcher:
    """
    Attack-Chain Correlation Engine matching 3 explicit multi-stage attack patterns:
    1. Recon -> C2 -> Exfiltration (recon_to_c2_to_exfil)
    2. DGA -> C2 check-in (dga_to_c2)
    3. DDoS as smokescreen (ddos_smokescreen)
    
    Generates IncidentRecord objects, updates constituent alert incident_ids,
    calculates severity multipliers, and produces explainable natural language narratives.
    """

    def __init__(self, entity_graph: Optional[EntityGraph] = None):
        self.graph = entity_graph or EntityGraph()
        self.incidents: Dict[str, IncidentRecord] = {}

    def process_new_alerts(self, alerts: List[Alert]) -> List[IncidentRecord]:
        """
        Process a stream of new Alert objects through the correlation engine.

        Returns:
            List of newly matched IncidentRecord objects.
        """
        for alert in alerts:
            self.graph.add_alert(alert)

        new_incidents: List[IncidentRecord] = []

        # Check Pattern 1: Recon -> C2 -> Exfiltration
        inc_p1 = self._check_recon_c2_exfil()
        if inc_p1:
            new_incidents.extend(inc_p1)

        # Check Pattern 2: DGA -> C2 Check-in
        inc_p2 = self._check_dga_to_c2()
        if inc_p2:
            new_incidents.extend(inc_p2)

        # Check Pattern 3: DDoS as Smokescreen
        inc_p3 = self._check_ddos_smokescreen()
        if inc_p3:
            new_incidents.extend(inc_p3)

        return new_incidents

    def _check_recon_c2_exfil(self) -> List[IncidentRecord]:
        """
        Pattern 1: Recon -> C2 -> Exfiltration
        Looks for Port_Scanning, C2_Beaconing, and Data_Exfiltration alerts on the same host/entity.
        """
        incidents = []
        for host, alist in self.graph.host_alerts.items():
            threat_map = {a.threat_class: a for a in alist if a.incident_id is None}
            
            if (
                ThreatClass.PORT_SCANNING in threat_map
                and ThreatClass.C2_BEACONING in threat_map
                and ThreatClass.DATA_EXFILTRATION in threat_map
            ):
                ps_alt = threat_map[ThreatClass.PORT_SCANNING]
                c2_alt = threat_map[ThreatClass.C2_BEACONING]
                ex_alt = threat_map[ThreatClass.DATA_EXFILTRATION]

                inc_id = f"INC-RECON-EXFIL-{uuid.uuid4().hex[:6].upper()}"
                constituent_ids = [ps_alt.alert_id, c2_alt.alert_id, ex_alt.alert_id]

                # Update constituent alert incident IDs
                ps_alt.incident_id = inc_id
                c2_alt.incident_id = inc_id
                ex_alt.incident_id = inc_id

                timestamps = [ps_alt.timestamp, c2_alt.timestamp, ex_alt.timestamp]
                first_seen = min(timestamps)
                last_seen = max(timestamps)

                narrative = (
                    f"Multi-stage intrusion chain identified on host '{host}': "
                    f"Initial port scan reconnaissance detected at {ps_alt.timestamp.strftime('%H:%M:%S')}, "
                    f"followed by active C2 beaconing channel established at {c2_alt.timestamp.strftime('%H:%M:%S')}, "
                    f"culminating in data exfiltration at {ex_alt.timestamp.strftime('%H:%M:%S')}."
                )

                incident = IncidentRecord(
                    incident_id=inc_id,
                    chain_pattern="recon_to_c2_to_exfil",
                    constituent_alert_ids=constituent_ids,
                    severity_multiplier=2.5,
                    narrative=narrative,
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
                self.incidents[inc_id] = incident
                incidents.append(incident)

        return incidents

    def _check_dga_to_c2(self) -> List[IncidentRecord]:
        """
        Pattern 2: DGA -> C2 Check-in
        DGA domain resolution followed by C2 beaconing on the same host within 15 minutes.
        """
        incidents = []
        for host, alist in self.graph.host_alerts.items():
            unlinked = [a for a in alist if a.incident_id is None]
            dga_alts = [a for a in unlinked if a.threat_class == ThreatClass.DGA_TUNNELLING]
            c2_alts = [a for a in unlinked if a.threat_class == ThreatClass.C2_BEACONING]

            if dga_alts and c2_alts:
                dga = dga_alts[0]
                c2 = c2_alts[0]

                time_diff = abs((dga.timestamp - c2.timestamp).total_seconds())
                if time_diff <= 900:  # 15 minutes temporal window
                    inc_id = f"INC-DGA-C2-{uuid.uuid4().hex[:6].upper()}"
                    constituent_ids = [dga.alert_id, c2.alert_id]

                    dga.incident_id = inc_id
                    c2.incident_id = inc_id

                    timestamps = [dga.timestamp, c2.timestamp]
                    first_seen = min(timestamps)
                    last_seen = max(timestamps)

                    narrative = (
                        f"DGA-to-C2 check-in chain identified on host '{host}': "
                        f"Algorithmically generated domain (DGA) query detected at {dga.timestamp.strftime('%H:%M:%S')}, "
                        f"followed by active C2 beaconing check-in at {c2.timestamp.strftime('%H:%M:%S')}."
                    )

                    incident = IncidentRecord(
                        incident_id=inc_id,
                        chain_pattern="dga_to_c2",
                        constituent_alert_ids=constituent_ids,
                        severity_multiplier=1.8,
                        narrative=narrative,
                        first_seen=first_seen,
                        last_seen=last_seen,
                    )
                    self.incidents[inc_id] = incident
                    incidents.append(incident)

        return incidents

    def _check_ddos_smokescreen(self) -> List[IncidentRecord]:
        """
        Pattern 3: DDoS as Smokescreen
        DDoS alert active in time with an unrelated Data Exfiltration alert on a different host.
        """
        incidents = []
        all_alerts = list(self.graph.alerts_by_id.values())
        unlinked = [a for a in all_alerts if a.incident_id is None]

        ddos_alts = [a for a in unlinked if a.threat_class == ThreatClass.DDOS]
        exfil_alts = [a for a in unlinked if a.threat_class == ThreatClass.DATA_EXFILTRATION]

        for ddos in ddos_alts:
            for exfil in exfil_alts:
                ddos_host = ddos.src_ip or ddos.host
                exfil_host = exfil.src_ip or exfil.host
                # Must be on different hosts and coinciding within 15 minutes (900s)
                if ddos_host != exfil_host and ddos.incident_id is None and exfil.incident_id is None:
                    time_diff = abs((ddos.timestamp - exfil.timestamp).total_seconds())
                    if time_diff <= 900:
                        inc_id = f"INC-SMOKESCREEN-{uuid.uuid4().hex[:6].upper()}"
                        constituent_ids = [ddos.alert_id, exfil.alert_id]

                        ddos.incident_id = inc_id
                        exfil.incident_id = inc_id

                        timestamps = [ddos.timestamp, exfil.timestamp]
                        first_seen = min(timestamps)
                        last_seen = max(timestamps)

                        narrative = (
                            f"DDoS Smokescreen attack pattern detected: "
                            f"Volumetric DDoS attack on host '{ddos_host}' at {ddos.timestamp.strftime('%H:%M:%S')} "
                            f"coincided with simultaneous data exfiltration on critical host '{exfil_host}' at {exfil.timestamp.strftime('%H:%M:%S')}."
                        )

                        incident = IncidentRecord(
                            incident_id=inc_id,
                            chain_pattern="ddos_smokescreen",
                            constituent_alert_ids=constituent_ids,
                            severity_multiplier=2.0,
                            narrative=narrative,
                            first_seen=first_seen,
                            last_seen=last_seen,
                        )
                        self.incidents[inc_id] = incident
                        incidents.append(incident)

        return incidents
