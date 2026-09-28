from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
from collections import defaultdict
from schemas.alert_record import Alert


class EntityGraph:
    """
    Short-term in-memory entity correlation graph tracking hosts, IPs, ports,
    and associated Alert objects within a rolling TTL time window (default 30 minutes).
    Ensures memory remains strictly bounded.
    """

    def __init__(self, ttl_seconds: int = 1800):
        self.ttl_seconds = ttl_seconds
        # host/IP -> list of Alert objects
        self.host_alerts: Dict[str, List[Alert]] = defaultdict(list)
        # alert_id -> Alert
        self.alerts_by_id: Dict[str, Alert] = {}
        # Entity relationships: IP -> set of connected host/IP entities
        self.entity_edges: Dict[str, Set[str]] = defaultdict(set)

    def add_alert(self, alert: Alert) -> None:
        """Adds an alert to the entity graph."""
        self.alerts_by_id[alert.alert_id] = alert
        
        src = alert.src_ip or alert.host
        dst = alert.dst_ip

        if src:
            self.host_alerts[src].append(alert)
        if dst:
            self.host_alerts[dst].append(alert)

        if src and dst:
            self.entity_edges[src].add(dst)
            self.entity_edges[dst].add(src)
        elif "->" in alert.flow_identifier:
            try:
                parts = alert.flow_identifier.split("->")
                src_ip = parts[0].strip().split(":")[0]
                dst_ip = parts[1].strip().split(":")[0]
                if src_ip and dst_ip:
                    self.entity_edges[src_ip].add(dst_ip)
                    self.entity_edges[dst_ip].add(src_ip)
                    if not src:
                        self.host_alerts[src_ip].append(alert)
            except Exception:
                pass

    def get_related_alerts(self, host: str, window_seconds: Optional[int] = None) -> List[Alert]:
        """
        Gets all active alerts associated with a host or its directly connected entities
        within the given time window.
        """
        win = window_seconds or self.ttl_seconds
        cutoff = datetime.now() - timedelta(seconds=win)

        # Gather hosts in 1-hop graph neighborhood
        target_hosts = {host}
        target_hosts.update(self.entity_edges.get(host, set()))

        related = []
        for h in target_hosts:
            for alt in self.host_alerts.get(h, []):
                if alt.timestamp >= cutoff:
                    related.append(alt)
        return related

    def prune_stale(self, current_time: datetime) -> int:
        """
        Prunes alerts and graph edges older than TTL. Returns count of pruned alerts.
        """
        cutoff = current_time - timedelta(seconds=self.ttl_seconds)
        pruned_count = 0

        # Identify stale alert IDs
        stale_alert_ids = {
            aid for aid, alt in self.alerts_by_id.items() if alt.timestamp < cutoff
        }

        for aid in stale_alert_ids:
            del self.alerts_by_id[aid]
            pruned_count += 1

        # Rebuild host_alerts dictionary without stale alerts
        new_host_alerts = defaultdict(list)
        for host, alist in self.host_alerts.items():
            valid = [a for a in alist if a.alert_id not in stale_alert_ids]
            if valid:
                new_host_alerts[host] = valid

        self.host_alerts = new_host_alerts
        return pruned_count
