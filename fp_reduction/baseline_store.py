from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import math
from collections import defaultdict


class BaselineStore:
    """
    Rolling baseline store maintaining per-host statistical metrics (mean, stddev)
    for numeric features, including support for time-of-day host profiles.
    Includes anomaly poisoning safeguards.
    """

    def __init__(self, window_minutes: int = 60, max_samples: int = 500):
        self.window_minutes = window_minutes
        self.max_samples = max_samples
        # host -> feature_name -> list of (timestamp, value)
        self._history: Dict[str, Dict[str, List[Tuple[datetime, float]]]] = defaultdict(lambda: defaultdict(list))
        # host -> hour (0..23) -> feature_name -> list of float values
        self._tod_history: Dict[str, Dict[int, Dict[str, List[float]]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(list))
        )

    def update(
        self,
        host: str,
        feature_name: str,
        value: float,
        timestamp: Optional[datetime] = None,
        is_warmup: bool = False,
    ) -> None:
        """
        Record a feature measurement for a host.
        Rejects extreme outliers (Z > 3.0) during live operations to prevent baseline poisoning.
        """
        now = timestamp or datetime.now()
        val = float(value)

        # Poisoning protection: if not in warmup phase and baseline exists (>= 3 samples), reject extreme anomaly values
        if not is_warmup and len(self._history[host][feature_name]) >= 3:
            mean, stddev = self.get_baseline(host, feature_name)
            if stddev > 1e-5:
                z_score = abs(val - mean) / stddev
                if z_score > 3.0:
                    # Ignore extreme outlier from poisoning the baseline
                    return

        # Clean old samples outside rolling window
        cutoff = now - timedelta(minutes=self.window_minutes)
        samples = self._history[host][feature_name]
        samples.append((now, val))

        self._history[host][feature_name] = [
            (ts, v) for ts, v in samples if ts >= cutoff
        ][-self.max_samples:]

        # Update time-of-day bucket (hourly 0..23)
        hour = now.hour
        tod_samples = self._tod_history[host][hour][feature_name]
        tod_samples.append(val)
        if len(tod_samples) > 200:
            tod_samples.pop(0)

    def get_baseline(self, host: str, feature_name: str) -> Tuple[float, float]:
        """
        Returns (mean, stddev) for host's feature across rolling window.
        Returns default (0.0, 1.0) if insufficient data (< 3 samples).
        """
        samples = [val for _, val in self._history[host][feature_name]]
        if len(samples) < 3:
            return 0.0, 1.0
        
        mean = sum(samples) / len(samples)
        variance = sum((x - mean) ** 2 for x in samples) / len(samples)
        stddev = math.sqrt(variance)
        return mean, max(stddev, 1e-5)

    def get_tod_baseline(self, host: str, feature_name: str, timestamp: Optional[datetime] = None) -> Tuple[float, float]:
        """
        Returns time-of-day specific (mean, stddev) for a host.
        Falls back to global host baseline if specific hour bucket has < 3 samples.
        """
        now = timestamp or datetime.now()
        hour = now.hour
        tod_samples = self._tod_history[host][hour][feature_name]
        if len(tod_samples) >= 3:
            mean = sum(tod_samples) / len(tod_samples)
            variance = sum((x - mean) ** 2 for x in tod_samples) / len(tod_samples)
            return mean, max(math.sqrt(variance), 1e-5)
        
        return self.get_baseline(host, feature_name)

    def deviation_score(
        self,
        host: str,
        feature_name: str,
        value: float,
        use_tod: bool = False,
        timestamp: Optional[datetime] = None,
    ) -> float:
        """
        Calculates standard Z-score deviation: (value - mean) / stddev.
        Returns 0.0 if insufficient historical baseline data (< 3 samples).
        """
        samples = [val for _, val in self._history[host][feature_name]]
        if len(samples) < 3:
            return 0.0

        if use_tod:
            mean, stddev = self.get_tod_baseline(host, feature_name, timestamp)
        else:
            mean, stddev = self.get_baseline(host, feature_name)
        
        if stddev < 1e-5:
            return 0.0
        return (value - mean) / stddev
