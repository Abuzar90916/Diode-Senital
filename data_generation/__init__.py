"""
Data generation package for Diode-Sentinel.
"""

from .benign_traffic_gen import BenignTrafficGenerator
from .attack_traffic_gen import AttackTrafficGenerator

__all__ = [
    "BenignTrafficGenerator",
    "AttackTrafficGenerator"
]
