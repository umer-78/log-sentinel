"""Detect SSH brute-force activity in auth logs."""

from .detector import Alert, DetectorConfig, detect
from .parser import AuthEvent, parse_line, parse_lines

__all__ = ["Alert", "AuthEvent", "DetectorConfig", "detect", "parse_line", "parse_lines"]
__version__ = "1.0.0"
