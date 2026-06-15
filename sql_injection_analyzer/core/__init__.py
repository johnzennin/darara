"""
SQL Injection Security Analysis and Audit Platform
Core Package Initialization

SECURITY NOTE: This is a passive analysis tool only.
No exploits are generated. No network requests are made.
Designed for authorized penetration test log analysis only.
"""

from .models import (
    SeverityLevel,
    DetectionType,
    HTTPRequest,
    HTTPResponse,
    DetectionResult,
    LogEntry,
    AnalysisRule,
    VulnerabilityReport,
    DashboardStats
)

__all__ = [
    'SeverityLevel',
    'DetectionType',
    'HTTPRequest',
    'HTTPResponse',
    'DetectionResult',
    'LogEntry',
    'AnalysisRule',
    'VulnerabilityReport',
    'DashboardStats'
]
