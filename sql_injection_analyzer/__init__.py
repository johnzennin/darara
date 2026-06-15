"""
SQL Injection Security Analysis and Audit Platform

A professional desktop application for analyzing HTTP logs and detecting
potential SQL injection vulnerabilities. 

SECURITY NOTE: This is a passive analysis tool only.
- No exploits are generated
- No network requests are made
- Designed for authorized penetration test log analysis only
"""

__version__ = "1.0.0"
__author__ = "Security Team"

from .core.models import (
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

from .parsers.log_parser import LogParser
from .analyzers.sqli_analyzer import SQLInjectionAnalyzer
from .reporters.report_generator import ReportGenerator

__all__ = [
    # Core models
    'SeverityLevel',
    'DetectionType',
    'HTTPRequest',
    'HTTPResponse',
    'DetectionResult',
    'LogEntry',
    'AnalysisRule',
    'VulnerabilityReport',
    'DashboardStats',
    # Parsers
    'LogParser',
    # Analyzers
    'SQLInjectionAnalyzer',
    # Reporters
    'ReportGenerator'
]
