"""
SQL Injection Security Analysis and Audit Platform
Core Models and Data Structures

This module defines the core data models used throughout the application.
SECURITY NOTE: This is a passive analysis tool only - no exploits are generated.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, List, Any


class SeverityLevel(Enum):
    """Risk severity levels based on CVSS-like scoring."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    
    @classmethod
    def from_score(cls, score: int) -> 'SeverityLevel':
        """Convert numeric score to severity level."""
        if score >= 90:
            return cls.CRITICAL
        elif score >= 70:
            return cls.HIGH
        elif score >= 40:
            return cls.MEDIUM
        else:
            return cls.LOW
    
    def get_color(self) -> str:
        """Get color code for UI display."""
        colors = {
            cls.LOW: "#4CAF50",
            cls.MEDIUM: "#FF9800",
            cls.HIGH: "#F44336",
            cls.CRITICAL: "#9C27B0"
        }
        return colors.get(self, "#9E9E9E")


class DetectionType(Enum):
    """Types of SQL injection detection patterns."""
    UNION_BASED = "Union-Based"
    BOOLEAN_BASED = "Boolean-Based"
    TIME_BASED = "Time-Based"
    ERROR_BASED = "Error-Based"
    STACKED_QUERIES = "Stacked Queries"
    ENCODING_ANOMALY = "Encoding Anomaly"
    TAUTOLOGY = "Tautology Detection"
    COMMENT_INJECTION = "Comment Injection"
    CUSTOM_RULE = "Custom Rule"


@dataclass
class HTTPRequest:
    """Represents a parsed HTTP request."""
    method: str = ""
    url: str = ""
    path: str = ""
    query_params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_type: str = ""
    raw_request: str = ""
    
    def get_all_inputs(self) -> List[str]:
        """Get all user-controllable inputs for analysis."""
        inputs = []
        inputs.extend(self.query_params.values())
        inputs.append(self.body)
        return [inp for inp in inputs if inp]


@dataclass
class HTTPResponse:
    """Represents a parsed HTTP response."""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_type: str = ""
    response_time_ms: float = 0.0
    raw_response: str = ""


@dataclass
class DetectionResult:
    """Result of a single detection rule evaluation."""
    detection_type: DetectionType
    pattern_matched: str
    location: str  # e.g., "query_param: id", "body: username"
    description: str
    confidence: float  # 0.0 to 1.0
    payload_sample: str = ""  # Truncated for safety


@dataclass
class LogEntry:
    """Complete log entry with request/response and analysis results."""
    id: int
    timestamp: datetime
    source_ip: str
    user_agent: str
    request: HTTPRequest
    response: Optional[HTTPResponse] = None
    detections: List[DetectionResult] = field(default_factory=list)
    risk_score: int = 0
    severity: SeverityLevel = SeverityLevel.LOW
    session_id: str = ""
    tags: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if isinstance(self.severity, str):
            self.severity = SeverityLevel[self.severity.upper()]
        if not self.timestamp:
            self.timestamp = datetime.now()


@dataclass
class AnalysisRule:
    """A detection rule for the rules engine."""
    id: str
    name: str
    description: str
    pattern: str
    detection_type: DetectionType
    severity_weight: float
    enabled: bool = True
    custom: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary for JSON export."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "pattern": self.pattern,
            "detection_type": self.detection_type.value,
            "severity_weight": self.severity_weight,
            "enabled": self.enabled,
            "custom": self.custom
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AnalysisRule':
        """Create rule from dictionary."""
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            pattern=data.get("pattern", ""),
            detection_type=DetectionType(data.get("detection_type", "CUSTOM_RULE")),
            severity_weight=float(data.get("severity_weight", 1.0)),
            enabled=data.get("enabled", True),
            custom=data.get("custom", False)
        )


@dataclass
class VulnerabilityReport:
    """Generated security report."""
    report_id: str
    generated_at: datetime
    total_logs_analyzed: int
    vulnerabilities_found: int
    severity_breakdown: Dict[SeverityLevel, int]
    timeline: List[Dict[str, Any]]
    top_risky_entries: List[LogEntry]
    recommendations: List[str]
    export_format: str = "HTML"
    
    def get_summary(self) -> str:
        """Get human-readable summary."""
        return (
            f"Security Analysis Report\n"
            f"========================\n"
            f"Generated: {self.generated_at}\n"
            f"Logs Analyzed: {self.total_logs_analyzed}\n"
            f"Vulnerabilities: {self.vulnerabilities_found}\n"
            f"\nSeverity Breakdown:\n"
            f"  Critical: {self.severity_breakdown.get(SeverityLevel.CRITICAL, 0)}\n"
            f"  High: {self.severity_breakdown.get(SeverityLevel.HIGH, 0)}\n"
            f"  Medium: {self.severity_breakdown.get(SeverityLevel.MEDIUM, 0)}\n"
            f"  Low: {self.severity_breakdown.get(SeverityLevel.LOW, 0)}"
        )


@dataclass
class DashboardStats:
    """Statistics for dashboard display."""
    total_logs: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    unique_ips: int = 0
    unique_sessions: int = 0
    time_range_hours: float = 0.0
    detection_types: Dict[str, int] = field(default_factory=dict)
    
    def get_risk_distribution(self) -> Dict[str, int]:
        """Get distribution for chart display."""
        return {
            "Critical": self.critical_count,
            "High": self.high_count,
            "Medium": self.medium_count,
            "Low": self.low_count
        }
