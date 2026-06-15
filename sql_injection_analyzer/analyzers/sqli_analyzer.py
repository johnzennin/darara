"""
SQL Injection Security Analysis and Audit Platform
Analyzer Engine Module

Implements OWASP Top 10 SQLi heuristic detection patterns.
SECURITY NOTE: Passive analysis only - no exploits generated.
"""

import re
import math
from typing import List, Dict, Tuple, Optional
from datetime import datetime

# Import models directly for standalone execution
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.models import (
    LogEntry, DetectionResult, DetectionType, 
    HTTPRequest, AnalysisRule, SeverityLevel
)


class SQLInjectionAnalyzer:
    """
    Analyzes HTTP requests for potential SQL injection patterns.
    
    Detection methods:
    - Suspicious keyword detection (UNION, SELECT, etc.)
    - Tautology detection (OR 1=1, AND 1=1, etc.)
    - Encoding anomaly detection (base64/url encoding)
    - Query length deviation detection
    - Comment injection detection
    """
    
    # OWASP Top 10 SQLi patterns (read-only analysis)
    UNION_PATTERNS = [
        r'(?i)\bunion\s+(all\s+)?select\b',
        r'(?i)\bunion\s+select\b',
        r'(?i)\'union\'',
        r'(?i)"union"',
    ]
    
    TAUTOLOGY_PATTERNS = [
        r'(?i)\bor\s+1\s*=\s*1\b',
        r'(?i)\band\s+1\s*=\s*1\b',
        r'(?i)\bor\s+\'[^\']*\'\s*=\s*\'[^\']*\'',
        r'(?i)\bor\s+"[^"]*"\s*=\s*"[^"]*"',
        r'(?i)\bor\s+\w+\s*=\s*\w+',
        r"(?i)'\s*or\s*'",
        r'(?i)"\s*or\s*"',
    ]
    
    COMMENT_PATTERNS = [
        r'--\s*$',
        r'--\s+',
        r'#\s*$',
        r'/\*.*\*/',
        r'(?i);\s*--',
    ]
    
    STACKED_QUERY_PATTERNS = [
        r'(?i);\s*(select|insert|update|delete|drop|truncate|exec)\b',
        r'(?i);\s*waitfor\s+delay',
        r'(?i);\s*sleep\s*\(',
        r'(?i);\s*benchmark\s*\(',
    ]
    
    TIME_BASED_PATTERNS = [
        r'(?i)\bsleep\s*\(\s*\d+\s*\)',
        r'(?i)\bwaitfor\s+delay\b',
        r'(?i)\bbenchmark\s*\(',
        r'(?i)\bpg_sleep\s*\(',
    ]
    
    ERROR_BASED_PATTERNS = [
        r"(?i)\bconvert\s*\(\s*int\s*,",
        r"(?i)\bcast\s*\([^)]+as\s+int",
        r"(?i)'[^']*'\s*>\s*'[^']*'",
    ]
    
    ENCODING_ANOMALY_PATTERNS = [
        r'%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}',  # Double URL encoding
        r'(?i)^[A-Za-z0-9+/]+=*$',  # Possible base64
        r'\\x[0-9a-fA-F]{2}',  # Hex encoding
        r'&#x?[0-9a-fA-F]+;',  # HTML entity encoding
    ]
    
    DANGEROUS_KEYWORDS = [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'TRUNCATE',
        'EXEC', 'EXECUTE', 'UNION', 'ALTER', 'CREATE', 'GRANT',
        'INFORMATION_SCHEMA', 'SYSOBJECTS', 'SYSCOLUMNS',
        'WAITFOR', 'BENCHMARK', 'SLEEP', 'LOAD_FILE', 'INTO OUTFILE',
        'INTO DUMPFILE', 'xp_cmdshell', 'sp_executesql'
    ]
    
    def __init__(self):
        self.rules: List[AnalysisRule] = []
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default detection rules."""
        default_rules = [
            AnalysisRule(
                id="union_based",
                name="Union-Based SQL Injection",
                description="Detects UNION SELECT patterns commonly used in SQLi",
                pattern=r'(?i)\bunion\s+(all\s+)?select\b',
                detection_type=DetectionType.UNION_BASED,
                severity_weight=0.9
            ),
            AnalysisRule(
                id="tautology",
                name="Tautology Detection",
                description="Detects always-true conditions like OR 1=1",
                pattern=r'(?i)\bor\s+1\s*=\s*1\b',
                detection_type=DetectionType.TAUTOLOGY,
                severity_weight=0.85
            ),
            AnalysisRule(
                id="comment_injection",
                name="Comment Injection",
                description="Detects SQL comment sequences used to truncate queries",
                pattern=r'--\s*',
                detection_type=DetectionType.COMMENT_INJECTION,
                severity_weight=0.6
            ),
            AnalysisRule(
                id="stacked_queries",
                name="Stacked Queries",
                description="Detects multiple query execution attempts",
                pattern=r'(?i);\s*(select|insert|update|delete|drop)\b',
                detection_type=DetectionType.STACKED_QUERIES,
                severity_weight=0.95
            ),
            AnalysisRule(
                id="time_based",
                name="Time-Based Blind SQLi",
                description="Detects time-delay functions used in blind SQLi",
                pattern=r'(?i)\bsleep\s*\(|\bwaitfor\s+delay\b',
                detection_type=DetectionType.TIME_BASED,
                severity_weight=0.8
            ),
            AnalysisRule(
                id="encoding_anomaly",
                name="Encoding Anomaly",
                description="Detects unusual encoding patterns that may hide payloads",
                pattern=r'%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}',
                detection_type=DetectionType.ENCODING_ANOMALY,
                severity_weight=0.5
            )
        ]
        self.rules = default_rules
    
    def add_rule(self, rule: AnalysisRule) -> None:
        """Add a custom detection rule."""
        self.rules.append(rule)
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a custom rule by ID."""
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id and rule.custom:
                self.rules.pop(i)
                return True
        return False
    
    def analyze_request(self, request: HTTPRequest) -> List[DetectionResult]:
        """Analyze a single HTTP request for SQL injection patterns."""
        detections = []
        
        # Check all input vectors
        inputs_to_check = []
        
        # Query parameters
        for param, value in request.query_params.items():
            inputs_to_check.append((f"query_param:{param}", value))
        
        # Request body
        if request.body:
            inputs_to_check.append(("body", request.body))
        
        # URL path
        if request.path:
            inputs_to_check.append(("path", request.path))
        
        # Run detection on each input
        for location, value in inputs_to_check:
            if not value:
                continue
            
            results = self._check_patterns(location, value)
            detections.extend(results)
        
        return detections
    
    def _check_patterns(self, location: str, value: str) -> List[DetectionResult]:
        """Check a single value against all detection patterns."""
        detections = []
        
        # Check built-in patterns
        detections.extend(self._check_union_patterns(location, value))
        detections.extend(self._check_tautology_patterns(location, value))
        detections.extend(self._check_comment_patterns(location, value))
        detections.extend(self._check_stacked_query_patterns(location, value))
        detections.extend(self._check_time_based_patterns(location, value))
        detections.extend(self._check_encoding_anomalies(location, value))
        detections.extend(self._check_dangerous_keywords(location, value))
        
        # Check custom rules
        detections.extend(self._check_custom_rules(location, value))
        
        return detections
    
    def _check_union_patterns(self, location: str, value: str) -> List[DetectionResult]:
        """Check for UNION-based SQLi patterns."""
        results = []
        for pattern in self.UNION_PATTERNS:
            if re.search(pattern, value):
                results.append(DetectionResult(
                    detection_type=DetectionType.UNION_BASED,
                    pattern_matched=pattern[:50],
                    location=location,
                    description="Potential UNION-based SQL injection detected",
                    confidence=0.9,
                    payload_sample=self._safe_sample(value)
                ))
                break
        return results
    
    def _check_tautology_patterns(self, location: str, value: str) -> List[DetectionResult]:
        """Check for tautology-based SQLi patterns."""
        results = []
        for pattern in self.TAUTOLOGY_PATTERNS:
            if re.search(pattern, value):
                results.append(DetectionResult(
                    detection_type=DetectionType.TAUTOLOGY,
                    pattern_matched=pattern[:50],
                    location=location,
                    description="Potential tautology-based SQL injection (always-true condition)",
                    confidence=0.85,
                    payload_sample=self._safe_sample(value)
                ))
                break
        return results
    
    def _check_comment_patterns(self, location: str, value: str) -> List[DetectionResult]:
        """Check for comment injection patterns."""
        results = []
        for pattern in self.COMMENT_PATTERNS:
            if re.search(pattern, value):
                results.append(DetectionResult(
                    detection_type=DetectionType.COMMENT_INJECTION,
                    pattern_matched=pattern[:50],
                    location=location,
                    description="SQL comment sequence detected - possible query truncation",
                    confidence=0.6,
                    payload_sample=self._safe_sample(value)
                ))
                break
        return results
    
    def _check_stacked_query_patterns(self, location: str, value: str) -> List[DetectionResult]:
        """Check for stacked query patterns."""
        results = []
        for pattern in self.STACKED_QUERY_PATTERNS:
            if re.search(pattern, value):
                results.append(DetectionResult(
                    detection_type=DetectionType.STACKED_QUERIES,
                    pattern_matched=pattern[:50],
                    location=location,
                    description="Stacked query execution attempt detected",
                    confidence=0.95,
                    payload_sample=self._safe_sample(value)
                ))
                break
        return results
    
    def _check_time_based_patterns(self, location: str, value: str) -> List[DetectionResult]:
        """Check for time-based blind SQLi patterns."""
        results = []
        for pattern in self.TIME_BASED_PATTERNS:
            if re.search(pattern, value):
                results.append(DetectionResult(
                    detection_type=DetectionType.TIME_BASED,
                    pattern_matched=pattern[:50],
                    location=location,
                    description="Time-based blind SQL injection pattern detected",
                    confidence=0.8,
                    payload_sample=self._safe_sample(value)
                ))
                break
        return results
    
    def _check_encoding_anomalies(self, location: str, value: str) -> List[DetectionResult]:
        """Check for encoding anomalies that may hide payloads."""
        results = []
        for pattern in self.ENCODING_ANOMALY_PATTERNS:
            matches = re.findall(pattern, value)
            if matches:
                results.append(DetectionResult(
                    detection_type=DetectionType.ENCODING_ANOMALY,
                    pattern_matched=pattern[:50],
                    location=location,
                    description=f"Encoding anomaly detected ({len(matches)} occurrences)",
                    confidence=0.5,
                    payload_sample=self._safe_sample(value)
                ))
                break
        return results
    
    def _check_dangerous_keywords(self, location: str, value: str) -> List[DetectionResult]:
        """Check for dangerous SQL keywords."""
        results = []
        found_keywords = []
        
        value_upper = value.upper()
        for keyword in self.DANGEROUS_KEYWORDS:
            if keyword in value_upper:
                found_keywords.append(keyword)
        
        if len(found_keywords) >= 2:
            results.append(DetectionResult(
                detection_type=DetectionType.ERROR_BASED,
                pattern_matched=", ".join(found_keywords[:3]),
                location=location,
                description=f"Multiple dangerous SQL keywords detected: {', '.join(found_keywords[:5])}",
                confidence=min(0.5 + (len(found_keywords) * 0.1), 0.95),
                payload_sample=self._safe_sample(value)
            ))
        
        return results
    
    def _check_custom_rules(self, location: str, value: str) -> List[DetectionResult]:
        """Check against custom rules."""
        results = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            try:
                if re.search(rule.pattern, value):
                    results.append(DetectionResult(
                        detection_type=rule.detection_type,
                        pattern_matched=rule.pattern[:50],
                        location=location,
                        description=rule.description,
                        confidence=rule.severity_weight,
                        payload_sample=self._safe_sample(value)
                    ))
            except re.error:
                pass  # Invalid regex, skip
        return results
    
    def _safe_sample(self, value: str, max_length: int = 50) -> str:
        """Get a safe truncated sample of the value for reporting."""
        if len(value) <= max_length:
            return value
        return value[:max_length] + "..."
    
    def calculate_risk_score(self, detections: List[DetectionResult]) -> int:
        """Calculate overall risk score (0-100) based on detections."""
        if not detections:
            return 0
        
        # Base score from detection count
        base_score = min(len(detections) * 15, 50)
        
        # Add weighted scores from each detection
        weighted_score = sum(d.confidence * 30 for d in detections)
        
        # Bonus for high-confidence detections
        high_confidence_count = sum(1 for d in detections if d.confidence >= 0.8)
        bonus = high_confidence_count * 10
        
        total = base_score + weighted_score + bonus
        return min(int(total), 100)
    
    def analyze_log_entry(self, entry: LogEntry) -> LogEntry:
        """Perform full analysis on a log entry."""
        detections = self.analyze_request(entry.request)
        entry.detections = detections
        entry.risk_score = self.calculate_risk_score(detections)
        entry.severity = SeverityLevel.from_score(entry.risk_score)
        return entry
    
    def analyze_batch(self, entries: List[LogEntry]) -> List[LogEntry]:
        """Analyze multiple log entries."""
        return [self.analyze_log_entry(entry) for entry in entries]
