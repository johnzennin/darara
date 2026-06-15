"""
SQL Injection Security Analysis and Audit Platform
Log Parser Module

Supports JSON, CSV, and TXT log formats.
SECURITY NOTE: Passive parsing only - no network requests.
"""

import json
import csv
import re
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path

from ..core.models import LogEntry, HTTPRequest, HTTPResponse


class LogParser:
    """Parses various log formats into structured LogEntry objects."""
    
    def __init__(self):
        self.supported_extensions = {'.json', '.csv', '.txt', '.log'}
    
    def parse_file(self, file_path: str) -> List[LogEntry]:
        """Parse a log file and return list of LogEntry objects."""
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")
        
        if path.suffix.lower() not in self.supported_extensions:
            raise ValueError(f"Unsupported file format: {path.suffix}")
        
        parsers = {
            '.json': self._parse_json,
            '.csv': self._parse_csv,
            '.txt': self._parse_txt,
            '.log': self._parse_txt
        }
        
        return parsers[path.suffix.lower()](path)
    
    def _parse_json(self, path: Path) -> List[LogEntry]:
        """Parse JSON format logs."""
        entries = []
        
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle both array and single object formats
        if isinstance(data, list):
            log_items = data
        else:
            log_items = [data]
        
        for idx, item in enumerate(log_items):
            entry = self._dict_to_log_entry(item, idx)
            if entry:
                entries.append(entry)
        
        return entries
    
    def _parse_csv(self, path: Path) -> List[LogEntry]:
        """Parse CSV format logs."""
        entries = []
        
        with open(path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader):
                entry = self._dict_to_log_entry(row, idx)
                if entry:
                    entries.append(entry)
        
        return entries
    
    def _parse_txt(self, path: Path) -> List[LogEntry]:
        """Parse TXT/LOG format (HTTP request/response logs)."""
        entries = []
        
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Try to parse as raw HTTP logs
        raw_entries = self._parse_raw_http_logs(content)
        if raw_entries:
            return raw_entries
        
        # Try JSON lines format
        lines = content.strip().split('\n')
        for idx, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                entry = self._dict_to_log_entry(item, idx)
                if entry:
                    entries.append(entry)
            except json.JSONDecodeError:
                continue
        
        return entries
    
    def _parse_raw_http_logs(self, content: str) -> Optional[List[LogEntry]]:
        """Parse raw HTTP request/response logs."""
        entries = []
        
        # Pattern for HTTP request start
        request_pattern = r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP/[\d.]+'
        
        matches = list(re.finditer(request_pattern, content))
        
        for idx, match in enumerate(matches):
            start = match.start()
            end = matches[idx + 1].start() if idx + 1 < len(matches) else len(content)
            
            raw_request = content[start:end]
            
            # Parse the request
            method = match.group(1)
            url = match.group(2)
            
            # Extract headers and body
            parts = raw_request.split('\r\n\r\n', 1)
            header_section = parts[0] if parts else ""
            body = parts[1] if len(parts) > 1 else ""
            
            # Parse headers
            headers = {}
            lines = header_section.split('\r\n')[1:]  # Skip request line
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Parse query params from URL
            query_params = {}
            if '?' in url:
                path, query_string = url.split('?', 1)
                for param in query_string.split('&'):
                    if '=' in param:
                        k, v = param.split('=', 1)
                        query_params[k] = v
                    else:
                        query_params[param] = ""
                url_path = path
            else:
                url_path = url
            
            request = HTTPRequest(
                method=method,
                url=url,
                path=url_path,
                query_params=query_params,
                headers=headers,
                body=body,
                raw_request=raw_request
            )
            
            entry = LogEntry(
                id=idx,
                timestamp=datetime.now(),
                source_ip=headers.get('X-Forwarded-For', headers.get('X-Real-IP', '0.0.0.0')),
                user_agent=headers.get('User-Agent', 'Unknown'),
                request=request,
                session_id=headers.get('Cookie', '')[:32] if headers.get('Cookie') else f"session_{idx}"
            )
            entries.append(entry)
        
        return entries if entries else None
    
    def _dict_to_log_entry(self, data: Dict[str, Any], idx: int) -> Optional[LogEntry]:
        """Convert dictionary to LogEntry object."""
        try:
            # Extract timestamp
            timestamp_str = data.get('timestamp', data.get('time', ''))
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    timestamp = datetime.now()
            else:
                timestamp = datetime.now()
            
            # Extract request info
            request_data = data.get('request', data)
            
            method = request_data.get('method', 'GET')
            url = request_data.get('url', request_data.get('uri', ''))
            path = request_data.get('path', '')
            
            # Query params
            query_params = request_data.get('query_params', request_data.get('params', {}))
            if isinstance(query_params, str):
                query_params = {}
            
            # Headers
            headers = request_data.get('headers', {})
            if isinstance(headers, str):
                headers = {}
            
            # Body
            body = request_data.get('body', request_data.get('data', ''))
            
            # Content type
            content_type = headers.get('Content-Type', headers.get('content-type', ''))
            
            request = HTTPRequest(
                method=method,
                url=url,
                path=path if path else url.split('?')[0],
                query_params=query_params,
                headers=headers,
                body=body,
                content_type=content_type,
                raw_request=data.get('raw_request', '')
            )
            
            # Response (if available)
            response = None
            response_data = data.get('response', {})
            if response_data:
                response = HTTPResponse(
                    status_code=response_data.get('status_code', response_data.get('status', 0)),
                    headers=response_data.get('headers', {}),
                    body=response_data.get('body', ''),
                    content_type=response_data.get('content_type', ''),
                    response_time_ms=float(response_data.get('response_time', 0)),
                    raw_response=response_data.get('raw_response', '')
                )
            
            # Source IP and User Agent
            source_ip = data.get('source_ip', data.get('client_ip', data.get('ip', '0.0.0.0')))
            user_agent = data.get('user_agent', headers.get('User-Agent', 'Unknown'))
            session_id = data.get('session_id', data.get('session', f"session_{idx}"))
            
            return LogEntry(
                id=idx,
                timestamp=timestamp,
                source_ip=source_ip,
                user_agent=user_agent,
                request=request,
                response=response,
                session_id=session_id,
                tags=data.get('tags', [])
            )
        except Exception as e:
            print(f"Warning: Failed to parse log entry {idx}: {e}")
            return None
    
    def export_to_json(self, entries: List[LogEntry], output_path: str) -> None:
        """Export log entries to JSON format."""
        data = []
        for entry in entries:
            item = {
                'id': entry.id,
                'timestamp': entry.timestamp.isoformat(),
                'source_ip': entry.source_ip,
                'user_agent': entry.user_agent,
                'request': {
                    'method': entry.request.method,
                    'url': entry.request.url,
                    'path': entry.request.path,
                    'query_params': entry.request.query_params,
                    'headers': entry.request.headers,
                    'body': entry.request.body,
                    'content_type': entry.request.content_type
                },
                'risk_score': entry.risk_score,
                'severity': entry.severity.value,
                'detections': [
                    {
                        'type': d.detection_type.value,
                        'pattern': d.pattern_matched,
                        'location': d.location,
                        'description': d.description,
                        'confidence': d.confidence
                    }
                    for d in entry.detections
                ],
                'tags': entry.tags
            }
            if entry.response:
                item['response'] = {
                    'status_code': entry.response.status_code,
                    'headers': entry.response.headers,
                    'body': entry.response.body[:1000],  # Truncate for size
                    'response_time_ms': entry.response.response_time_ms
                }
            data.append(item)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
