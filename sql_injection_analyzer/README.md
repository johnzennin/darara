# SQL Injection Security Analysis Platform

A professional, modern desktop application for analyzing HTTP logs and detecting potential SQL injection vulnerabilities. Built with PyQt6.

## ⚠️ Security Notice

**This is a PASSIVE ANALYSIS TOOL ONLY:**
- ❌ No exploits are generated
- ❌ No network requests are made  
- ❌ No active scanning capabilities
- ✅ Designed for authorized penetration test log analysis only
- ✅ Offline analyzer mode

## Features

### Core Capabilities
- **Log Import**: Support for JSON, CSV, TXT log formats
- **HTTP Request Parsing**: Headers, query parameters, body analysis
- **SQL Query Pattern Analysis**: Read-only detection patterns
- **OWASP Top 10 SQLi Heuristics**:
  - UNION-based injection detection
  - Boolean-based (tautology) detection
  - Time-based blind SQLi detection
  - Error-based injection patterns
  - Stacked queries detection
  - Comment injection detection
  - Encoding anomaly detection

### Risk Scoring Engine
- 0-100 severity scoring
- CVSS-like categorization (Low/Medium/High/Critical)
- Color-coded severity indicators

### Rules Engine
- Default detection rules included
- Custom regex rule builder UI
- Enable/disable rules dynamically

### Reporting
- HTML report export (professional pentest format)
- PDF report export
- JSON forensic data export
- Vulnerability summary tables
- Timeline of suspicious activity
- Security recommendations

### UI/UX
- Dark mode modern interface (Material Design inspired)
- Sidebar navigation:
  - Dashboard with statistics & charts
  - Log Analyzer with searchable table
  - Request Inspector with detailed breakdown
  - Vulnerability Reports
  - Rules Engine
- Real-time filtering/search
- Click-through log inspection
- Smooth transitions

## Installation

```bash
# Install dependencies
pip install PyQt6 pyqtgraph matplotlib reportlab

# Run the application
python -m sql_injection_analyzer.main
```

## Usage

1. **Launch the application**:
   ```bash
   python main.py
   ```

2. **Import Logs**: Click "📂 Import Logs" and select your log files (JSON, CSV, or TXT)

3. **Run Analysis**: Click "🔬 Analyze" to scan for SQL injection patterns

4. **Review Results**: 
   - Dashboard shows statistics and risk distribution
   - Log Analyzer displays all entries with filtering
   - Double-click any entry for detailed inspection

5. **Export Report**: Generate HTML/PDF reports with findings and recommendations

## Sample Data

Sample log files are included in `data/sample_logs.json` for testing.

## Architecture

```
sql_injection_analyzer/
├── core/           # Data models and structures
├── parsers/        # Log file parsing (JSON, CSV, TXT)
├── analyzers/      # SQL injection detection engine
├── reporters/      # Report generation (HTML, PDF)
├── ui/             # PyQt6 user interface
│   ├── main_window.py
│   ├── dashboard_widget.py
│   ├── log_analyzer_widget.py
│   ├── request_inspector_widget.py
│   ├── reports_widget.py
│   └── rules_widget.py
├── data/           # Sample log files
└── main.py         # Entry point
```

## Detection Patterns

The analyzer detects these SQL injection patterns:

| Pattern Type | Description | Severity Weight |
|-------------|-------------|-----------------|
| UNION-Based | `UNION SELECT` patterns | 0.90 |
| Tautology | `OR 1=1`, always-true conditions | 0.85 |
| Stacked Queries | Multiple query execution | 0.95 |
| Time-Based | `SLEEP()`, `WAITFOR DELAY` | 0.80 |
| Comment Injection | `--`, `/* */` truncation | 0.60 |
| Encoding Anomaly | Double-encoding, base64 | 0.50 |

## Requirements

- Python 3.11+
- PyQt6
- pyqtgraph
- matplotlib (optional)
- reportlab (for PDF export)

## License

MIT License - See LICENSE file for details.

## Disclaimer

This tool is designed for **authorized security testing only**. Users are responsible for ensuring they have proper authorization before analyzing any logs or systems. The developers assume no liability for misuse of this software.
