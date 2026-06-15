"""
SQL Injection Security Analysis and Audit Platform
Report Generator Module

Generates HTML and PDF security reports.
SECURITY NOTE: Passive analysis only - for authorized testing.
"""

import os
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path

# Import models directly for standalone execution
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.models import (
    LogEntry, SeverityLevel, VulnerabilityReport, DashboardStats
)


class ReportGenerator:
    """Generates security analysis reports in various formats."""
    
    def __init__(self):
        self.template_dir = Path(__file__).parent / "templates"
    
    def generate_report(
        self, 
        entries: List[LogEntry],
        stats: DashboardStats,
        output_format: str = "html",
        output_path: str = None
    ) -> str:
        """Generate a security report."""
        
        # Prepare data
        vulnerabilities = [e for e in entries if e.risk_score > 0]
        severity_breakdown = {
            SeverityLevel.CRITICAL: stats.critical_count,
            SeverityLevel.HIGH: stats.high_count,
            SeverityLevel.MEDIUM: stats.medium_count,
            SeverityLevel.LOW: stats.low_count
        }
        
        # Timeline data
        timeline = []
        for entry in sorted(entries, key=lambda x: x.timestamp)[:50]:
            if entry.risk_score > 0:
                timeline.append({
                    'timestamp': entry.timestamp.isoformat(),
                    'source_ip': entry.source_ip,
                    'risk_score': entry.risk_score,
                    'severity': entry.severity.value,
                    'url': entry.request.url[:100]
                })
        
        # Top risky entries
        top_risky = sorted(
            [e for e in entries if e.risk_score > 0],
            key=lambda x: x.risk_score,
            reverse=True
        )[:10]
        
        # Generate recommendations
        recommendations = self._generate_recommendations(vulnerabilities, stats)
        
        report = VulnerabilityReport(
            report_id=f"RPT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            generated_at=datetime.now(),
            total_logs_analyzed=len(entries),
            vulnerabilities_found=len(vulnerabilities),
            severity_breakdown={k.value: v for k, v in severity_breakdown.items()},
            timeline=timeline,
            top_risky_entries=top_risky,
            recommendations=recommendations,
            export_format=output_format.upper()
        )
        
        # Generate output
        if output_format.lower() == "html":
            content = self._generate_html_report(report, stats)
        elif output_format.lower() == "pdf":
            content = self._generate_pdf_report(report, stats, output_path)
            return output_path
        else:
            content = self._generate_text_report(report, stats)
        
        # Save to file if path provided
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
        
        return content
    
    def _generate_recommendations(self, vulnerabilities: List[LogEntry], stats: DashboardStats) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        if stats.critical_count > 0:
            recommendations.append(
                "CRITICAL: Immediate action required. Multiple critical vulnerabilities detected. "
                "Review and patch affected endpoints immediately."
            )
        
        if stats.high_count > 0:
            recommendations.append(
                "HIGH PRIORITY: Address high-severity vulnerabilities within 24-48 hours. "
                "Implement input validation and parameterized queries."
            )
        
        # Check for specific patterns
        union_based = sum(1 for v in vulnerabilities 
                         if any(d.detection_type.value == "Union-Based" for d in v.detections))
        if union_based > 0:
            recommendations.append(
                f"UNION-based attacks detected ({union_based} instances). "
                "Ensure all database queries use parameterized statements."
            )
        
        time_based = sum(1 for v in vulnerabilities 
                        if any(d.detection_type.value == "Time-Based" for d in v.detections))
        if time_based > 0:
            recommendations.append(
                f"Time-based blind SQLi detected ({time_based} instances). "
                "Consider implementing query timeouts and rate limiting."
            )
        
        if len(set(v.source_ip for v in vulnerabilities)) < 3 and len(vulnerabilities) > 10:
            recommendations.append(
                "Multiple attacks from limited IP sources. Consider implementing IP-based rate limiting or blocking."
            )
        
        if not recommendations:
            recommendations.append("Continue monitoring and maintain current security controls.")
        
        recommendations.append(
            "General: Implement Web Application Firewall (WAF) rules for SQL injection protection."
        )
        recommendations.append(
            "General: Conduct regular security audits and penetration testing."
        )
        
        return recommendations
    
    def _generate_html_report(self, report: VulnerabilityReport, stats: DashboardStats) -> str:
        """Generate HTML format report."""
        
        severity_colors = {
            "Critical": "#9C27B0",
            "High": "#F44336",
            "Medium": "#FF9800",
            "Low": "#4CAF50"
        }
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Security Analysis Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #00d9ff; margin-bottom: 10px; }}
        h2 {{ color: #00d9ff; margin: 20px 0 10px; border-bottom: 2px solid #00d9ff; padding-bottom: 5px; }}
        h3 {{ color: #fff; margin: 15px 0 10px; }}
        .header {{ background: linear-gradient(135deg, #16213e, #1a1a2e); padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #16213e; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 2.5em; font-weight: bold; }}
        .stat-label {{ color: #888; margin-top: 5px; }}
        .critical {{ color: #9C27B0; }}
        .high {{ color: #F44336; }}
        .medium {{ color: #FF9800; }}
        .low {{ color: #4CAF50; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background: #16213e; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #0f3460; color: #00d9ff; }}
        tr:hover {{ background: #1a1a2e; }}
        .severity-badge {{ padding: 4px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; }}
        .recommendations {{ background: #16213e; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .recommendations li {{ margin: 10px 0; padding-left: 10px; }}
        .footer {{ text-align: center; margin-top: 40px; color: #666; font-size: 0.9em; }}
        code {{ background: #0f3460; padding: 2px 6px; border-radius: 4px; font-family: 'Consolas', monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 SQL Injection Security Analysis Report</h1>
            <p style="color: #888;">Report ID: {report.report_id}</p>
            <p style="color: #888;">Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <h2>Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{stats.total_logs}</div>
                <div class="stat-label">Total Logs Analyzed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{report.vulnerabilities_found}</div>
                <div class="stat-label">Vulnerabilities Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats.unique_ips}</div>
                <div class="stat-label">Unique Source IPs</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats.time_range_hours:.1f}h</div>
                <div class="stat-label">Time Range</div>
            </div>
        </div>
        
        <h2>Severity Distribution</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value critical">{report.severity_breakdown.get('Critical', 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value high">{report.severity_breakdown.get('High', 0)}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value medium">{report.severity_breakdown.get('Medium', 0)}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-value low">{report.severity_breakdown.get('Low', 0)}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
        
        <h2>Top Risky Entries</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>Risk Score</th>
                    <th>Severity</th>
                    <th>URL</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for entry in report.top_risky_entries[:10]:
            severity_color = severity_colors.get(entry.severity.value, "#9E9E9E")
            html += f"""
                <tr>
                    <td>{entry.id}</td>
                    <td>{entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td>
                    <td>{entry.source_ip}</td>
                    <td>{entry.risk_score}</td>
                    <td><span class="severity-badge" style="background: {severity_color};">{entry.severity.value}</span></td>
                    <td><code>{entry.request.url[:60]}...</code></td>
                </tr>
"""
        
        html += """
            </tbody>
        </table>
        
        <h2>Activity Timeline</h2>
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Source IP</th>
                    <th>Severity</th>
                    <th>Risk Score</th>
                    <th>Target URL</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for event in report.timeline[:20]:
            severity_color = severity_colors.get(event['severity'], "#9E9E9E")
            html += f"""
                <tr>
                    <td>{event['timestamp'][:19]}</td>
                    <td>{event['source_ip']}</td>
                    <td><span class="severity-badge" style="background: {severity_color};">{event['severity']}</span></td>
                    <td>{event['risk_score']}</td>
                    <td><code>{event['url']}...</code></td>
                </tr>
"""
        
        html += f"""
            </tbody>
        </table>
        
        <h2>Security Recommendations</h2>
        <div class="recommendations">
            <ul>
"""
        
        for rec in report.recommendations:
            html += f"<li>{rec}</li>\n"
        
        html += f"""
            </ul>
        </div>
        
        <div class="footer">
            <p>Generated by SQL Injection Security Analysis Platform</p>
            <p>⚠️ This report is for authorized security testing purposes only</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
    def _generate_pdf_report(self, report: VulnerabilityReport, stats: DashboardStats, output_path: str) -> str:
        """Generate PDF format report using reportlab."""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            styles = getSampleStyleSheet()
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#00d9ff'),
                spaceAfter=30
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                textColor=colors.HexColor('#00d9ff'),
                spaceAfter=12,
                spaceBefore=12
            )
            
            story = []
            
            # Title
            story.append(Paragraph("SQL Injection Security Analysis Report", title_style))
            story.append(Paragraph(f"Report ID: {report.report_id}", styles['Normal']))
            story.append(Paragraph(f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", heading_style))
            summary_data = [
                ['Metric', 'Value'],
                ['Total Logs Analyzed', str(stats.total_logs)],
                ['Vulnerabilities Found', str(report.vulnerabilities_found)],
                ['Unique Source IPs', str(stats.unique_ips)],
                ['Critical', str(report.severity_breakdown.get('Critical', 0))],
                ['High', str(report.severity_breakdown.get('High', 0))],
                ['Medium', str(report.severity_breakdown.get('Medium', 0))],
                ['Low', str(report.severity_breakdown.get('Low', 0))],
            ]
            summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f3460')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#16213e')),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.white),
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Recommendations
            story.append(Paragraph("Security Recommendations", heading_style))
            for rec in report.recommendations:
                story.append(Paragraph(f"• {rec}", styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
            
            doc.build(story)
            return output_path
            
        except ImportError:
            # Fallback to HTML if reportlab not available
            html_path = output_path.replace('.pdf', '.html')
            return self._generate_html_report(report, stats)
    
    def _generate_text_report(self, report: VulnerabilityReport, stats: DashboardStats) -> str:
        """Generate plain text report."""
        text = report.get_summary()
        
        text += "\n\nTop Risky Entries:\n"
        text += "-" * 80 + "\n"
        for entry in report.top_risky_entries[:10]:
            text += f"ID: {entry.id} | Score: {entry.risk_score} | {entry.severity.value} | {entry.source_ip} | {entry.request.url[:50]}\n"
        
        text += "\nRecommendations:\n"
        text += "-" * 80 + "\n"
        for rec in report.recommendations:
            text += f"• {rec}\n"
        
        return text
