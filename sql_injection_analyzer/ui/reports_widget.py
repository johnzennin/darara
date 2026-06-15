"""
SQL Injection Security Analysis and Audit Platform
Reports Widget
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel,
    QPushButton, QScrollArea, QTextEdit, QFileDialog, QMessageBox
)
from PyQt6.QtCore import Qt


class ReportsWidget(QWidget):
    """Vulnerability reports widget."""
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Header
        header = QLabel("📄 Vulnerability Reports")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #00d9ff;")
        layout.addWidget(header)
        
        # Summary card
        self.summary_card = self._create_summary_card()
        layout.addWidget(self.summary_card)
        
        # Export options
        export_frame = self._create_export_options()
        layout.addWidget(export_frame)
        
        # Preview area
        preview_title = QLabel("Report Preview")
        preview_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #fff; margin-top: 10px;")
        layout.addWidget(preview_title)
        
        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setStyleSheet("""
            QTextEdit {
                background: #16213e;
                border: 1px solid #0f3460;
                border-radius: 8px;
                color: #eee;
                font-family: 'Consolas', monospace;
                font-size: 12px;
                padding: 15px;
            }
        """)
        layout.addWidget(self.preview_text, 1)
        
        # Initialize
        self.refresh_data()
    
    def _create_summary_card(self) -> QFrame:
        """Create summary statistics card."""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #16213e;
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QHBoxLayout(frame)
        
        self.summary_label = QLabel("No data available - import and analyze logs first")
        self.summary_label.setStyleSheet("color: #888; font-size: 14px;")
        self.summary_label.setWordWrap(True)
        layout.addWidget(self.summary_label)
        
        return frame
    
    def _create_export_options(self) -> QFrame:
        """Create export options panel."""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #16213e;
                border-radius: 8px;
                padding: 15px;
            }
        """)
        
        layout = QHBoxLayout(frame)
        
        layout.addWidget(QLabel("Export Format:"))
        
        # HTML Export
        html_btn = QPushButton("📄 HTML Report")
        html_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(90deg, #00d9ff, #0099cc);
                color: #000;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: linear-gradient(90deg, #00eeff, #00aadd);
            }
        """)
        html_btn.clicked.connect(lambda: self.export_report("html"))
        layout.addWidget(html_btn)
        
        # PDF Export
        pdf_btn = QPushButton("📕 PDF Report")
        pdf_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(90deg, #F44336, #D32F2F);
                color: #fff;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: linear-gradient(90deg, #F75C4B, #E53935);
            }
        """)
        pdf_btn.clicked.connect(lambda: self.export_report("pdf"))
        layout.addWidget(pdf_btn)
        
        # JSON Export
        json_btn = QPushButton("📋 JSON Data")
        json_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(90deg, #4CAF50, #388E3C);
                color: #fff;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: linear-gradient(90deg, #66BB6A, #43A047);
            }
        """)
        json_btn.clicked.connect(lambda: self.export_json())
        layout.addWidget(json_btn)
        
        layout.addStretch()
        
        return frame
    
    def refresh_data(self):
        """Refresh report data."""
        entries = self.main_window.log_entries
        
        if not entries:
            self.summary_label.setText("No data available - import and analyze logs first")
            self.preview_text.setText("")
            return
        
        # Calculate stats
        total = len(entries)
        vulnerable = sum(1 for e in entries if e.risk_score > 0)
        critical = sum(1 for e in entries if e.severity.value == "Critical")
        high = sum(1 for e in entries if e.severity.value == "High")
        medium = sum(1 for e in entries if e.severity.value == "Medium")
        low = sum(1 for e in entries if e.severity.value == "Low")
        
        summary = f"""
        <div style='padding: 10px'>
            <h3 style='color: #00d9ff'>Analysis Summary</h3>
            <p><strong>Total Logs:</strong> {total}</p>
            <p><strong>Vulnerabilities Found:</strong> {vulnerable}</p>
            <p style='color: #9C27B0'><strong>Critical:</strong> {critical}</p>
            <p style='color: #F44336'><strong>High:</strong> {high}</p>
            <p style='color: #FF9800'><strong>Medium:</strong> {medium}</p>
            <p style='color: #4CAF50'><strong>Low:</strong> {low}</p>
        </div>
        """
        
        self.summary_label.setText("")
        self.summary_label.setStyleSheet("")
        self.summary_label.setText(summary)
        
        # Generate preview
        self._generate_preview()
    
    def _generate_preview(self):
        """Generate text preview of the report."""
        entries = self.main_window.log_entries
        
        if not entries:
            self.preview_text.setText("No data to preview")
            return
        
        preview = "=" * 60 + "\n"
        preview += "SQL INJECTION SECURITY ANALYSIS REPORT\n"
        preview += "=" * 60 + "\n\n"
        
        from datetime import datetime
        preview += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # Stats
        vulnerable = [e for e in entries if e.risk_score > 0]
        preview += f"Total Entries: {len(entries)}\n"
        preview += f"Vulnerabilities: {len(vulnerable)}\n\n"
        
        # Top findings
        preview += "-" * 60 + "\n"
        preview += "TOP FINDINGS\n"
        preview += "-" * 60 + "\n\n"
        
        sorted_entries = sorted(vulnerable, key=lambda x: x.risk_score, reverse=True)[:5]
        
        for entry in sorted_entries:
            preview += f"[{entry.severity.value}] Score: {entry.risk_score}\n"
            preview += f"  IP: {entry.source_ip}\n"
            preview += f"  URL: {entry.request.url[:70]}...\n"
            preview += f"  Detections: {len(entry.detections)}\n\n"
        
        self.preview_text.setText(preview)
    
    def export_report(self, format_type: str):
        """Export report in specified format."""
        entries = self.main_window.log_entries
        
        if not entries:
            QMessageBox.warning(self, "No Data", "No log data to export. Please import and analyze logs first.")
            return
        
        file_dialog = QFileDialog()
        file_dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        
        if format_type == "html":
            file_dialog.setDefaultSuffix("html")
            file_dialog.setNameFilters(["HTML Files (*.html)"])
        else:
            file_dialog.setDefaultSuffix("pdf")
            file_dialog.setNameFilters(["PDF Files (*.pdf)"])
        
        if file_dialog.exec():
            output_path = file_dialog.selectedFiles()[0]
            
            try:
                from reporters import ReportGenerator
                from core.models import DashboardStats
                
                stats = DashboardStats(
                    total_logs=len(entries),
                    total_vulnerabilities=sum(1 for e in entries if e.risk_score > 0),
                    critical_count=sum(1 for e in entries if e.severity.value == "Critical"),
                    high_count=sum(1 for e in entries if e.severity.value == "High"),
                    medium_count=sum(1 for e in entries if e.severity.value == "Medium"),
                    low_count=sum(1 for e in entries if e.severity.value == "Low"),
                    unique_ips=len(set(e.source_ip for e in entries)),
                    unique_sessions=len(set(e.session_id for e in entries))
                )
                
                generator = ReportGenerator()
                generator.generate_report(entries, stats, format_type, output_path)
                
                QMessageBox.information(self, "Export Complete", f"Report saved to:\n{output_path}")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export report:\n{str(e)}")
    
    def export_json(self):
        """Export forensic data as JSON."""
        entries = self.main_window.log_entries
        
        if not entries:
            QMessageBox.warning(self, "No Data", "No log data to export.")
            return
        
        file_dialog = QFileDialog()
        file_dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        file_dialog.setDefaultSuffix("json")
        file_dialog.setNameFilters(["JSON Files (*.json)"])
        
        if file_dialog.exec():
            output_path = file_dialog.selectedFiles()[0]
            
            try:
                from parsers import LogParser
                
                parser = LogParser()
                parser.export_to_json(entries, output_path)
                
                QMessageBox.information(self, "Export Complete", f"JSON data saved to:\n{output_path}")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export JSON:\n{str(e)}")
