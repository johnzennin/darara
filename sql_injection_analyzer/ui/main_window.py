"""
SQL Injection Security Analysis and Audit Platform
Main Window with Modern Dark Theme UI

SECURITY NOTE: Passive analysis tool only - no exploits generated.
"""

import sys
from datetime import datetime
from typing import Optional, List

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget,
    QPushButton, QLabel, QFrame, QScrollArea, QSplitter, QFileDialog,
    QMessageBox, QToolBar, QStatusBar, QProgressBar, QApplication
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QSize
from PyQt6.QtGui import QIcon, QFont, QAction

from .dashboard_widget import DashboardWidget
from .log_analyzer_widget import LogAnalyzerWidget
from .request_inspector_widget import RequestInspectorWidget
from .reports_widget import ReportsWidget
from .rules_widget import RulesWidget


class SidebarButton(QPushButton):
    """Modern styled sidebar navigation button."""
    
    def __init__(self, text: str, icon_char: str = "📊", parent=None):
        super().__init__(text, parent)
        self.icon_char = icon_char
        self.setCheckable(True)
        self.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #888;
                padding: 12px 20px;
                text-align: left;
                font-size: 14px;
                border-radius: 8px;
                margin: 4px 8px;
            }
            QPushButton:hover {
                background: rgba(0, 217, 255, 0.1);
                color: #00d9ff;
            }
            QPushButton:checked {
                background: linear-gradient(90deg, rgba(0, 217, 255, 0.2), transparent);
                color: #00d9ff;
                border-left: 3px solid #00d9ff;
            }
        """)
        
    def setText(self, text: str):
        super().setText(f"{self.icon_char}  {text}")


class MainWindow(QMainWindow):
    """Main application window with modern dark theme."""
    
    log_loaded = pyqtSignal(list)
    analysis_complete = pyqtSignal(list)
    
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("🔒 SQL Injection Security Analysis Platform")
        self.setMinimumSize(1400, 900)
        
        # Core data
        self.log_entries = []
        self.current_entry = None
        
        # Setup UI
        self._setup_ui()
        self._setup_styles()
        self._connect_signals()
        
    def _setup_ui(self):
        """Setup the main UI structure."""
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main horizontal layout
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Sidebar
        self.sidebar = self._create_sidebar()
        main_layout.addWidget(self.sidebar)
        
        # Content area
        content_frame = QFrame()
        content_frame.setObjectName("contentFrame")
        content_layout = QVBoxLayout(content_frame)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)
        
        # Header bar
        self.header_bar = self._create_header_bar()
        content_layout.addWidget(self.header_bar)
        
        # Stacked widget for pages
        self.stack = QStackedWidget()
        self.stack.setObjectName("mainStack")
        
        # Add pages
        self.dashboard_page = DashboardWidget(self)
        self.log_analyzer_page = LogAnalyzerWidget(self)
        self.request_inspector_page = RequestInspectorWidget(self)
        self.reports_page = ReportsWidget(self)
        self.rules_page = RulesWidget(self)
        
        self.stack.addWidget(self.dashboard_page)
        self.stack.addWidget(self.log_analyzer_page)
        self.stack.addWidget(self.request_inspector_page)
        self.stack.addWidget(self.reports_page)
        self.stack.addWidget(self.rules_page)
        
        content_layout.addWidget(self.stack)
        main_layout.addWidget(content_frame)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.setStyleSheet("""
            QStatusBar {
                background: #16213e;
                color: #888;
                padding: 5px;
            }
        """)
        self.status_bar.showMessage("Ready - Load logs to begin analysis")
        
    def _create_sidebar(self) -> QWidget:
        """Create the sidebar navigation."""
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(250)
        
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 20, 0, 20)
        layout.setSpacing(5)
        
        # Logo/Title
        logo_label = QLabel("🛡️ SQLi Analyzer")
        logo_label.setStyleSheet("""
            font-size: 20px;
            font-weight: bold;
            color: #00d9ff;
            padding: 20px 15px;
        """)
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(logo_label)
        
        # Navigation buttons
        self.nav_buttons = {}
        
        buttons = [
            ("Dashboard", "dashboard", "📊"),
            ("Log Analyzer", "analyzer", "📋"),
            ("Request Inspector", "inspector", "🔍"),
            ("Vulnerability Reports", "reports", "📄"),
            ("Rules Engine", "rules", "⚙️")
        ]
        
        for text, key, icon in buttons:
            btn = SidebarButton(text, icon)
            btn.clicked.connect(lambda checked, k=key: self._navigate_to(k))
            self.nav_buttons[key] = btn
            layout.addWidget(btn)
        
        layout.addStretch()
        
        # Footer info
        footer = QLabel("v1.0.0\nPassive Analysis Mode")
        footer.setStyleSheet("""
            color: #555;
            font-size: 11px;
            padding: 15px;
            text-align: center;
        """)
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(footer)
        
        return sidebar
    
    def _create_header_bar(self) -> QWidget:
        """Create the top header bar."""
        header = QFrame()
        header.setObjectName("headerBar")
        header.setFixedHeight(60)
        
        layout = QHBoxLayout(header)
        layout.setContentsMargins(20, 10, 20, 10)
        
        # Page title
        self.page_title = QLabel("Dashboard")
        self.page_title.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: #fff;
        """)
        layout.addWidget(self.page_title)
        
        layout.addStretch()
        
        # Action buttons
        self.import_btn = QPushButton("📂 Import Logs")
        self.import_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(90deg, #00d9ff, #0099cc);
                color: #000;
                padding: 8px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: linear-gradient(90deg, #00eeff, #00aadd);
            }
        """)
        self.import_btn.clicked.connect(self.import_logs)
        layout.addWidget(self.import_btn)
        
        self.analyze_btn = QPushButton("🔬 Analyze")
        self.analyze_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(90deg, #9C27B0, #7B1FA2);
                color: #fff;
                padding: 8px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: linear-gradient(90deg, #AB47BC, #8E24AA);
            }
            QPushButton:disabled {
                background: #333;
                color: #666;
            }
        """)
        self.analyze_btn.clicked.connect(self.run_analysis)
        self.analyze_btn.setEnabled(False)
        layout.addWidget(self.analyze_btn)
        
        self.export_btn = QPushButton("📤 Export Report")
        self.export_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(90deg, #4CAF50, #388E3C);
                color: #fff;
                padding: 8px 20px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: linear-gradient(90deg, #66BB6A, #43A047);
            }
            QPushButton:disabled {
                background: #333;
                color: #666;
            }
        """)
        self.export_btn.clicked.connect(self.export_report)
        self.export_btn.setEnabled(False)
        layout.addWidget(self.export_btn)
        
        return header
    
    def _setup_styles(self):
        """Apply global styles."""
        self.setStyleSheet("""
            QMainWindow {
                background: #1a1a2e;
            }
            #sidebar {
                background: #16213e;
                border-right: 1px solid #0f3460;
            }
            #contentFrame {
                background: #1a1a2e;
            }
            #headerBar {
                background: #16213e;
                border-bottom: 1px solid #0f3460;
            }
            #mainStack {
                background: #1a1a2e;
            }
            QScrollArea {
                border: none;
                background: transparent;
            }
            QScrollBar:vertical {
                background: #16213e;
                width: 10px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical {
                background: #0f3460;
                border-radius: 5px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background: #00d9ff;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar:horizontal {
                background: #16213e;
                height: 10px;
                border-radius: 5px;
            }
            QScrollBar::handle:horizontal {
                background: #0f3460;
                border-radius: 5px;
                min-width: 20px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #00d9ff;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
        """)
    
    def _connect_signals(self):
        """Connect internal signals."""
        self.log_loaded.connect(self._on_log_loaded)
        self.analysis_complete.connect(self._on_analysis_complete)
    
    def _navigate_to(self, page_key: str):
        """Navigate to a specific page."""
        page_indices = {
            "dashboard": 0,
            "analyzer": 1,
            "inspector": 2,
            "reports": 3,
            "rules": 4
        }
        
        if page_key in page_indices:
            self.stack.setCurrentIndex(page_indices[page_key])
            
            # Update button states
            for key, btn in self.nav_buttons.items():
                btn.setChecked(key == page_key)
            
            # Update title
            titles = {
                "dashboard": "Dashboard",
                "analyzer": "Log Analyzer",
                "inspector": "Request Inspector",
                "reports": "Vulnerability Reports",
                "rules": "Rules Engine"
            }
            self.page_title.setText(titles.get(page_key, ""))
    
    def import_logs(self):
        """Import log files."""
        file_dialog = QFileDialog()
        file_dialog.setNameFilters([
            "Log Files (*.json *.csv *.txt *.log)",
            "JSON Files (*.json)",
            "CSV Files (*.csv)",
            "Text Files (*.txt *.log)",
            "All Files (*)"
        ])
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFiles)
        
        if file_dialog.exec():
            file_paths = file_dialog.selectedFiles()
            self.status_bar.showMessage(f"Loading {len(file_paths)} file(s)...")
            
            try:
                from ..parsers import LogParser
                parser = LogParser()
                
                all_entries = []
                for path in file_paths:
                    entries = parser.parse_file(path)
                    all_entries.extend(entries)
                
                self.log_entries = all_entries
                self.log_loaded.emit(all_entries)
                
                self.status_bar.showMessage(f"Loaded {len(all_entries)} log entries")
                self.analyze_btn.setEnabled(len(all_entries) > 0)
                
            except Exception as e:
                QMessageBox.critical(self, "Import Error", f"Failed to import logs:\n{str(e)}")
                self.status_bar.showMessage("Import failed")
    
    def run_analysis(self):
        """Run security analysis on loaded logs."""
        if not self.log_entries:
            return
        
        self.status_bar.showMessage("Running security analysis...")
        self.analyze_btn.setEnabled(False)
        
        # Run analysis in background thread
        class AnalysisThread(QThread):
            def __init__(self, entries):
                super().__init__()
                self.entries = entries
                self.result = []
            
            def run(self):
                from ..analyzers import SQLInjectionAnalyzer
                analyzer = SQLInjectionAnalyzer()
                self.result = analyzer.analyze_batch(self.entries)
        
        self.analysis_thread = AnalysisThread(self.log_entries)
        self.analysis_thread.finished.connect(self._on_analysis_finished)
        self.analysis_thread.start()
    
    def _on_analysis_finished(self):
        """Handle analysis completion."""
        if hasattr(self.analysis_thread, 'result'):
            self.log_entries = self.analysis_thread.result
            self.analysis_complete.emit(self.log_entries)
            
            vulnerable = sum(1 for e in self.log_entries if e.risk_score > 0)
            self.status_bar.showMessage(f"Analysis complete: {vulnerable} vulnerabilities found")
            self.export_btn.setEnabled(vulnerable > 0)
        
        self.analyze_btn.setEnabled(True)
    
    def export_report(self):
        """Export security report."""
        file_dialog = QFileDialog()
        file_dialog.setNameFilters(["HTML Report (*.html)", "PDF Report (*.pdf)", "Text Report (*.txt)"])
        file_dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        file_dialog.setDefaultSuffix("html")
        
        if file_dialog.exec():
            output_path = file_dialog.selectedFiles()[0]
            
            try:
                from ..reporters import ReportGenerator
                from ..core.models import DashboardStats
                
                # Calculate stats
                stats = DashboardStats(
                    total_logs=len(self.log_entries),
                    total_vulnerabilities=sum(1 for e in self.log_entries if e.risk_score > 0),
                    critical_count=sum(1 for e in self.log_entries if e.severity.value == "Critical"),
                    high_count=sum(1 for e in self.log_entries if e.severity.value == "High"),
                    medium_count=sum(1 for e in self.log_entries if e.severity.value == "Medium"),
                    low_count=sum(1 for e in self.log_entries if e.severity.value == "Low"),
                    unique_ips=len(set(e.source_ip for e in self.log_entries)),
                    unique_sessions=len(set(e.session_id for e in self.log_entries))
                )
                
                # Determine format
                fmt = "html"
                if output_path.endswith(".pdf"):
                    fmt = "pdf"
                elif output_path.endswith(".txt"):
                    fmt = "txt"
                
                generator = ReportGenerator()
                generator.generate_report(self.log_entries, stats, fmt, output_path)
                
                QMessageBox.information(self, "Export Complete", f"Report saved to:\n{output_path}")
                self.status_bar.showMessage(f"Report exported: {output_path}")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export report:\n{str(e)}")
    
    def _on_log_loaded(self, entries):
        """Handle log loaded signal."""
        # Refresh all pages
        self.dashboard_page.refresh_data()
        self.log_analyzer_page.refresh_data()
        self.request_inspector_page.refresh_data()
        self.reports_page.refresh_data()
    
    def _on_analysis_complete(self, entries):
        """Handle analysis complete signal."""
        # Refresh all pages with analyzed data
        self.dashboard_page.refresh_data()
        self.log_analyzer_page.refresh_data()
        self.request_inspector_page.refresh_data()
        self.reports_page.refresh_data()
    
    def select_entry(self, entry):
        """Select a log entry for inspection."""
        self.current_entry = entry
        self.request_inspector_page.display_entry(entry)
        self._navigate_to("inspector")


def main():
    """Main entry point."""
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Set dark palette
    from PyQt6.QtGui import QPalette, QColor
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#1a1a2e"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#eee"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#16213e"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#1a1a2e"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#eee"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#16213e"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#eee"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#00d9ff"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#000"))
    app.setPalette(palette)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
