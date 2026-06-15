"""
SQL Injection Security Analysis and Audit Platform
Log Analyzer Widget with Table View
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel,
    QTableView, QLineEdit, QPushButton, QHeaderView, QMenu
)
from PyQt6.QtCore import Qt, QSortFilterProxyModel
from PyQt6.QtGui import QStandardItemModel, QStandardItem, QColor, QBrush


class LogAnalyzerWidget(QWidget):
    """Log analyzer page with searchable table view."""
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Filter bar
        filter_bar = self._create_filter_bar()
        layout.addWidget(filter_bar)
        
        # Table view
        self.table_frame = self._create_table_view()
        layout.addWidget(self.table_frame, 1)
        
        # Create model
        self.model = QStandardItemModel(0, 8)
        self.model.setHorizontalHeaderLabels([
            "ID", "Timestamp", "Source IP", "Method", "URL", 
            "Risk Score", "Severity", "Detections"
        ])
        
        # Proxy model for filtering
        self.proxy_model = QSortFilterProxyModel()
        self.proxy_model.setSourceModel(self.model)
        self.proxy_model.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        
        self.table_view.setModel(self.proxy_model)
        
        # Configure table
        self._configure_table()
    
    def _create_filter_bar(self) -> QWidget:
        """Create the filter/search bar."""
        frame = QFrame()
        frame.setObjectName("filterBar")
        frame.setStyleSheet("""
            #filterBar {
                background: #16213e;
                border-radius: 8px;
                padding: 15px;
            }
        """)
        
        layout = QHBoxLayout(frame)
        
        # Search box
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search logs by IP, URL, or detection...")
        self.search_input.setStyleSheet("""
            QLineEdit {
                background: #0f3460;
                border: 1px solid #1a1a2e;
                border-radius: 6px;
                padding: 10px 15px;
                color: #fff;
                font-size: 14px;
            }
            QLineEdit:focus {
                border: 1px solid #00d9ff;
            }
        """)
        self.search_input.textChanged.connect(self._filter_logs)
        layout.addWidget(self.search_input, 3)
        
        # Severity filter
        self.severity_filter = QPushButton("All Severities")
        self.severity_filter.setStyleSheet("""
            QPushButton {
                background: #0f3460;
                color: #fff;
                border: 1px solid #1a1a2e;
                border-radius: 6px;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background: #16213e;
            }
        """)
        layout.addWidget(self.severity_filter)
        
        # Clear filter
        clear_btn = QPushButton("Clear")
        clear_btn.setStyleSheet("""
            QPushButton {
                background: #F44336;
                color: #fff;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background: #F75C4B;
            }
        """)
        clear_btn.clicked.connect(self._clear_filters)
        layout.addWidget(clear_btn)
        
        return frame
    
    def _create_table_view(self) -> QFrame:
        """Create the log table view."""
        frame = QFrame()
        frame.setObjectName("tableFrame")
        frame.setStyleSheet("""
            #tableFrame {
                background: #16213e;
                border-radius: 8px;
            }
            QTableView {
                background: #16213e;
                alternate-background-color: #1a1a2e;
                color: #eee;
                gridline-color: #0f3460;
                border: none;
            }
            QHeaderView::section {
                background: #0f3460;
                color: #00d9ff;
                padding: 12px;
                border: none;
                font-weight: bold;
            }
            QTableView::item {
                padding: 8px;
            }
            QTableView::item:selected {
                background: rgba(0, 217, 255, 0.3);
            }
        """)
        
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.table_view = QTableView()
        self.table_view.setAlternatingRowColors(True)
        self.table_view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table_view.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.table_view.doubleClicked.connect(self._on_row_double_clicked)
        
        layout.addWidget(self.table_view)
        
        return frame
    
    def _configure_table(self):
        """Configure table view settings."""
        header = self.table_view.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        
        self.table_view.verticalHeader().setVisible(False)
        self.table_view.setSortingEnabled(True)
    
    def refresh_data(self):
        """Refresh table data from main window."""
        self.model.removeRow(0, self.model.rowCount())
        
        entries = self.main_window.log_entries
        
        for entry in entries:
            # Format timestamp
            ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            
            # Severity color
            severity_color = entry.severity.get_color()
            
            # Detection count
            detection_count = len(entry.detections)
            detection_text = f"{detection_count} detected" if detection_count > 0 else "Clean"
            
            # Create row items
            items = [
                QStandardItem(str(entry.id)),
                QStandardItem(ts),
                QStandardItem(entry.source_ip),
                QStandardItem(entry.request.method),
                QStandardItem(entry.request.url[:80] + "..." if len(entry.request.url) > 80 else entry.request.url),
                QStandardItem(str(entry.risk_score)),
                QStandardItem(entry.severity.value),
                QStandardItem(detection_text)
            ]
            
            # Apply colors to severity cell
            items[6].setBackground(QBrush(QColor(severity_color)))
            if entry.risk_score >= 50:
                items[6].setForeground(QBrush(QColor("#fff")))
            
            # Apply color to risk score
            if entry.risk_score >= 70:
                items[5].setForeground(QBrush(QColor("#F44336")))
            elif entry.risk_score >= 40:
                items[5].setForeground(QBrush(QColor("#FF9800")))
            elif entry.risk_score > 0:
                items[5].setForeground(QBrush(QColor("#4CAF50")))
            
            # Store entry reference
            for item in items:
                item.setData(entry, Qt.ItemDataRole.UserRole)
            
            self.model.appendRow(items)
    
    def _filter_logs(self):
        """Filter logs based on search text."""
        text = self.search_input.text()
        self.proxy_model.setFilterFixedString(text)
        self.proxy_model.setFilterKeyColumn(-1)  # Search all columns
    
    def _clear_filters(self):
        """Clear all filters."""
        self.search_input.clear()
        self.proxy_model.setFilterFixedString("")
    
    def _on_row_double_clicked(self, index):
        """Handle double-click on table row."""
        row = index.row()
        if row >= 0:
            item = self.model.item(row, 0)
            if item:
                entry = item.data(Qt.ItemDataRole.UserRole)
                if entry:
                    self.main_window.select_entry(entry)
