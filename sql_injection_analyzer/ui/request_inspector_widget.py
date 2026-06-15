"""
SQL Injection Security Analysis and Audit Platform
Request Inspector Widget with Detailed View
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel,
    QScrollArea, QSplitter, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView
)
from PyQt6.QtCore import Qt


class RequestInspectorWidget(QWidget):
    """Detailed request/response inspector widget."""
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.current_entry = None
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Splitter for left/right panels
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Request details
        left_panel = self._create_left_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Detections and analysis
        right_panel = self._create_right_panel()
        splitter.addWidget(right_panel)
        
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        
        layout.addWidget(splitter)
        
        # Show placeholder
        self._show_placeholder()
    
    def _create_left_panel(self) -> QWidget:
        """Create the left panel with request details."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(15)
        
        # Title
        self.request_title = QLabel("Select a log entry to inspect")
        self.request_title.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: #00d9ff;
        """)
        layout.addWidget(self.request_title)
        
        # Basic info card
        self.basic_info = self._create_info_card("Request Information")
        layout.addWidget(self.basic_info)
        
        # Headers card
        self.headers_card = self._create_text_card("HTTP Headers")
        layout.addWidget(self.headers_card)
        
        # Query params card
        self.params_card = self._create_text_card("Query Parameters")
        layout.addWidget(self.params_card)
        
        # Body card
        self.body_card = self._create_text_card("Request Body")
        layout.addWidget(self.body_card)
        
        # Response card
        self.response_card = self._create_text_card("Response")
        layout.addWidget(self.response_card)
        
        layout.addStretch()
        scroll.setWidget(content)
        
        return scroll
    
    def _create_right_panel(self) -> QWidget:
        """Create the right panel with detection results."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(15)
        
        # Risk score display
        self.risk_score_display = self._create_risk_gauge()
        layout.addWidget(self.risk_score_display)
        
        # Detections list
        detections_title = QLabel("🔍 Detection Results")
        detections_title.setStyleSheet("""
            font-size: 16px;
            font-weight: bold;
            color: #fff;
            margin-top: 10px;
        """)
        layout.addWidget(detections_title)
        
        self.detections_list = QVBoxLayout()
        self.detections_list.setSpacing(10)
        
        detections_container = QWidget()
        detections_container.setLayout(self.detections_list)
        
        layout.addWidget(detections_container)
        layout.addStretch()
        
        scroll.setWidget(content)
        
        return scroll
    
    def _create_info_card(self, title: str) -> QFrame:
        """Create an information card."""
        frame = QFrame()
        frame.setObjectName("infoCard")
        frame.setStyleSheet("""
            #infoCard {
                background: #16213e;
                border-radius: 8px;
                padding: 15px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        label = QLabel(title)
        label.setStyleSheet("""
            font-size: 14px;
            font-weight: bold;
            color: #00d9ff;
            margin-bottom: 10px;
        """)
        layout.addWidget(label)
        
        self.info_table = QTableWidget(0, 2)
        self.info_table.setStyleSheet("""
            QTableWidget {
                background: transparent;
                border: none;
                color: #eee;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QHeaderView::section {
                background: #0f3460;
                color: #00d9ff;
                padding: 8px;
                border: none;
            }
        """)
        self.info_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.info_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.info_table.verticalHeader().setVisible(False)
        self.info_table.setShowGrid(False)
        
        layout.addWidget(self.info_table)
        
        return frame
    
    def _create_text_card(self, title: str) -> QFrame:
        """Create a text display card."""
        frame = QFrame()
        frame.setObjectName("textCard")
        frame.setStyleSheet("""
            #textCard {
                background: #16213e;
                border-radius: 8px;
                padding: 15px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        label = QLabel(title)
        label.setStyleSheet("""
            font-size: 14px;
            font-weight: bold;
            color: #00d9ff;
            margin-bottom: 10px;
        """)
        layout.addWidget(label)
        
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setStyleSheet("""
            QTextEdit {
                background: #0f3460;
                border: none;
                border-radius: 4px;
                color: #00ff88;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px;
                padding: 10px;
            }
        """)
        text_edit.setMaximumHeight(150)
        
        layout.addWidget(text_edit)
        
        return frame
    
    def _create_risk_gauge(self) -> QFrame:
        """Create risk score gauge display."""
        frame = QFrame()
        frame.setObjectName("riskGauge")
        frame.setStyleSheet("""
            #riskGauge {
                background: linear-gradient(135deg, #16213e, #0f3460);
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.gauge_label = QLabel("0")
        self.gauge_label.setStyleSheet("""
            font-size: 72px;
            font-weight: bold;
            color: #4CAF50;
        """)
        self.gauge_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.gauge_label)
        
        self.gauge_desc = QLabel("No Risk Detected")
        self.gauge_desc.setStyleSheet("""
            font-size: 16px;
            color: #888;
        """)
        self.gauge_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.gauge_desc)
        
        return frame
    
    def _create_detection_item(self, detection) -> QFrame:
        """Create a detection result item."""
        frame = QFrame()
        frame.setObjectName("detectionItem")
        
        severity_color = "#4CAF50"
        if detection.confidence >= 0.8:
            severity_color = "#F44336"
        elif detection.confidence >= 0.5:
            severity_color = "#FF9800"
        
        frame.setStyleSheet(f"""
            #detectionItem {{
                background: #0f3460;
                border-left: 4px solid {severity_color};
                border-radius: 6px;
                padding: 12px;
            }}
        """)
        
        layout = QVBoxLayout(frame)
        
        # Title row
        title_layout = QHBoxLayout()
        
        type_label = QLabel(f"🚨 {detection.detection_type.value}")
        type_label.setStyleSheet("""
            font-weight: bold;
            color: #fff;
        """)
        title_layout.addWidget(type_label)
        
        confidence_label = QLabel(f"Confidence: {int(detection.confidence * 100)}%")
        confidence_label.setStyleSheet("color: #888;")
        title_layout.addStretch()
        title_layout.addWidget(confidence_label)
        
        layout.addLayout(title_layout)
        
        # Description
        desc_label = QLabel(detection.description)
        desc_label.setStyleSheet("color: #aaa; margin-top: 5px;")
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)
        
        # Location
        loc_label = QLabel(f"📍 Location: {detection.location}")
        loc_label.setStyleSheet("color: #00d9ff; font-size: 12px; margin-top: 5px;")
        layout.addWidget(loc_label)
        
        # Payload sample (truncated)
        if detection.payload_sample:
            payload_label = QLabel(f"Sample: {detection.payload_sample[:60]}...")
            payload_label.setStyleSheet("""
                color: #00ff88;
                font-family: 'Consolas', monospace;
                font-size: 11px;
                background: #1a1a2e;
                padding: 5px;
                border-radius: 4px;
                margin-top: 5px;
            """)
            payload_label.setWordWrap(True)
            layout.addWidget(payload_label)
        
        return frame
    
    def _show_placeholder(self):
        """Show placeholder message."""
        self.request_title.setText("Select a log entry to inspect")
        self.gauge_label.setText("0")
        self.gauge_label.setStyleSheet("font-size: 72px; font-weight: bold; color: #4CAF50;")
        self.gauge_desc.setText("No entry selected")
        
        # Clear detections
        self._clear_detections()
    
    def _clear_detections(self):
        """Clear all detection items."""
        while self.detections_list.count():
            item = self.detections_list.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
    
    def display_entry(self, entry):
        """Display detailed information for a log entry."""
        self.current_entry = entry
        
        # Update title
        self.request_title.setText(f"Request #{entry.id} - {entry.request.method} {entry.request.path[:50]}")
        
        # Update basic info
        self._update_info_table(entry)
        
        # Update headers
        headers_text = "\n".join(f"{k}: {v}" for k, v in entry.request.headers.items())
        self._update_text_card(self.headers_card, headers_text or "No headers")
        
        # Update query params
        params_text = "\n".join(f"{k}={v}" for k, v in entry.request.query_params.items())
        self._update_text_card(self.params_card, params_text or "No query parameters")
        
        # Update body
        self._update_text_card(self.body_card, entry.request.body or "No body")
        
        # Update response
        if entry.response:
            response_text = f"Status: {entry.response.status_code}\n\n"
            response_text += "\n".join(f"{k}: {v}" for k, v in entry.response.headers.items())
            response_text += f"\n\n{entry.response.body[:500]}..." if len(entry.response.body) > 500 else f"\n\n{entry.response.body}"
            self._update_text_card(self.response_card, response_text)
        else:
            self._update_text_card(self.response_card, "No response data available")
        
        # Update risk gauge
        self._update_risk_gauge(entry.risk_score, entry.severity.value)
        
        # Update detections
        self._update_detections(entry.detections)
    
    def _update_info_table(self, entry):
        """Update the basic info table."""
        self.info_table.setRowCount(0)
        
        info_items = [
            ("ID", str(entry.id)),
            ("Timestamp", entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")),
            ("Source IP", entry.source_ip),
            ("Method", entry.request.method),
            ("URL", entry.request.url),
            ("User Agent", entry.user_agent[:60] + "..." if len(entry.user_agent) > 60 else entry.user_agent),
            ("Session ID", entry.session_id[:40] + "..." if len(entry.session_id) > 40 else entry.session_id),
            ("Risk Score", str(entry.risk_score)),
            ("Severity", entry.severity.value)
        ]
        
        for key, value in info_items:
            row = self.info_table.rowCount()
            self.info_table.insertRow(row)
            self.info_table.setItem(row, 0, QTableWidgetItem(key))
            self.info_table.setItem(row, 1, QTableWidgetItem(value))
    
    def _update_text_card(self, card: QFrame, text: str):
        """Update a text card's content."""
        text_edit = card.findChild(QTextEdit)
        if text_edit:
            text_edit.setText(text)
    
    def _update_risk_gauge(self, score: int, severity: str):
        """Update the risk gauge display."""
        self.gauge_label.setText(str(score))
        
        if score >= 90:
            color = "#9C27B0"
            desc = "CRITICAL RISK"
        elif score >= 70:
            color = "#F44336"
            desc = "HIGH RISK"
        elif score >= 40:
            color = "#FF9800"
            desc = "MEDIUM RISK"
        elif score > 0:
            color = "#4CAF50"
            desc = "LOW RISK"
        else:
            color = "#4CAF50"
            desc = "No Risk Detected"
        
        self.gauge_label.setStyleSheet(f"font-size: 72px; font-weight: bold; color: {color};")
        self.gauge_desc.setText(desc)
        self.gauge_desc.setStyleSheet(f"font-size: 16px; color: {color};")
    
    def _update_detections(self, detections):
        """Update the detections list."""
        self._clear_detections()
        
        if not detections:
            no_detect = QLabel("✅ No suspicious patterns detected")
            no_detect.setStyleSheet("color: #4CAF50; padding: 20px; font-size: 14px;")
            self.detections_list.addWidget(no_detect)
            return
        
        for detection in detections:
            item = self._create_detection_item(detection)
            self.detections_list.addWidget(item)
