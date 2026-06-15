"""
SQL Injection Security Analysis and Audit Platform
Dashboard Widget with Statistics and Charts
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, 
    QScrollArea, QGridLayout, QPushButton
)
from PyQt6.QtCore import Qt
import pyqtgraph as pg


class StatCard(QFrame):
    """Modern statistics card widget."""
    
    def __init__(self, title: str, value: str = "0", color: str = "#00d9ff"):
        super().__init__()
        self.setObjectName("statCard")
        self.setStyleSheet(f"""
            #statCard {{
                background: #16213e;
                border-radius: 12px;
                padding: 20px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(f"""
            font-size: 36px;
            font-weight: bold;
            color: {color};
        """)
        self.value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("""
            font-size: 14px;
            color: #888;
            margin-top: 5px;
        """)
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(self.value_label)
        layout.addWidget(self.title_label)
    
    def set_value(self, value: str):
        self.value_label.setText(value)


class DashboardWidget(QWidget):
    """Main dashboard with statistics and charts."""
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Scroll area for content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        content_widget = QWidget()
        self.content_layout = QVBoxLayout(content_widget)
        self.content_layout.setSpacing(20)
        
        # Stats grid
        self.stats_grid = self._create_stats_grid()
        self.content_layout.addWidget(self.stats_grid)
        
        # Charts row
        charts_layout = QHBoxLayout()
        charts_layout.setSpacing(20)
        
        # Risk distribution chart
        self.risk_chart = self._create_risk_chart()
        charts_layout.addWidget(self.risk_chart, 1)
        
        # Detection types chart
        self.detection_chart = self._create_detection_chart()
        charts_layout.addWidget(self.detection_chart, 1)
        
        self.content_layout.addLayout(charts_layout)
        
        # Recent activity table placeholder
        self.recent_activity = self._create_recent_activity()
        self.content_layout.addWidget(self.recent_activity)
        
        self.content_layout.addStretch()
        
        scroll.setWidget(content_widget)
        layout.addWidget(scroll)
        
        # Initialize empty data
        self.refresh_data()
    
    def _create_stats_grid(self) -> QWidget:
        """Create the statistics cards grid."""
        grid_widget = QWidget()
        grid = QGridLayout(grid_widget)
        grid.setSpacing(15)
        
        self.stat_cards = {
            'total_logs': StatCard("Total Logs", "0", "#00d9ff"),
            'vulnerabilities': StatCard("Vulnerabilities", "0", "#F44336"),
            'critical': StatCard("Critical", "0", "#9C27B0"),
            'high': StatCard("High", "0", "#FF5722"),
            'medium': StatCard("Medium", "0", "#FF9800"),
            'low': StatCard("Low", "0", "#4CAF50"),
            'unique_ips': StatCard("Unique IPs", "0", "#2196F3"),
            'sessions': StatCard("Sessions", "0", "#00BCD4")
        }
        
        positions = [
            (0, 0, 'total_logs'), (0, 1, 'vulnerabilities'),
            (0, 2, 'critical'), (0, 3, 'high'),
            (1, 0, 'medium'), (1, 1, 'low'),
            (1, 2, 'unique_ips'), (1, 3, 'sessions')
        ]
        
        for row, col, key in positions:
            grid.addWidget(self.stat_cards[key], row, col)
        
        return grid_widget
    
    def _create_risk_chart(self) -> QFrame:
        """Create risk distribution bar chart."""
        frame = QFrame()
        frame.setObjectName("chartFrame")
        frame.setStyleSheet("""
            #chartFrame {
                background: #16213e;
                border-radius: 12px;
                padding: 15px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        title = QLabel("📊 Risk Distribution")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #fff;")
        layout.addWidget(title)
        
        # Create pyqtgraph bar chart
        self.risk_plot = pg.PlotWidget()
        self.risk_plot.setBackground('#16213e')
        self.risk_plot.showGrid(x=True, y=True, alpha=0.3)
        self.risk_plot.setLabel('left', 'Count')
        self.risk_plot.setLabel('bottom', 'Severity')
        self.risk_plot.getAxis('left').setTickFont(pg.QtGui.QFont("Arial", 10))
        self.risk_plot.getAxis('bottom').setTickFont(pg.QtGui.QFont("Arial", 10))
        
        # Style axes
        self.risk_plot.getAxis('left').setPen(pg.mkPen(color='#888'))
        self.risk_plot.getAxis('bottom').setPen(pg.mkPen(color='#888'))
        
        layout.addWidget(self.risk_plot)
        
        return frame
    
    def _create_detection_chart(self) -> QFrame:
        """Create detection types pie chart representation."""
        frame = QFrame()
        frame.setObjectName("chartFrame")
        frame.setStyleSheet("""
            #chartFrame {
                background: #16213e;
                border-radius: 12px;
                padding: 15px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        title = QLabel("🔍 Detection Types")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #fff;")
        layout.addWidget(title)
        
        # Use horizontal bar chart instead of pie
        self.detection_plot = pg.PlotWidget()
        self.detection_plot.setBackground('#16213e')
        self.detection_plot.showGrid(x=True, y=True, alpha=0.3)
        self.detection_plot.setLabel('bottom', 'Count')
        
        # Style axes
        self.detection_plot.getAxis('left').setPen(pg.mkPen(color='#888'))
        self.detection_plot.getAxis('bottom').setPen(pg.mkPen(color='#888'))
        
        layout.addWidget(self.detection_plot)
        
        return frame
    
    def _create_recent_activity(self) -> QFrame:
        """Create recent activity section."""
        frame = QFrame()
        frame.setObjectName("activityFrame")
        frame.setStyleSheet("""
            #activityFrame {
                background: #16213e;
                border-radius: 12px;
                padding: 15px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        header_layout = QHBoxLayout()
        title = QLabel("⚡ Recent Suspicious Activity")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #fff;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        layout.addLayout(header_layout)
        
        # Activity list
        self.activity_list = QLabel("No activity yet - import logs to begin")
        self.activity_list.setStyleSheet("color: #666; padding: 20px;")
        self.activity_list.setWordWrap(True)
        layout.addWidget(self.activity_list)
        
        return frame
    
    def refresh_data(self):
        """Refresh dashboard data from main window."""
        entries = self.main_window.log_entries
        
        if not entries:
            self._clear_dashboard()
            return
        
        # Calculate stats
        total = len(entries)
        vulnerable = sum(1 for e in entries if e.risk_score > 0)
        critical = sum(1 for e in entries if e.severity.value == "Critical")
        high = sum(1 for e in entries if e.severity.value == "High")
        medium = sum(1 for e in entries if e.severity.value == "Medium")
        low = sum(1 for e in entries if e.severity.value == "Low")
        unique_ips = len(set(e.source_ip for e in entries))
        sessions = len(set(e.session_id for e in entries))
        
        # Update stat cards
        self.stat_cards['total_logs'].set_value(str(total))
        self.stat_cards['vulnerabilities'].set_value(str(vulnerable))
        self.stat_cards['critical'].set_value(str(critical))
        self.stat_cards['high'].set_value(str(high))
        self.stat_cards['medium'].set_value(str(medium))
        self.stat_cards['low'].set_value(str(low))
        self.stat_cards['unique_ips'].set_value(str(unique_ips))
        self.stat_cards['sessions'].set_value(str(sessions))
        
        # Update risk distribution chart
        self._update_risk_chart(critical, high, medium, low)
        
        # Update detection types chart
        self._update_detection_chart(entries)
        
        # Update recent activity
        self._update_recent_activity(entries)
    
    def _clear_dashboard(self):
        """Clear all dashboard data."""
        for card in self.stat_cards.values():
            card.set_value("0")
        
        self.risk_plot.clear()
        self.detection_plot.clear()
        self.activity_list.setText("No activity yet - import logs to begin")
    
    def _update_risk_chart(self, critical, high, medium, low):
        """Update the risk distribution bar chart."""
        self.risk_plot.clear()
        
        categories = ['Critical', 'High', 'Medium', 'Low']
        values = [critical, high, medium, low]
        colors = ['#9C27B0', '#F44336', '#FF9800', '#4CAF50']
        
        bars = pg.BarGraphItem(
            x=list(range(len(categories))),
            height=values,
            width=0.6,
            brush=colors
        )
        self.risk_plot.addItem(bars)
        
        # Set x-axis labels
        self.risk_plot.getAxis('bottom').setTicks([[(i, cat) for i, cat in enumerate(categories)]])
        self.risk_plot.setXRange(-0.5, len(categories) - 0.5)
    
    def _update_detection_chart(self, entries):
        """Update the detection types chart."""
        self.detection_plot.clear()
        
        # Count detection types
        detection_counts = {}
        for entry in entries:
            for detection in entry.detections:
                dtype = detection.detection_type.value
                detection_counts[dtype] = detection_counts.get(dtype, 0) + 1
        
        if not detection_counts:
            self.detection_plot.getAxis('left').setTicks([[[]]])
            return
        
        categories = list(detection_counts.keys())[:8]  # Top 8
        values = [detection_counts.get(cat, 0) for cat in categories]
        
        bars = pg.BarGraphItem(
            y=list(range(len(categories))),
            width=values,
            height=0.6,
            brush='#00d9ff'
        )
        self.detection_plot.addItem(bars)
        
        # Set y-axis labels
        self.detection_plot.getAxis('left').setTicks([[(i, cat) for i, cat in enumerate(categories)]])
        self.detection_plot.setYRange(-0.5, len(categories) - 0.5)
    
    def _update_recent_activity(self, entries):
        """Update recent suspicious activity list."""
        suspicious = [e for e in entries if e.risk_score > 0]
        suspicious.sort(key=lambda x: x.risk_score, reverse=True)
        
        if not suspicious:
            self.activity_list.setText("✅ No suspicious activity detected!")
            return
        
        # Show top 5
        lines = []
        for entry in suspicious[:5]:
            time_str = entry.timestamp.strftime("%H:%M:%S")
            lines.append(
                f"<span style='color:#00d9ff'>{time_str}</span> | "
                f"<span style='color:{entry.severity.get_color()}'>{entry.severity.value}</span> | "
                f"Score: {entry.risk_score} | "
                f"{entry.source_ip}"
            )
        
        html = "<br/>".join(lines)
        self.activity_list.setText(f"<p style='padding:10px'>{html}</p>")
