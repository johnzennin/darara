"""
SQL Injection Security Analysis and Audit Platform
Rules Engine Widget
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel,
    QPushButton, QScrollArea, QLineEdit, QTextEdit, 
    QComboBox, QCheckBox, QMessageBox, QTableWidget,
    QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt

from ..core.models import AnalysisRule, DetectionType


class RulesWidget(QWidget):
    """Rules engine management widget."""
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.custom_rules = []
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Header
        header = QLabel("⚙️ Rules Engine")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #00d9ff;")
        layout.addWidget(header)
        
        # Info label
        info_label = QLabel("Manage custom detection rules. Rules are applied during analysis.")
        info_label.setStyleSheet("color: #888; margin-bottom: 10px;")
        layout.addWidget(info_label)
        
        # Create rule form
        form_frame = self._create_rule_form()
        layout.addWidget(form_frame)
        
        # Rules table
        table_title = QLabel("Active Rules")
        table_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #fff; margin-top: 10px;")
        layout.addWidget(table_title)
        
        self.rules_table = self._create_rules_table()
        layout.addWidget(self.rules_table, 1)
        
        # Load default rules into table
        self._refresh_rules_table()
    
    def _create_rule_form(self) -> QFrame:
        """Create the rule creation form."""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: #16213e;
                border-radius: 8px;
                padding: 15px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        layout.setSpacing(10)
        
        # Title row
        title_row = QLabel("➕ Add Custom Rule")
        title_row.setStyleSheet("font-size: 14px; font-weight: bold; color: #00d9ff;")
        layout.addWidget(title_row)
        
        # Rule name
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Name:"))
        self.rule_name = QLineEdit()
        self.rule_name.setPlaceholderText("My Custom Rule")
        self.rule_name.setStyleSheet(self._input_style())
        name_layout.addWidget(self.rule_name)
        layout.addLayout(name_layout)
        
        # Pattern
        pattern_layout = QHBoxLayout()
        pattern_layout.addWidget(QLabel("Regex Pattern:"))
        self.rule_pattern = QLineEdit()
        self.rule_pattern.setPlaceholderText(r"(?i)\bunion\s+select\b")
        self.rule_pattern.setStyleSheet(self._input_style())
        pattern_layout.addWidget(self.rule_pattern)
        layout.addLayout(pattern_layout)
        
        # Description
        desc_layout = QHBoxLayout()
        desc_layout.addWidget(QLabel("Description:"))
        self.rule_description = QLineEdit()
        self.rule_description.setPlaceholderText("Detects UNION SELECT patterns")
        self.rule_description.setStyleSheet(self._input_style())
        desc_layout.addWidget(self.rule_description)
        layout.addLayout(desc_layout)
        
        # Detection type
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Detection Type:"))
        self.rule_type = QComboBox()
        self.rule_type.addItems([dt.value for dt in DetectionType])
        self.rule_type.setStyleSheet(self._input_style())
        type_layout.addWidget(self.rule_type)
        layout.addLayout(type_layout)
        
        # Severity weight
        weight_layout = QHBoxLayout()
        weight_layout.addWidget(QLabel("Severity Weight (0.1-1.0):"))
        self.rule_weight = QLineEdit("0.7")
        self.rule_weight.setStyleSheet(self._input_style())
        weight_layout.addWidget(self.rule_weight)
        layout.addLayout(weight_layout)
        
        # Add button
        add_btn = QPushButton("➕ Add Rule")
        add_btn.setStyleSheet("""
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
        add_btn.clicked.connect(self._add_custom_rule)
        layout.addWidget(add_btn)
        
        return frame
    
    def _create_rules_table(self) -> QTableWidget:
        """Create the rules table."""
        table = QTableWidget(0, 6)
        table.setHorizontalHeaderLabels(["ID", "Name", "Type", "Pattern", "Weight", "Actions"])
        table.setStyleSheet("""
            QTableWidget {
                background: #16213e;
                color: #eee;
                gridline-color: #0f3460;
                border-radius: 8px;
            }
            QHeaderView::section {
                background: #0f3460;
                color: #00d9ff;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 8px;
            }
        """)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        
        table.verticalHeader().setVisible(False)
        
        return table
    
    def _input_style(self) -> str:
        """Get standard input style."""
        return """
            QLineEdit, QComboBox {
                background: #0f3460;
                border: 1px solid #1a1a2e;
                border-radius: 4px;
                padding: 8px 12px;
                color: #fff;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 1px solid #00d9ff;
            }
        """
    
    def _refresh_rules_table(self):
        """Refresh the rules table."""
        self.rules_table.setRowCount(0)
        
        # Get analyzer rules
        from ..analyzers import SQLInjectionAnalyzer
        analyzer = SQLInjectionAnalyzer()
        
        # Add default rules
        for rule in analyzer.rules:
            self._add_rule_to_table(rule, is_default=True)
        
        # Add custom rules
        for rule in self.custom_rules:
            self._add_rule_to_table(rule, is_default=False)
    
    def _add_rule_to_table(self, rule: AnalysisRule, is_default: bool):
        """Add a rule to the table."""
        row = self.rules_table.rowCount()
        self.rules_table.insertRow(row)
        
        self.rules_table.setItem(row, 0, QTableWidgetItem(rule.id))
        self.rules_table.setItem(row, 1, QTableWidgetItem(rule.name))
        self.rules_table.setItem(row, 2, QTableWidgetItem(rule.detection_type.value))
        self.rules_table.setItem(row, 3, QTableWidgetItem(rule.pattern[:40] + "..." if len(rule.pattern) > 40 else rule.pattern))
        self.rules_table.setItem(row, 4, QTableWidgetItem(str(rule.severity_weight)))
        
        # Actions
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(5, 0, 5, 0)
        
        if not is_default:
            delete_btn = QPushButton("🗑️")
            delete_btn.setStyleSheet("""
                QPushButton {
                    background: #F44336;
                    color: #fff;
                    border-radius: 4px;
                    padding: 5px 10px;
                }
                QPushButton:hover {
                    background: #F75C4B;
                }
            """)
            delete_btn.clicked.connect(lambda checked, r=rule: self._delete_custom_rule(r))
            actions_layout.addWidget(delete_btn)
        
        self.rules_table.setCellWidget(row, 5, actions_widget)
    
    def _add_custom_rule(self):
        """Add a custom rule."""
        name = self.rule_name.text().strip()
        pattern = self.rule_pattern.text().strip()
        description = self.rule_description.text().strip()
        detection_type_str = self.rule_type.currentText()
        weight_str = self.rule_weight.text().strip()
        
        # Validation
        if not name or not pattern:
            QMessageBox.warning(self, "Validation Error", "Name and Pattern are required fields.")
            return
        
        try:
            import re
            re.compile(pattern)
        except re.error as e:
            QMessageBox.warning(self, "Invalid Regex", f"Invalid regular expression:\n{str(e)}")
            return
        
        try:
            weight = float(weight_str)
            if not 0.1 <= weight <= 1.0:
                raise ValueError()
        except ValueError:
            QMessageBox.warning(self, "Invalid Weight", "Severity weight must be between 0.1 and 1.0")
            return
        
        # Get detection type enum
        detection_type = DetectionType(detection_type_str)
        
        # Create rule
        rule = AnalysisRule(
            id=f"custom_{len(self.custom_rules) + 1}",
            name=name,
            description=description or name,
            pattern=pattern,
            detection_type=detection_type,
            severity_weight=weight,
            enabled=True,
            custom=True
        )
        
        self.custom_rules.append(rule)
        self._refresh_rules_table()
        
        # Clear form
        self.rule_name.clear()
        self.rule_pattern.clear()
        self.rule_description.clear()
        self.rule_weight.setText("0.7")
        
        QMessageBox.information(self, "Rule Added", f"Custom rule '{name}' has been added.")
    
    def _delete_custom_rule(self, rule: AnalysisRule):
        """Delete a custom rule."""
        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Are you sure you want to delete the rule '{rule.name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.custom_rules = [r for r in self.custom_rules if r.id != rule.id]
            self._refresh_rules_table()
            QMessageBox.information(self, "Rule Deleted", "Custom rule has been deleted.")
