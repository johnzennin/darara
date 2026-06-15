#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQLMap GUI - PyQt5 based graphical interface for sqlmap
"""

import sys
import os
import subprocess
import threading
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QTextEdit, QPushButton, QComboBox,
    QGroupBox, QFormLayout, QTabWidget, QCheckBox, QSpinBox,
    QFileDialog, QMessageBox, QSplitter, QStatusBar, QMenuBar,
    QMenu, QAction, QProgressBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QProcess
from PyQt5.QtGui import QFont, QTextCursor


class SqlmapWorker(QThread):
    """Worker thread for running sqlmap commands"""
    output_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(int)
    
    def __init__(self, command, working_dir=None):
        super().__init__()
        self.command = command
        self.working_dir = working_dir
        self.process = None
        
    def run(self):
        try:
            self.process = QProcess()
            if self.working_dir:
                self.process.setWorkingDirectory(self.working_dir)
            
            self.process.readyReadStandardOutput.connect(self.handle_stdout)
            self.process.readyReadStandardError.connect(self.handle_stderr)
            self.process.finished.connect(self.handle_finished)
            
            # Parse command into arguments
            if isinstance(self.command, str):
                import shlex
                args = shlex.split(self.command)
            else:
                args = self.command
            
            program = args[0]
            arguments = args[1:] if len(args) > 1 else []
            
            self.process.start(program, arguments)
            
            # Wait for process to finish
            if not self.process.waitForStarted():
                self.error_signal.emit(f"Failed to start process: {program}")
                return
                
            self.process.waitForFinished(-1)
            
        except Exception as e:
            self.error_signal.emit(f"Error: {str(e)}")
            self.finished_signal.emit(-1)
    
    def handle_stdout(self):
        data = self.process.readAllStandardOutput()
        text = data.data().decode('utf-8', errors='replace')
        self.output_signal.emit(text)
    
    def handle_stderr(self):
        data = self.process.readAllStandardError()
        text = data.data().decode('utf-8', errors='replace')
        if text.strip():
            self.error_signal.emit(text)
    
    def handle_finished(self, exit_code):
        self.finished_signal.emit(exit_code)
    
    def stop(self):
        if self.process and self.process.state() == QProcess.Running:
            self.process.kill()


class SqlmapGUI(QMainWindow):
    """Main SQLMap GUI Application"""
    
    def __init__(self):
        super().__init__()
        self.worker = None
        self.sqlmap_path = ""
        self.init_ui()
        self.check_sqlmap()
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("SQLMap GUI")
        self.setMinimumSize(1000, 700)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Splitter for resizable sections
        splitter = QSplitter(Qt.Vertical)
        main_layout.addWidget(splitter)
        
        # Top section - Configuration
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        
        # Tab widget for different option categories
        self.tabs = QTabWidget()
        top_layout.addWidget(self.tabs)
        
        # Target tab
        self.target_tab = self.create_target_tab()
        self.tabs.addTab(self.target_tab, "Hedef")
        
        # Request tab
        self.request_tab = self.create_request_tab()
        self.tabs.addTab(self.request_tab, "İstek")
        
        # Optimization tab
        self.optimization_tab = self.create_optimization_tab()
        self.tabs.addTab(self.optimization_tab, "Optimizasyon")
        
        # Injection tab
        self.injection_tab = self.create_injection_tab()
        self.tabs.addTab(self.injection_tab, "Enjeksiyon")
        
        # Detection tab
        self.detection_tab = self.create_detection_tab()
        self.tabs.addTab(self.detection_tab, "Tespit")
        
        # Techniques tab
        self.techniques_tab = self.create_techniques_tab()
        self.tabs.addTab(self.techniques_tab, "Teknikler")
        
        # Enumerasyon tab
        self.enumeration_tab = self.create_enumeration_tab()
        self.tabs.addTab(self.enumeration_tab, "Numaralandırma")
        
        # Filtreleme tab
        self.filter_tab = self.create_filter_tab()
        self.tabs.addTab(self.filter_tab, "Filtreleme")
        
        # Genel ayarlar tab
        self.general_tab = self.create_general_tab()
        self.tabs.addTab(self.general_tab, "Genel")
        
        # Command preview and buttons
        cmd_group = QGroupBox("Komut Önizleme")
        cmd_layout = QVBoxLayout(cmd_group)
        
        self.command_preview = QLineEdit()
        self.command_preview.setReadOnly(True)
        self.command_preview.setFont(QFont("Courier", 10))
        cmd_layout.addWidget(self.command_preview)
        
        btn_layout = QHBoxLayout()
        
        self.run_btn = QPushButton("▶ Çalıştır")
        self.run_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 10px 20px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.run_btn.clicked.connect(self.run_sqlmap)
        btn_layout.addWidget(self.run_btn)
        
        self.stop_btn = QPushButton("⏹ Durdur")
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                padding: 10px 20px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.stop_btn.clicked.connect(self.stop_sqlmap)
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.stop_btn)
        
        self.clear_btn = QPushButton("🗑 Temizle")
        self.clear_btn.clicked.connect(self.clear_output)
        btn_layout.addWidget(self.clear_btn)
        
        self.save_btn = QPushButton("💾 Kaydet")
        self.save_btn.clicked.connect(self.save_output)
        btn_layout.addWidget(self.save_btn)
        
        btn_layout.addStretch()
        cmd_layout.addLayout(btn_layout)
        
        top_layout.addWidget(cmd_group)
        splitter.addWidget(top_widget)
        
        # Bottom section - Output
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        
        output_label = QLabel("Çıktı:")
        bottom_layout.addWidget(output_label)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Courier", 9))
        self.output_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #00ff00;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 5px;
            }
        """)
        bottom_layout.addWidget(self.output_text)
        
        # Progress bar
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        bottom_layout.addWidget(self.progress)
        
        splitter.addWidget(bottom_widget)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        
        # Status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Hazır")
        
        # Update command preview when any field changes
        self.update_command_preview()
        
    def create_menu_bar(self):
        """Create application menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("Dosya")
        
        load_req_action = QAction("İstek Dosyası Yükle", self)
        load_req_action.triggered.connect(self.load_request_file)
        file_menu.addAction(load_req_action)
        
        save_output_action = QAction("Çıktıyı Kaydet", self)
        save_output_action.triggered.connect(self.save_output)
        file_menu.addAction(save_output_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Çıkış", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Settings menu
        settings_menu = menubar.addMenu("Ayarlar")
        
        sqlmap_path_action = QAction("SQLMap Yolunu Ayarla", self)
        sqlmap_path_action.triggered.connect(self.set_sqlmap_path)
        settings_menu.addAction(sqlmap_path_action)
        
        # Help menu
        help_menu = menubar.addMenu("Yardım")
        
        about_action = QAction("Hakkında", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def create_target_tab(self):
        """Create target configuration tab"""
        widget = QWidget()
        layout = QFormLayout(widget)
        
        self.target_url = QLineEdit()
        self.target_url.setPlaceholderText("https://example.com/page.php?id=1")
        self.target_url.textChanged.connect(self.update_command_preview)
        layout.addRow("Hedef URL:", self.target_url)
        
        self.google_dork = QLineEdit()
        self.google_dork.setPlaceholderText("inurl:.php?id=")
        layout.addRow("Google Dork:", self.google_dork)
        
        self.post_data = QLineEdit()
        self.post_data.setPlaceholderText("id=1&name=test")
        self.post_data.textChanged.connect(self.update_command_preview)
        layout.addRow("POST Verisi:", self.post_data)
        
        self.cookie_input = QLineEdit()
        self.cookie_input.setPlaceholderText("PHPSESSID=abc123; user=admin")
        self.cookie_input.textChanged.connect(self.update_command_preview)
        layout.addRow("Cookie:", self.cookie_input)
        
        self.user_agent = QLineEdit()
        self.user_agent.setText("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        layout.addRow("User-Agent:", self.user_agent)
        
        self.random_agent = QCheckBox("Rastgele User-Agent kullan")
        self.random_agent.stateChanged.connect(self.update_command_preview)
        layout.addRow("", self.random_agent)
        
        self.host_header = QLineEdit()
        self.host_header.setPlaceholderText("www.example.com")
        layout.addRow("Host Header:", self.host_header)
        
        return widget
    
    def create_request_tab(self):
        """Create request configuration tab"""
        widget = QWidget()
        layout = QFormLayout(widget)
        
        self.request_file = QLineEdit()
        self.request_file.setReadOnly(True)
        layout.addRow("İstek Dosyası:", self.request_file)
        
        browse_req_btn = QPushButton("Gözat...")
        browse_req_btn.clicked.connect(self.browse_request_file)
        layout.addRow("", browse_req_btn)
        
        self.delay_spin = QDoubleSpinBox()
        self.delay_spin.setRange(0, 60)
        self.delay_spin.setSingleStep(0.5)
        self.delay_spin.setSuffix(" saniye")
        layout.addRow("İstek Gecikmesi:", self.delay_spin)
        
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 300)
        self.timeout_spin.setValue(30)
        self.timeout_spin.setSuffix(" saniye")
        layout.addRow("Zaman Aşımı:", self.timeout_spin)
        
        self.retries_spin = QSpinBox()
        self.retries_spin.setRange(0, 10)
        self.retries_spin.setValue(3)
        layout.addRow("Yeniden Deneme:", self.retries_spin)
        
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText("http://127.0.0.1:8080")
        layout.addRow("Proxy:", self.proxy_input)
        
        self.tor_checkbox = QCheckBox("Tor kullan")
        self.tor_checkbox.stateChanged.connect(self.update_command_preview)
        layout.addRow("", self.tor_checkbox)
        
        self.check_tor = QCheckBox("Tor bağlantısını kontrol et")
        layout.addRow("", self.check_tor)
        
        return widget
    
    def create_optimization_tab(self):
        """Create optimization configuration tab"""
        widget = QWidget()
        layout = QFormLayout(widget)
        
        self.optimize_requests = QCheckBox("HTTP isteklerini optimize et")
        layout.addRow("", self.optimize_requests)
        
        self.keep_alive = QCheckBox("HTTP Keep-Alive kullan")
        layout.addRow("", self.keep_alive)
        
        self.null_connection = QCheckBox("Boş TCP bağlantıları kullan")
        layout.addRow("", self.null_connection)
        
        self.thread_spin = QSpinBox()
        self.thread_spin.setRange(1, 10)
        self.thread_spin.setValue(1)
        self.thread_spin.setSuffix(" iş parçacığı")
        layout.addRow("İş Parçacığı Sayısı:", self.thread_spin)
        
        return widget
    
    def create_injection_tab(self):
        """Create injection configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Injection type
        type_group = QGroupBox("Enjeksiyon Tipi")
        type_layout = QHBoxLayout(type_group)
        
        self.injection_type_combo = QComboBox()
        self.injection_type_combo.addItems([
            "Tümü",
            "Boolean-based blind",
            "Error-based",
            "Union query",
            "Stacked queries",
            "Time-based blind"
        ])
        type_layout.addWidget(self.injection_type_combo)
        layout.addWidget(type_group)
        
        # Risk level
        risk_group = QGroupBox("Risk Seviyesi")
        risk_layout = QHBoxLayout(risk_group)
        
        self.risk_spin = QSpinBox()
        self.risk_spin.setRange(1, 3)
        self.risk_spin.setValue(1)
        risk_layout.addWidget(self.risk_spin)
        risk_layout.addWidget(QLabel("(1-3)"))
        risk_layout.addStretch()
        layout.addWidget(risk_group)
        
        # Level
        level_group = QGroupBox("Seviye")
        level_layout = QHBoxLayout(level_group)
        
        self.level_spin = QSpinBox()
        self.level_spin.setRange(1, 5)
        self.level_spin.setValue(1)
        level_layout.addWidget(self.level_spin)
        level_layout.addWidget(QLabel("(1-5)"))
        level_layout.addStretch()
        layout.addWidget(level_group)
        
        # Test parameters
        param_group = QGroupBox("Test Parametreleri")
        param_layout = QVBoxLayout(param_group)
        
        self.test_param = QLineEdit()
        self.test_param.setPlaceholderText("Parametre adı (virgülle ayrılmış)")
        param_layout.addWidget(self.test_param)
        
        self.skip_param = QLineEdit()
        self.skip_param.setPlaceholderText("Atlanacak parametreler")
        param_layout.addWidget(self.skip_param)
        
        self.param_skip = QLineEdit()
        self.param_skip.setPlaceholderText("Atlanacak değerler")
        param_layout.addWidget(self.param_skip)
        
        layout.addWidget(param_group)
        
        layout.addStretch()
        return widget
    
    def create_detection_tab(self):
        """Create detection configuration tab"""
        widget = QWidget()
        layout = QFormLayout(widget)
        
        self.string_match = QLineEdit()
        self.string_match.setPlaceholderText("Sayfada aranacak metin")
        layout.addRow("Eşleşecek Metin:", self.string_match)
        
        self.string_not_match = QLineEdit()
        self.string_not_match.setPlaceholderText("Sayfada olmaması gereken metin")
        layout.addRow("Eşleşmeyecek Metin:", self.string_not_match)
        
        self.regexp_match = QLineEdit()
        self.regexp_match.setPlaceholderText("Regex pattern")
        layout.addRow("Regex Eşleşme:", self.regexp_match)
        
        self.code_match = QSpinBox()
        self.code_match.setRange(100, 599)
        layout.addRow("HTTP Kod Eşleşme:", self.code_match)
        
        self.code_not_match = QSpinBox()
        self.code_not_match.setRange(100, 599)
        layout.addRow("HTTP Kod Eşleşmeme:", self.code_not_match)
        
        self.text_only_compare = QCheckBox("Sadece metin karşılaştırması")
        layout.addRow("", self.text_only_compare)
        
        self.title_compare = QCheckBox("Başlık karşılaştırması")
        layout.addRow("", self.title_compare)
        
        return widget
    
    def create_techniques_tab(self):
        """Create techniques configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        techniques_group = QGroupBox("SQL Enjeksiyon Teknikleri")
        techniques_layout = QVBoxLayout(techniques_group)
        
        self.tech_boolean = QCheckBox("B - Boolean-based blind SQL injection")
        self.tech_boolean.setChecked(True)
        techniques_layout.addWidget(self.tech_boolean)
        
        self.tech_error = QCheckBox("E - Error-based SQL injection")
        self.tech_error.setChecked(True)
        techniques_layout.addWidget(self.tech_error)
        
        self.tech_union = QCheckBox("U - Union query SQL injection")
        self.tech_union.setChecked(True)
        techniques_layout.addWidget(self.tech_union)
        
        self.tech_stacked = QCheckBox("S - Stacked queries SQL injection")
        self.tech_stacked.setChecked(True)
        techniques_layout.addWidget(self.tech_stacked)
        
        self.tech_time = QCheckBox("T - Time-based blind SQL injection")
        self.tech_time.setChecked(True)
        techniques_layout.addWidget(self.tech_time)
        
        layout.addWidget(techniques_group)
        layout.addStretch()
        return widget
    
    def create_enumeration_tab(self):
        """Create enumeration configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Database options
        db_group = QGroupBox("Veritabanı Seçenekleri")
        db_layout = QVBoxLayout(db_group)
        
        self.enum_all = QCheckBox("Tüm veritabanlarını numaralandır")
        self.enum_all.stateChanged.connect(self.update_command_preview)
        db_layout.addWidget(self.enum_all)
        
        self.current_db = QCheckBox("Mevcut veritabanını al")
        self.current_db.stateChanged.connect(self.update_command_preview)
        db_layout.addWidget(self.current_db)
        
        self.db_names = QCheckBox("Veritabanı isimlerini listele")
        self.db_names.stateChanged.connect(self.update_command_preview)
        db_layout.addWidget(self.db_names)
        
        self.specific_db = QLineEdit()
        self.specific_db.setPlaceholderText("Belirli veritabanı adı")
        db_layout.addWidget(self.specific_db)
        
        layout.addWidget(db_group)
        
        # Table options
        table_group = QGroupBox("Tablo Seçenekleri")
        table_layout = QVBoxLayout(table_group)
        
        self.enum_tables = QCheckBox("Tabloları numaralandır")
        self.enum_tables.stateChanged.connect(self.update_command_preview)
        table_layout.addWidget(self.enum_tables)
        
        self.enum_columns = QCheckBox("Sütunları numaralandır")
        self.enum_columns.stateChanged.connect(self.update_command_preview)
        table_layout.addWidget(self.enum_columns)
        
        self.specific_table = QLineEdit()
        self.specific_table.setPlaceholderText("Belirli tablo adı")
        table_layout.addWidget(self.specific_table)
        
        layout.addWidget(table_group)
        
        # Column options
        column_group = QGroupBox("Sütun Seçenekleri")
        column_layout = QVBoxLayout(column_group)
        
        self.specific_column = QLineEdit()
        self.specific_column.setPlaceholderText("Belirli sütun adı")
        column_layout.addWidget(self.specific_column)
        
        layout.addWidget(column_group)
        
        # Data options
        data_group = QGroupBox("Veri Seçenekleri")
        data_layout = QVBoxLayout(data_group)
        
        self.dump_data = QCheckBox("Verileri dök")
        self.dump_data.stateChanged.connect(self.update_command_preview)
        data_layout.addWidget(self.dump_data)
        
        self.dump_all = QCheckBox("Tüm veritabanlarından verileri dök")
        self.dump_all.stateChanged.connect(self.update_command_preview)
        data_layout.addWidget(self.dump_all)
        
        self.dump_limit_start = QSpinBox()
        self.dump_limit_start.setRange(0, 10000)
        self.dump_limit_start.setPrefix("Başlangıç: ")
        data_layout.addWidget(self.dump_limit_start)
        
        self.dump_limit_count = QSpinBox()
        self.dump_limit_count.setRange(1, 10000)
        self.dump_limit_count.setValue(100)
        self.dump_limit_count.setPrefix("Adet: ")
        data_layout.addWidget(self.dump_limit_count)
        
        layout.addWidget(data_group)
        
        # User options
        user_group = QGroupBox("Kullanıcı Seçenekleri")
        user_layout = QVBoxLayout(user_group)
        
        self.enum_users = QCheckBox("Kullanıcıları numaralandır")
        user_layout.addWidget(self.enum_users)
        
        self.current_user = QCheckBox("Mevcut kullanıcıyı al")
        user_layout.addWidget(self.current_user)
        
        self.specific_user = QLineEdit()
        self.specific_user.setPlaceholderText("Belirli kullanıcı adı")
        user_layout.addWidget(self.specific_user)
        
        layout.addWidget(user_group)
        
        # Password options
        pass_group = QGroupBox("Parola Seçenekleri")
        pass_layout = QVBoxLayout(pass_group)
        
        self.password_hashes = QCheckBox("Parola hash'lerini dök")
        pass_layout.addWidget(self.password_hashes)
        
        layout.addWidget(pass_group)
        
        # Privileges
        priv_group = QGroupBox("Yetki Seçenekleri")
        priv_layout = QVBoxLayout(priv_group)
        
        self.enum_privileges = QCheckBox("Kullanıcı yetkilerini numaralandır")
        priv_layout.addWidget(self.enum_privileges)
        
        layout.addWidget(priv_group)
        
        # Roles
        roles_group = QGroupBox("Rol Seçenekleri")
        roles_layout = QVBoxLayout(roles_group)
        
        self.enum_roles = QCheckBox("Kullanıcı rollerini numaralandır")
        roles_layout.addWidget(self.enum_roles)
        
        layout.addWidget(roles_group)
        
        # DBMS
        dbms_group = QGroupBox("DBMS Seçenekleri")
        dbms_layout = QVBoxLayout(dbms_group)
        
        self.fingerprint = QCheckBox("DBMS parmak izini al")
        self.fingerprint.stateChanged.connect(self.update_command_preview)
        dbms_layout.addWidget(self.fingerprint)
        
        self.dbms_version = QCheckBox("DBMS versiyonunu al")
        self.dbms_version.stateChanged.connect(self.update_command_preview)
        dbms_layout.addWidget(self.dbms_version)
        
        layout.addWidget(dbms_group)
        
        # OS
        os_group = QGroupBox("İşletim Sistemi Seçenekleri")
        os_layout = QVBoxLayout(os_group)
        
        self.is_dba = QCheckBox("DBA olup olmadığını kontrol et")
        self.is_dba.stateChanged.connect(self.update_command_preview)
        os_layout.addWidget(self.is_dba)
        
        self.os_cmd = QLineEdit()
        self.os_cmd.setPlaceholderText("Çalıştırılacak OS komutu")
        os_layout.addWidget(self.os_cmd)
        
        self.os_shell = QCheckBox("OS shell aç")
        os_layout.addWidget(self.os_shell)
        
        self.os_pwn = QCheckBox("OS pwn aç")
        os_layout.addWidget(self.os_pwn)
        
        layout.addWidget(os_group)
        
        layout.addStretch()
        return widget
    
    def create_filter_tab(self):
        """Create filter configuration tab"""
        widget = QWidget()
        layout = QFormLayout(widget)
        
        self.regexp = QLineEdit()
        self.regexp.setPlaceholderText("Sütunları filtrelemek için regex")
        layout.addRow("Sütun Regex:", self.regexp)
        
        self.exclude_sys = QCheckBox("Sistem tablolarını hariç tut")
        layout.addRow("", self.exclude_sys)
        
        self.exclude_lib = QCheckBox("Library tablolarını hariç tut")
        layout.addRow("", self.exclude_lib)
        
        return widget
    
    def create_general_tab(self):
        """Create general configuration tab"""
        widget = QWidget()
        layout = QFormLayout(widget)
        
        self.verbose_spin = QSpinBox()
        self.verbose_spin.setRange(0, 6)
        self.verbose_spin.setValue(1)
        layout.addRow("Detay Seviyesi:", self.verbose_spin)
        
        self.debug = QCheckBox("Debug modu")
        layout.addRow("", self.debug)
        
        self.hex_conversion = QCheckBox("Hex dönüşümü kullan")
        layout.addRow("", self.hex_conversion)
        
        self.no_cast = QCheckBox("CAST fonksiyonunu kullanma")
        layout.addRow("", self.no_cast)
        
        self.predump = QCheckBox("Dökmeden önce temizle")
        layout.addRow("", self.predump)
        
        self.cleanup = QCheckBox("Temizleme yap")
        layout.addRow("", self.cleanup)
        
        self.offline = QCheckBox("Offline mod")
        layout.addRow("", self.offline)
        
        self.batch = QCheckBox("Batch mod (sormadan devam et)")
        self.batch.setChecked(True)
        layout.addRow("", self.batch)
        
        self.check_waf = QCheckBox("WAF tespiti")
        layout.addRow("", self.check_waf)
        
        self.skip_waf = QCheckBox("WAF bypass dene")
        layout.addRow("", self.skip_waf)
        
        self.flush_session = QCheckBox("Oturumu temizle")
        layout.addRow("", self.flush_session)
        
        self.save_session = QLineEdit()
        self.save_session.setPlaceholderText("Oturum dosyası kaydet")
        layout.addRow("Oturum Kaydet:", self.save_session)
        
        self.resume_session = QLineEdit()
        self.resume_session.setPlaceholderText("Oturum dosyasından devam et")
        layout.addRow("Oturum Devam:", self.resume_session)
        
        self.output_dir = QLineEdit()
        self.output_dir.setReadOnly(True)
        layout.addRow("Çıktı Dizini:", self.output_dir)
        
        browse_output_btn = QPushButton("Gözat...")
        browse_output_btn.clicked.connect(self.browse_output_dir)
        layout.addRow("", browse_output_btn)
        
        return widget
    
    def check_sqlmap(self):
        """Check if sqlmap is available"""
        # Try common paths
        possible_paths = [
            "sqlmap",
            "/usr/bin/sqlmap",
            "/usr/local/bin/sqlmap",
            os.path.expanduser("~/.local/bin/sqlmap"),
            os.path.join(os.path.dirname(__file__), "sqlmap", "sqlmap.py"),
            "/opt/sqlmap/sqlmap.py"
        ]
        
        for path in possible_paths:
            if os.path.isfile(path) or self.check_command_exists(path.split()[0]):
                self.sqlmap_path = path
                self.statusBar.showMessage(f"SQLMap bulundu: {path}")
                return
        
        self.sqlmap_path = "sqlmap"  # Assume it's in PATH
        self.statusBar.showMessage("SQLMap yolu varsayılan olarak 'sqlmap' olarak ayarlandı")
        QMessageBox.warning(
            self,
            "SQLMap Bulunamadı",
            "SQLMap sistemde bulunamadı. Lütfen SQLMap'i yükleyin veya "
            "Ayarlar menüsünden doğru yolu belirtin.\n\n"
            "SQLMap GitHub: https://github.com/sqlmapproject/sqlmap"
        )
    
    def check_command_exists(self, cmd):
        """Check if a command exists in PATH"""
        return subprocess.call(
            ["which", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        ) == 0
    
    def set_sqlmap_path(self):
        """Set sqlmap path manually"""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "SQLMap Konumu Seç",
            "",
            "Python Files (*.py);;All Files (*)"
        )
        if path:
            self.sqlmap_path = path
            self.statusBar.showMessage(f"SQLMap yolu ayarlandı: {path}")
    
    def browse_request_file(self):
        """Browse for request file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "İstek Dosyası Seç",
            "",
            "All Files (*)"
        )
        if file_path:
            self.request_file.setText(file_path)
            self.update_command_preview()
    
    def browse_output_dir(self):
        """Browse for output directory"""
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Çıktı Dizini Seç"
        )
        if dir_path:
            self.output_dir.setText(dir_path)
            self.update_command_preview()
    
    def load_request_file(self):
        """Load request from file"""
        self.browse_request_file()
    
    def update_command_preview(self):
        """Update the command preview based on current settings"""
        cmd_parts = [self.sqlmap_path]
        
        # Target options
        if self.target_url.text():
            cmd_parts.append(f'-u "{self.target_url.text()}"')
        
        if self.google_dork.text():
            cmd_parts.append(f'-g "{self.google_dork.text()}"')
        
        if self.request_file.text():
            cmd_parts.append(f'-r "{self.request_file.text()}"')
        
        # Request options
        if self.post_data.text():
            cmd_parts.append(f'--data="{self.post_data.text()}"')
        
        if self.cookie_input.text():
            cmd_parts.append(f'--cookie="{self.cookie_input.text()}"')
        
        if self.user_agent.text() and not self.random_agent.isChecked():
            cmd_parts.append(f'--user-agent="{self.user_agent.text()}"')
        
        if self.random_agent.isChecked():
            cmd_parts.append('--random-agent')
        
        if self.host_header.text():
            cmd_parts.append(f'--host="{self.host_header.text()}"')
        
        # Request settings
        if self.delay_spin.value() > 0:
            cmd_parts.append(f'--delay={self.delay_spin.value()}')
        
        if self.timeout_spin.value() != 30:
            cmd_parts.append(f'--timeout={self.timeout_spin.value()}')
        
        if self.retries_spin.value() != 3:
            cmd_parts.append(f'--retries={self.retries_spin.value()}')
        
        if self.proxy_input.text():
            cmd_parts.append(f'--proxy="{self.proxy_input.text()}"')
        
        if self.tor_checkbox.isChecked():
            cmd_parts.append('--tor')
            if self.check_tor.isChecked():
                cmd_parts.append('--check-tor')
        
        # Optimization
        if self.optimize_requests.isChecked():
            cmd_parts.append('-o')
        
        if self.keep_alive.isChecked():
            cmd_parts.append('--keep-alive')
        
        if self.null_connection.isChecked():
            cmd_parts.append('--null-connection')
        
        if self.thread_spin.value() > 1:
            cmd_parts.append(f'--threads={self.thread_spin.value()}')
        
        # Injection
        injection_type = self.injection_type_combo.currentText()
        if injection_type != "Tümü":
            type_map = {
                "Boolean-based blind": "B",
                "Error-based": "E",
                "Union query": "U",
                "Stacked queries": "S",
                "Time-based blind": "T"
            }
            cmd_parts.append(f'--technique={type_map.get(injection_type, "")}')
        
        if self.risk_spin.value() > 1:
            cmd_parts.append(f'--risk={self.risk_spin.value()}')
        
        if self.level_spin.value() > 1:
            cmd_parts.append(f'--level={self.level_spin.value()}')
        
        if self.test_param.text():
            cmd_parts.append(f'--test-parameter="{self.test_param.text()}"')
        
        if self.skip_param.text():
            cmd_parts.append(f'--skip="{self.skip_param.text()}"')
        
        # Detection
        if self.string_match.text():
            cmd_parts.append(f'--string="{self.string_match.text()}"')
        
        if self.string_not_match.text():
            cmd_parts.append(f'--not-string="{self.string_not_match.text()}"')
        
        if self.regexp_match.text():
            cmd_parts.append(f'--regexp="{self.regexp_match.text()}"')
        
        if self.code_match.value() >= 100:
            cmd_parts.append(f'--match-code={self.code_match.value()}')
        
        if self.code_not_match.value() >= 100:
            cmd_parts.append(f'--skip-code={self.code_not_match.value()}')
        
        if self.text_only_compare.isChecked():
            cmd_parts.append('--text-only')
        
        if self.title_compare.isChecked():
            cmd_parts.append('--title')
        
        # Techniques
        tech_chars = []
        if self.tech_boolean.isChecked():
            tech_chars.append('B')
        if self.tech_error.isChecked():
            tech_chars.append('E')
        if self.tech_union.isChecked():
            tech_chars.append('U')
        if self.tech_stacked.isChecked():
            tech_chars.append('S')
        if self.tech_time.isChecked():
            tech_chars.append('T')
        
        if tech_chars and len(tech_chars) < 5:
            cmd_parts.append(f'--technique={"".join(tech_chars)}')
        
        # Enumeration
        if self.enum_all.isChecked():
            cmd_parts.append('--dbs')
        
        if self.current_db.isChecked():
            cmd_parts.append('--current-db')
        
        if self.db_names.isChecked():
            cmd_parts.append('--dbs')
        
        if self.specific_db.text():
            cmd_parts.append(f'-D {self.specific_db.text()}')
        
        if self.enum_tables.isChecked():
            cmd_parts.append('--tables')
        
        if self.enum_columns.isChecked():
            cmd_parts.append('--columns')
        
        if self.specific_table.text():
            cmd_parts.append(f'-T {self.specific_table.text()}')
        
        if self.specific_column.text():
            cmd_parts.append(f'-C {self.specific_column.text()}')
        
        if self.dump_data.isChecked():
            cmd_parts.append('--dump')
        
        if self.dump_all.isChecked():
            cmd_parts.append('--dump-all')
        
        if self.dump_limit_start.value() > 0 or self.dump_limit_count.value() < 100:
            cmd_parts.append(f'--start={self.dump_limit_start.value()} --stop={self.dump_limit_start.value() + self.dump_limit_count.value()}')
        
        if self.enum_users.isChecked():
            cmd_parts.append('--users')
        
        if self.current_user.isChecked():
            cmd_parts.append('--current-user')
        
        if self.specific_user.text():
            cmd_parts.append(f'-U {self.specific_user.text()}')
        
        if self.password_hashes.isChecked():
            cmd_parts.append('--passwords')
        
        if self.enum_privileges.isChecked():
            cmd_parts.append('--privileges')
        
        if self.enum_roles.isChecked():
            cmd_parts.append('--roles')
        
        if self.fingerprint.isChecked():
            cmd_parts.append('--fingerprint')
        
        if self.dbms_version.isChecked():
            cmd_parts.append('--dbms-version')
        
        if self.is_dba.isChecked():
            cmd_parts.append('--is-dba')
        
        if self.os_cmd.text():
            cmd_parts.append(f'--os-cmd="{self.os_cmd.text()}"')
        
        if self.os_shell.isChecked():
            cmd_parts.append('--os-shell')
        
        if self.os_pwn.isChecked():
            cmd_parts.append('--os-pwn')
        
        # Filter
        if self.regexp.text():
            cmd_parts.append(f'--regexp="{self.regexp.text()}"')
        
        if self.exclude_sys.isChecked():
            cmd_parts.append('--exclude-sys')
        
        if self.exclude_lib.isChecked():
            cmd_parts.append('--exclude-lib')
        
        # General
        if self.verbose_spin.value() > 1:
            cmd_parts.append(f'-v {self.verbose_spin.value()}')
        
        if self.debug.isChecked():
            cmd_parts.append('--debug')
        
        if self.hex_conversion.isChecked():
            cmd_parts.append('--hex')
        
        if self.no_cast.isChecked():
            cmd_parts.append('--no-cast')
        
        if self.predump.isChecked():
            cmd_parts.append('--cleanup')
        
        if self.cleanup.isChecked():
            cmd_parts.append('--cleanup')
        
        if self.offline.isChecked():
            cmd_parts.append('--offline')
        
        if self.batch.isChecked():
            cmd_parts.append('--batch')
        
        if self.check_waf.isChecked():
            cmd_parts.append('--identify-waf')
        
        if self.skip_waf.isChecked():
            cmd_parts.append('--skip-waf')
        
        if self.flush_session.isChecked():
            cmd_parts.append('--flush-session')
        
        if self.save_session.text():
            cmd_parts.append(f'--save-config={self.save_session.text()}')
        
        if self.resume_session.text():
            cmd_parts.append(f'--resume={self.resume_session.text()}')
        
        if self.output_dir.text():
            cmd_parts.append(f'--output-dir="{self.output_dir.text()}"')
        
        self.command_preview.setText(" ".join(cmd_parts))
    
    def run_sqlmap(self):
        """Run sqlmap with current configuration"""
        command = self.command_preview.text()
        
        if not command or command == self.sqlmap_path:
            QMessageBox.warning(
                self,
                "Hata",
                "Lütfen en az bir hedef URL veya istek dosyası belirtin."
            )
            return
        
        # Disable run button, enable stop button
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)  # Indeterminate progress
        
        self.statusBar.showMessage("SQLMap çalışıyor...")
        
        # Create and start worker thread
        self.worker = SqlmapWorker(command)
        self.worker.output_signal.connect(self.append_output)
        self.worker.error_signal.connect(self.append_error)
        self.worker.finished_signal.connect(self.on_sqlmap_finished)
        self.worker.start()
    
    def stop_sqlmap(self):
        """Stop running sqlmap process"""
        if self.worker and self.worker.isRunning():
            reply = QMessageBox.question(
                self,
                "İşlemi Durdur",
                "SQLMap işlemini durdurmak istediğinize emin misiniz?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.worker.stop()
                self.statusBar.showMessage("SQLMap durduruluyor...")
    
    def on_sqlmap_finished(self, exit_code):
        """Handle sqlmap process completion"""
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress.setVisible(False)
        
        if exit_code == 0:
            self.statusBar.showMessage("SQLMap işlemi tamamlandı")
            self.append_output("\n✓ İşlem başarıyla tamamlandı!\n")
        else:
            self.statusBar.showMessage(f"SQLMap işlemi hata ile sonlandı (kod: {exit_code})")
            self.append_error(f"\n✗ İşlem hata ile sonlandı (çıkış kodu: {exit_code})\n")
    
    def append_output(self, text):
        """Append text to output window"""
        self.output_text.moveCursor(QTextCursor.End)
        self.output_text.insertPlainText(text)
        self.output_text.moveCursor(QTextCursor.End)
    
    def append_error(self, text):
        """Append error text to output window"""
        self.output_text.moveCursor(QTextCursor.End)
        self.output_text.setTextColor(Qt.red)
        self.output_text.insertPlainText(text)
        self.output_text.setTextColor(Qt.green)
        self.output_text.moveCursor(QTextCursor.End)
    
    def clear_output(self):
        """Clear output window"""
        self.output_text.clear()
        self.statusBar.showMessage("Çıktı temizlendi")
    
    def save_output(self):
        """Save output to file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Çıktıyı Kaydet",
            "sqlmap_output.txt",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.output_text.toPlainText())
                self.statusBar.showMessage(f"Çıktı kaydedildi: {file_path}")
                QMessageBox.information(
                    self,
                    "Başarılı",
                    f"Çıktı başarıyla kaydedildi:\n{file_path}"
                )
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Hata",
                    f"Dosya kaydedilemedi:\n{str(e)}"
                )
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self,
            "SQLMap GUI Hakkında",
            "<h2>SQLMap GUI</h2>"
            "<p>PyQt5 ile geliştirilmiş grafiksel SQLMap arayüzü.</p>"
            "<p><b>Not:</b> Bu araç sadece eğitim ve yasal güvenlik testleri "
            "için kullanılmalıdır. İzinsiz sistemlere karşı kullanım yasa dışıdır.</p>"
            "<p><b>SQLMap:</b> https://github.com/sqlmapproject/sqlmap</p>"
            "<p><b>Lisans:</b> GPLv2</p>"
        )
    
    def closeEvent(self, event):
        """Handle window close event"""
        if self.worker and self.worker.isRunning():
            reply = QMessageBox.question(
                self,
                "İşlem Devam Ediyor",
                "SQLMap hala çalışıyor. Çıkmak istediğinize emin misiniz?\n"
                "Bu durum çalışan işlemi sonlandıracaktır.",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.worker.stop()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


def main():
    """Main entry point"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Set application palette
    from PyQt5.QtGui import QPalette, QColor
    
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, QColor(25, 25, 25))
    palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ToolTipBase, Qt.white)
    palette.setColor(QPalette.ToolTipText, Qt.white)
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ButtonText, Qt.white)
    palette.setColor(QPalette.BrightText, Qt.black)
    palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.HighlightedText, Qt.black)
    app.setPalette(palette)
    
    window = SqlmapGUI()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
