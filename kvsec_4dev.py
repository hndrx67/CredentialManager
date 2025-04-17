import sys
import os
import json
import sqlite3
import hashlib
import base64
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QPushButton, QMessageBox, QTableWidget, 
                            QTableWidgetItem, QDialog, QFormLayout, QTextEdit, QFileDialog,
                            QProgressBar, QGroupBox, QTabWidget, QHeaderView, QToolBar, QAction,
                            QStatusBar, QSplashScreen, QInputDialog)
from PyQt5.QtGui import QIcon, QPixmap, QFont, QColor, QPalette, QBrush, QImage, QPainter
from PyQt5.QtCore import Qt, QTimer, QRect, QSize, QThread, pyqtSignal, QPoint

class AppPaths:
    def __init__(self):
        # Define application name
        self.app_name = "SecureCredentialsManager"
        
        # Get the base directory
        if getattr(sys, 'frozen', False):
            # If the application is run as a bundle (compiled with PyInstaller)
            self.base_dir = os.path.dirname(sys.executable)
        else:
            # If running as a script
            self.base_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Create application data directory
        self.app_data_dir = os.path.join(self.base_dir, f"{self.app_name}Data")
        if not os.path.exists(self.app_data_dir):
            os.makedirs(self.app_data_dir)
        
        # Define paths for configuration and database
        self.config_path = os.path.join(self.app_data_dir, "config.json")
        self.db_path = os.path.join(self.app_data_dir, "credentials.db")
    
    def get_config_path(self):
        return self.config_path
    
    def get_db_path(self):
        return self.db_path
    
    def get_app_data_dir(self):
        return self.app_data_dir

class OldStyleProgressDialog(QDialog):
    def __init__(self, title, parent=None):
        super(OldStyleProgressDialog, self).__init__(parent)
        self.setWindowTitle(title)
        self.setFixedSize(300, 100)
        
        # Windows 95 style
        self.setStyleSheet("""
            QDialog {
                background-color: #c0c0c0;
                border: 2px solid #808080;
            }
            QLabel {
                color: #000000;
                font-family: 'MS Sans Serif', Arial;
                font-size: 8pt;
            }
            QProgressBar {
                border: 1px solid #808080;
                border-radius: 0px;
                background-color: #ffffff;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #000080;
                width: 10px;
            }
        """)
        
        layout = QVBoxLayout()
        
        self.message_label = QLabel("Please wait...")
        layout.addWidget(self.message_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        self.setLayout(layout)
        
        # Animated progress timer
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_progress)
        self.timer.start(100)
        self.progress_value = 0
        
    def update_progress(self):
        self.progress_value = (self.progress_value + 5) % 101
        self.progress_bar.setValue(self.progress_value)
    
    def set_message(self, message):
        self.message_label.setText(message)
    
    def closeEvent(self, event):
        self.timer.stop()
        super().closeEvent(event)

class PasswordHasher:
    def __init__(self):
        self.iterations = 100000
        self.salt_length = 16
    
    def hash_password(self, password):
        # Generate a random salt
        salt = os.urandom(self.salt_length)
        
        # Create a hash of the password
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            self.iterations
        )
        
        # Combine the salt and hash for storage
        storage = salt + password_hash
        
        # Return a base64 encoded string of the combined salt and hash
        return base64.b64encode(storage).decode('utf-8')
    
    def verify_password(self, stored_password, provided_password):
        # Decode the base64 encoded string
        storage = base64.b64decode(stored_password.encode('utf-8'))
        
        # Extract the salt and stored hash
        salt = storage[:self.salt_length]
        stored_hash = storage[self.salt_length:]
        
        # Hash the provided password with the extracted salt
        hash_attempt = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            salt,
            self.iterations
        )
        
        # Compare the computed hash with the stored hash
        return hash_attempt == stored_hash
    
    def generate_encryption_key(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

class CredentialsDatabase:
    def __init__(self, db_path, master_password):
        self.db_path = db_path
        self.master_password = master_password
        self.encryptor = None
        self.setup_encryption()
        self.initialize_database()
    
    def setup_encryption(self):
        # Generate a key from the master password
        hasher = PasswordHasher()
        # We need to use the same salt for encryption and decryption
        # In a real application, this should be stored securely
        salt = b'SecureCredManager'
        key, _ = hasher.generate_encryption_key(self.master_password, salt)
        self.encryptor = Fernet(key)
    
    def initialize_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables if they don't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY,
            title TEXT,
            username TEXT,
            password TEXT,
            url TEXT,
            notes TEXT,
            category TEXT,
            date_created TEXT,
            date_modified TEXT
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def encrypt_data(self, data):
        if data is None:
            return None
        return self.encryptor.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data):
        if encrypted_data is None:
            return None
        return self.encryptor.decrypt(encrypted_data.encode()).decode()
    
    def add_credential(self, title, username, password, url, notes, category):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Encrypt sensitive data
        encrypted_username = self.encrypt_data(username)
        encrypted_password = self.encrypt_data(password)
        encrypted_url = self.encrypt_data(url)
        encrypted_notes = self.encrypt_data(notes)
        
        current_time = time.strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute('''
        INSERT INTO credentials (title, username, password, url, notes, category, date_created, date_modified)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (title, encrypted_username, encrypted_password, encrypted_url, encrypted_notes, category, current_time, current_time))
        
        conn.commit()
        conn.close()
    
    def get_all_credentials(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, title, username, password, url, notes, category, date_created, date_modified FROM credentials')
        credentials = cursor.fetchall()
        
        # Decrypt the data
        decrypted_credentials = []
        for cred in credentials:
            cred_id, title, username, password, url, notes, category, date_created, date_modified = cred
            decrypted_credentials.append((
                cred_id,
                title,
                self.decrypt_data(username) if username else "",
                self.decrypt_data(password) if password else "",
                self.decrypt_data(url) if url else "",
                self.decrypt_data(notes) if notes else "",
                category,
                date_created,
                date_modified
            ))
        
        conn.close()
        return decrypted_credentials
    
    def get_credential_by_id(self, cred_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, title, username, password, url, notes, category, date_created, date_modified FROM credentials WHERE id = ?', (cred_id,))
        cred = cursor.fetchone()
        
        conn.close()
        
        if cred:
            cred_id, title, username, password, url, notes, category, date_created, date_modified = cred
            return (
                cred_id,
                title,
                self.decrypt_data(username) if username else "",
                self.decrypt_data(password) if password else "",
                self.decrypt_data(url) if url else "",
                self.decrypt_data(notes) if notes else "",
                category,
                date_created,
                date_modified
            )
        return None
    
    def update_credential(self, cred_id, title, username, password, url, notes, category):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Encrypt sensitive data
        encrypted_username = self.encrypt_data(username)
        encrypted_password = self.encrypt_data(password)
        encrypted_url = self.encrypt_data(url)
        encrypted_notes = self.encrypt_data(notes)
        
        current_time = time.strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute('''
        UPDATE credentials
        SET title = ?, username = ?, password = ?, url = ?, notes = ?, category = ?, date_modified = ?
        WHERE id = ?
        ''', (title, encrypted_username, encrypted_password, encrypted_url, encrypted_notes, category, current_time, cred_id))
        
        conn.commit()
        conn.close()
    
    def delete_credential(self, cred_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM credentials WHERE id = ?', (cred_id,))
        
        conn.commit()
        conn.close()
    
    def export_credentials_to_file(self, file_path):
        credentials = self.get_all_credentials()
        
        with open(file_path, 'w') as f:
            f.write("=== Secure Credentials Manager Export ===\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            for cred in credentials:
                f.write(f"Title: {cred[1]}\n")
                f.write(f"Username: {cred[2]}\n")
                f.write(f"Password: {cred[3]}\n")
                f.write(f"URL: {cred[4]}\n")
                f.write(f"Category: {cred[6]}\n")
                f.write(f"Created: {cred[7]}\n")
                f.write(f"Modified: {cred[8]}\n")
                f.write(f"Notes:\n{cred[5]}\n")
                f.write("\n" + "="*40 + "\n\n")

class ConfigManager:
    def __init__(self, config_path):
        self.config_path = config_path
        self.config = {}
        self.load_config()
    
    def load_config(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
            except:
                self.config = {}
        else:
            self.config = {}
            self.save_config()
    
    def save_config(self):
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=4)
    
    def get(self, key, default=None):
        return self.config.get(key, default)
    
    def set(self, key, value):
        self.config[key] = value
        self.save_config()

class SetupDialog(QDialog):
    def __init__(self, parent=None):
        super(SetupDialog, self).__init__(parent)
        self.setWindowTitle("Setup Master Password")
        self.setFixedSize(350, 200)
        
        # Windows 95 style
        self.setStyleSheet("""
            QDialog {
                background-color: #c0c0c0;
                border: 2px solid #808080;
            }
            QLabel {
                color: #000000;
                font-family: 'MS Sans Serif', Arial;
                font-size: 8pt;
            }
            QLineEdit {
                border: 1px solid #808080;
                border-radius: 0px;
                background-color: #ffffff;
                padding: 2px;
                font-family: 'MS Sans Serif', Arial;
                font-size: 8pt;
            }
            QPushButton {
                background-color: #c0c0c0;
                border: 2px outset #d3d3d3;
                border-top-color: #ffffff;
                border-left-color: #ffffff;
                padding: 3px;
                font-family: 'MS Sans Serif', Arial;
                font-size: 8pt;
            }
            QPushButton:pressed {
                border: 2px inset #d3d3d3;
                border-bottom-color: #ffffff;
                border-right-color: #ffffff;
            }
        """)
        
        layout = QVBoxLayout()
        
        welcome_label = QLabel("Welcome to Secure Credentials Manager!")
        welcome_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(welcome_label)
        
        instruction_label = QLabel("Please set up your master password. This password will be used to encrypt and decrypt your credentials.")
        instruction_label.setWordWrap(True)
        layout.addWidget(instruction_label)
        
        form_layout = QFormLayout()
        
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        form_layout.addRow("Master Password:", self.password_edit)
        
        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.Password)
        form_layout.addRow("Confirm Password:", self.confirm_password_edit)
        
        layout.addLayout(form_layout)
        
        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: red;")
        layout.addWidget(self.error_label)
        
        button_layout = QHBoxLayout()
        self.setup_button = QPushButton("Setup")
        self.setup_button.clicked.connect(self.check_passwords)
        button_layout.addWidget(self.setup_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def check_passwords(self):
        password = self.password_edit.text()
        confirm_password = self.confirm_password_edit.text()
        
        if password == "":
            self.error_label.setText("Password cannot be empty")
            return
        
        if password != confirm_password:
            self.error_label.setText("Passwords do not match")
            return
        
        self.accept()
    
    def get_password(self):
        return self.password_edit.text()

class LoginDialog(QDialog):
    def __init__(self, stored_hash, parent=None):
        super(LoginDialog, self).__init__(parent)
        self.setWindowTitle("Enter Master Password")
        self.setFixedSize(300, 150)
        self.stored_hash = stored_hash
        self.password_hasher = PasswordHasher()
        
        # Windows 95 style
        self.setStyleSheet("""
            QDialog {
                background-color: #c0c0c0;
                border: 2px solid #808080;
            }
            QLabel {
                color: #000000;
                font-family: 'MS Sans Serif', Arial;
                font-size: 8pt;
            }
            QLineEdit {
                border: 1px solid #808080;
                border-radius: 0px;
                background-color: #ffffff;
                padding: 2px;
                font-family: 'MS Sans Serif', Arial;
                font-size: 8pt;
            }
            QPushButton {
                background-color: #c0c0c0;
                border: 2px outset #d3d3d3;
                border-top-color: #ffffff;
                border-left-color: #ffffff;
                padding: 3px;
                font-family: 'MS Sans Serif', Arial;
                font-size: 8pt;
            }
            QPushButton:pressed {
                border: 2px inset #d3d3d3;
                border-bottom-color: #ffffff;
                border-right-color: #ffffff;
            }
        """)
        
        layout = QVBoxLayout()
        
        instruction_label = QLabel("Please enter your master password to unlock your credentials.")
        instruction_label.setWordWrap(True)
        layout.addWidget(instruction_label)
        
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_edit)
        
        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: red;")
        layout.addWidget(self.error_label)
        
        button_layout = QHBoxLayout()
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.check_password)
        button_layout.addWidget(self.login_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Set focus to password field
        self.password_edit.setFocus()
    
    def check_password(self):
        provided_password = self.password_edit.text()
        
        if provided_password == "":
            self.error_label.setText("Password cannot be empty")
            return
        
        if self.password_hasher.verify_password(self.stored_hash, provided_password):
            self.accept()
        else:
            self.error_label.setText("Incorrect password")
            self.password_edit.clear()
            self.password_edit.setFocus()
    
    def get_password(self):
        return self.password_edit.text()

class CredentialDialog(QDialog):
    def __init__(self, parent=None, credential=None):
        super(CredentialDialog, self).__init__(parent)
        self.setWindowTitle("Credential" if credential else "Add New Credential")
        self.setFixedSize(400, 450)
        self.credential = credential
        
        # Windows 95 style
        self.setStyleSheet("""
            QDialog {
                background-color: #c0c0c0;
                border: 2px solid #808080;
            }
            QLabel {
                color: #000000;
                font-family: 'MS Sans Serif', Arial;
                font-size: 8pt;
            }
            QLineEdit, QTextEdit {
                border: 1px solid #808080;
                border-radius: 0px;
                background-color: #ffffff;
                padding: 2px;
                font-family: 'MS Sans Serif', Arial;
                font-size: 8pt;
            }
            QPushButton {
                background-color: #c0c0c0;
                border: 2px outset #d3d3d3;
                border-top-color: #ffffff;
                border-left-color: #ffffff;
                padding: 3px;
                font-family: 'MS Sans Serif', Arial;
                font-size: 8pt;
            }
            QPushButton:pressed {
                border: 2px inset #d3d3d3;
                border-bottom-color: #ffffff;
                border-right-color: #ffffff;
            }
        """)
        
        layout = QVBoxLayout()
        
        form_layout = QFormLayout()
        
        self.title_edit = QLineEdit()
        form_layout.addRow("Title:", self.title_edit)
        
        self.username_edit = QLineEdit()
        form_layout.addRow("Username:", self.username_edit)
        
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        password_layout = QHBoxLayout()
        password_layout.addWidget(self.password_edit)
        self.show_password_button = QPushButton("Show")
        self.show_password_button.setFixedWidth(60)
        self.show_password_button.pressed.connect(lambda: self.password_edit.setEchoMode(QLineEdit.Normal))
        self.show_password_button.released.connect(lambda: self.password_edit.setEchoMode(QLineEdit.Password))
        password_layout.addWidget(self.show_password_button)
        form_layout.addRow("Password:", password_layout)
        
        self.url_edit = QLineEdit()
        form_layout.addRow("URL:", self.url_edit)
        
        self.category_edit = QLineEdit()
        form_layout.addRow("Category:", self.category_edit)
        
        layout.addLayout(form_layout)
        
        notes_label = QLabel("Notes:")
        layout.addWidget(notes_label)
        
        self.notes_edit = QTextEdit()
        layout.addWidget(self.notes_edit)
        
        button_layout = QHBoxLayout()
        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.accept)
        button_layout.addWidget(self.save_button)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # If editing existing credential, populate fields
        if credential:
            cred_id, title, username, password, url, notes, category, _, _ = credential
            self.title_edit.setText(title)
            self.username_edit.setText(username)
            self.password_edit.setText(password)
            self.url_edit.setText(url)
            self.notes_edit.setText(notes)
            self.category_edit.setText(category)
    
    def get_credential_data(self):
        return {
            'title': self.title_edit.text(),
            'username': self.username_edit.text(),
            'password': self.password_edit.text(),
            'url': self.url_edit.text(),
            'notes': self.notes_edit.toPlainText(),
            'category': self.category_edit.text()
        }

class MainWindow(QMainWindow):
    def __init__(self, config_manager, db_path, master_password):
        super(MainWindow, self).__init__()
        
        self.config_manager = config_manager
        self.db = CredentialsDatabase(db_path, master_password)
        self.master_password = master_password
        
        self.init_ui()
        self.load_credentials()
        
        # Center the window
        self.center_on_screen()


    def copy_to_clipboard(self, text):
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
    
    def init_ui(self):
        self.setWindowTitle("Secure Credentials Manager")
        self.setMinimumSize(800, 600)
        
        # Windows 95 style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #c0c0c0;
            }
            QTableWidget {
                background-color: #ffffff;
                border: 1px solid #808080;
                gridline-color: #d3d3d3;
                selection-background-color: #000080;
                selection-color: #ffffff;
            }
            QTableWidget::item {
                padding: 2px;
            }
            QHeaderView::section {
                background-color: #c0c0c0;
                border: 1px solid #808080;
                padding: 4px;
                font-family: 'MS Sans Serif', Arial;
                font-size: 8pt;
            }
            QLabel, QTabWidget, QTableWidget {
                font-family: 'MS Sans Serif', Arial;
                font-size: 8pt;
            }
            QPushButton {
                background-color: #c0c0c0;
                border: 2px outset #d3d3d3;
                border-top-color: #ffffff;
                border-left-color: #ffffff;
                padding: 3px;
                font-family: 'MS Sans Serif', Arial;
                font-size: 8pt;
            }
            QPushButton:pressed {
                border: 2px inset #d3d3d3;
                border-bottom-color: #ffffff;
                border-right-color: #ffffff;
            }
            QToolBar {
                background-color: #c0c0c0;
                border: 1px solid #808080;
                spacing: 3px;
            }
            QStatusBar {
                background-color: #c0c0c0;
                border-top: 1px solid #808080;
            }
            QTabWidget::pane {
                border: 1px solid #808080;
            }
            QTabBar::tab {
                background-color: #c0c0c0;
                border: 1px solid #808080;
                padding: 4px;
                font-family: 'MS Sans Serif', Arial;
                font-size: 8pt;
            }
            QTabBar::tab:selected {
                background-color: #d3d3d3;
                border-bottom-color: #d3d3d3;
            }
        """)
        
        # Create toolbar
        toolbar = QToolBar("Main Toolbar")
        self.addToolBar(toolbar)
        
        # Add action
        add_action = QAction("Add New", self)
        add_action.triggered.connect(self.add_credential)
        toolbar.addAction(add_action)
        
        # Edit action
        edit_action = QAction("Edit", self)
        edit_action.triggered.connect(self.edit_credential)
        toolbar.addAction(edit_action)
        
        # Delete action
        delete_action = QAction("Delete", self)
        delete_action.triggered.connect(self.delete_credential)
        toolbar.addAction(delete_action)
        
        toolbar.addSeparator()
        
        # Export action
        export_action = QAction("Export", self)
        export_action.triggered.connect(self.export_credentials)
        toolbar.addAction(export_action)
        
        # Search action
        search_action = QAction("Search", self)
        search_action.triggered.connect(self.search_credentials)
        toolbar.addAction(search_action)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)
        
        # Create credentials tab
        credentials_tab = QWidget()
        tab_widget.addTab(credentials_tab, "Credentials")
        
        # Credentials tab layout
        credentials_layout = QVBoxLayout(credentials_tab)
        
        # Create table widget for credentials
        self.table_widget = QTableWidget()
        self.table_widget.setColumnCount(5)
        self.table_widget.setHorizontalHeaderLabels(["Title", "Username", "URL", "Category", "Modified"])
        self.table_widget.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table_widget.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table_widget.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table_widget.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_widget.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table_widget.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_widget.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table_widget.cellDoubleClicked.connect(self.view_credential_details)
        
        credentials_layout.addWidget(self.table_widget)
        
        # Create status bar
        status_bar = QStatusBar()
        self.setStatusBar(status_bar)
        self.status_label = QLabel("Ready")
        status_bar.addWidget(self.status_label)
    
    def center_on_screen(self):
        frame_geometry = self.frameGeometry()
        center_point = self.screen().availableGeometry().center()
        frame_geometry.moveCenter(center_point)
        self.move(frame_geometry.topLeft())
    
    def load_credentials(self):
        # Show loading progress dialog
        progress_dialog = OldStyleProgressDialog("Loading Credentials", self)
        progress_dialog.set_message("Loading credentials from database...")
        progress_dialog.show()
        
        QApplication.processEvents()
        
        # Simulate loading delay
        time.sleep(1)
        
        # Get credentials from database
        credentials = self.db.get_all_credentials()
        
        # Clear the table
        self.table_widget.setRowCount(0)
        
        # Populate the table
        for cred in credentials:
            cred_id, title, username, password, url, notes, category, date_created, date_modified = cred
            
            row_position = self.table_widget.rowCount()
            self.table_widget.insertRow(row_position)
            
            self.table_widget.setItem(row_position, 0, QTableWidgetItem(title))
            self.table_widget.setItem(row_position, 1, QTableWidgetItem(username))
            self.table_widget.setItem(row_position, 2, QTableWidgetItem(url))
            self.table_widget.setItem(row_position, 3, QTableWidgetItem(category))
            self.table_widget.setItem(row_position, 4, QTableWidgetItem(date_modified))
            
            # Store credential ID as hidden data in first column
            self.table_widget.item(row_position, 0).setData(Qt.UserRole, cred_id)
        
        progress_dialog.close()
        
        # Update status
        self.status_label.setText(f"Loaded {self.table_widget.rowCount()} credentials")
    
    def add_credential(self):
        dialog = CredentialDialog(self)
        if dialog.exec_():
            credential_data = dialog.get_credential_data()
            
            # Show progress dialog
            progress_dialog = OldStyleProgressDialog("Adding Credential", self)
            progress_dialog.set_message("Saving credential to database...")
            progress_dialog.show()
            
            QApplication.processEvents()
            
            # Simulate processing delay
            time.sleep(1)
            
            # Add to database
            self.db.add_credential(
                credential_data['title'],
                credential_data['username'],
                credential_data['password'],
                credential_data['url'],
                credential_data['notes'],
                credential_data['category']
            )
            
            progress_dialog.close()
            
            # Reload credentials
            self.load_credentials()
    
    def edit_credential(self):
        selected_rows = self.table_widget.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select a credential to edit.")
            return
        
        # Get the credential ID from the selected row
        cred_id = self.table_widget.item(selected_rows[0].row(), 0).data(Qt.UserRole)
        
        # Get credential data
        credential = self.db.get_credential_by_id(cred_id)
        
        dialog = CredentialDialog(self, credential)
        if dialog.exec_():
            credential_data = dialog.get_credential_data()
            
            # Show progress dialog
            progress_dialog = OldStyleProgressDialog("Updating Credential", self)
            progress_dialog.set_message("Saving changes to database...")
            progress_dialog.show()
            
            QApplication.processEvents()
            
            # Simulate processing delay
            time.sleep(1)
            
            # Update in database
            self.db.update_credential(
                cred_id,
                credential_data['title'],
                credential_data['username'],
                credential_data['password'],
                credential_data['url'],
                credential_data['notes'],
                credential_data['category']
            )
            
            progress_dialog.close()
            
            # Reload credentials
            self.load_credentials()
    
    def delete_credential(self):
        selected_rows = self.table_widget.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select a credential to delete.")
            return
        
        # Get the credential ID from the selected row
        cred_id = self.table_widget.item(selected_rows[0].row(), 0).data(Qt.UserRole)
        title = self.table_widget.item(selected_rows[0].row(), 0).text()
        
        # Confirm deletion
        confirm = QMessageBox.question(self, "Confirm Deletion", 
                                    f"Are you sure you want to delete the credential '{title}'?",
                                    QMessageBox.Yes | QMessageBox.No)
        
        if confirm == QMessageBox.Yes:
            # Show progress dialog
            progress_dialog = OldStyleProgressDialog("Deleting Credential", self)
            progress_dialog.set_message("Removing credential from database...")
            progress_dialog.show()
            
            QApplication.processEvents()
            
            # Simulate processing delay
            time.sleep(1)
            
            # Delete from database
            self.db.delete_credential(cred_id)
            
            progress_dialog.close()
            
            # Reload credentials
            self.load_credentials()
    
    def view_credential_details(self, row, column):
        # Get the credential ID from the selected row
        cred_id = self.table_widget.item(row, 0).data(Qt.UserRole)
        
        # Get credential data
        credential = self.db.get_credential_by_id(cred_id)
        
        if credential:
            cred_id, title, username, password, url, notes, category, date_created, date_modified = credential
            
            detail_text = f"Title: {title}\n"
            detail_text += f"Username: {username}\n"
            detail_text += f"Password: {(password)}\n"
            detail_text += f"URL: {url}\n"
            detail_text += f"Category: {category}\n"
            detail_text += f"Created: {date_created}\n"
            detail_text += f"Modified: {date_modified}\n\n"
            detail_text += f"Notes:\n{notes}"
            
            detail_dialog = QDialog(self)
            detail_dialog.setWindowTitle(f"Credential: {title}")
            detail_dialog.setFixedSize(400, 350)
            
            # Windows 95 style
            detail_dialog.setStyleSheet("""
                QDialog {
                    background-color: #c0c0c0;
                    border: 2px solid #808080;
                }
                QLabel {
                    color: #000000;
                    font-family: 'MS Sans Serif', Arial;
                    font-size: 8pt;
                }
                QTextEdit {
                    border: 1px solid #808080;
                    border-radius: 0px;
                    background-color: #ffffff;
                    padding: 2px;
                    font-family: 'MS Sans Serif', Arial;
                    font-size: 8pt;
                }
                QPushButton {
                    background-color: #c0c0c0;
                    border: 2px outset #d3d3d3;
                    border-top-color: #ffffff;
                    border-left-color: #ffffff;
                    padding: 3px;
                    font-family: 'MS Sans Serif', Arial;
                    font-size: 8pt;
                }
                QPushButton:pressed {
                    border: 2px inset #d3d3d3;
                    border-bottom-color: #ffffff;
                    border-right-color: #ffffff;
                }
            """)
            
            layout = QVBoxLayout(detail_dialog)
            
            detail_text_edit = QTextEdit()
            detail_text_edit.setReadOnly(True)
            detail_text_edit.setText(detail_text)
            layout.addWidget(detail_text_edit)
            
            button_layout = QHBoxLayout()
            
            # Add view password button
            view_password_button = QPushButton("View Password")
            
            def show_password():
                password_dialog = QDialog(detail_dialog)
                password_dialog.setWindowTitle("Password")
                password_dialog.setMaximumSize(1280, 720)
                
                password_dialog.setStyleSheet("""
                    QDialog {
                        background-color: #c0c0c0;
                        border: 2px solid #808080;
                    }
                    QLabel {
                        color: #000000;
                        font-family: 'MS Sans Serif', Arial;
                        font-size: 8pt;
                    }
                    QPushButton {
                        background-color: #c0c0c0;
                        border: 2px outset #d3d3d3;
                        border-top-color: #ffffff;
                        border-left-color: #ffffff;
                        padding: 3px;
                        font-family: 'MS Sans Serif', Arial;
                        font-size: 8pt;
                    }
                """)
                
                password_layout = QVBoxLayout(password_dialog)
                password_label = QLabel(f"Password: {password}")
                password_layout.addWidget(password_label)
                
               
                

                ok_button = QPushButton("OK")
                ok_button.clicked.connect(password_dialog.accept)
                password_layout.addWidget(ok_button)
                
                password_dialog.exec_()


            

           
            
            view_password_button.clicked.connect(show_password)
            button_layout.addWidget(view_password_button)
            
            
            # Add edit button
            edit_button = QPushButton("Edit")
            edit_button.clicked.connect(lambda: self.edit_credential_from_detail(detail_dialog, credential))
            button_layout.addWidget(edit_button)
            
            # Add close button
            close_button = QPushButton("Close")
            close_button.clicked.connect(detail_dialog.accept)
            button_layout.addWidget(close_button)
            
            layout.addLayout(button_layout)
            
            detail_dialog.exec_()
    
    def edit_credential_from_detail(self, detail_dialog, credential):
        detail_dialog.accept()
        dialog = CredentialDialog(self, credential)
        if dialog.exec_():
            credential_data = dialog.get_credential_data()
            
            # Show progress dialog
            progress_dialog = OldStyleProgressDialog("Updating Credential", self)
            progress_dialog.set_message("Saving changes to database...")
            progress_dialog.show()
            
            QApplication.processEvents()
            
            # Simulate processing delay
            time.sleep(1)
            
            # Update in database
            self.db.update_credential(
                credential[0],  # Credential ID
                credential_data['title'],
                credential_data['username'],
                credential_data['password'],
                credential_data['url'],
                credential_data['notes'],
                credential_data['category']
            )
            
            progress_dialog.close()
            
            # Reload credentials
            self.load_credentials()
    
    def export_credentials(self):
        # Ask for master password confirmation first
        password, ok = QInputDialog.getText(
            self, "Master Password Confirmation", 
            "Please enter your master password to export credentials:",
            QLineEdit.Password
        )
        
        if not ok or password == "":
            return
        
        password_hasher = PasswordHasher()
        stored_hash = self.config_manager.get("master_password_hash")
        
        if not password_hasher.verify_password(stored_hash, password):
            QMessageBox.warning(self, "Authentication Failed", "Incorrect master password.")
            return
        
        # Get export file path
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Credentials", "", "Text Files (*.txt)"
        )
        
        if file_path:
            # Show progress dialog
            progress_dialog = OldStyleProgressDialog("Exporting Credentials", self)
            progress_dialog.set_message("Exporting credentials to file...")
            progress_dialog.show()
            
            QApplication.processEvents()
            
            # Simulate processing delay
            time.sleep(1)
            
            # Export credentials
            self.db.export_credentials_to_file(file_path)
            
            progress_dialog.close()
            
            QMessageBox.information(self, "Export Complete", "Credentials exported successfully.")
    
    def search_credentials(self):
        search_text, ok = QInputDialog.getText(
            self, "Search Credentials", 
            "Enter search term:"
        )
        
        if not ok or search_text == "":
            return
        
        # Show loading progress dialog
        progress_dialog = OldStyleProgressDialog("Searching", self)
        progress_dialog.set_message("Searching credentials...")
        progress_dialog.show()
        
        QApplication.processEvents()
        
        # Simulate search delay
        time.sleep(1)
        
        # Get all credentials
        credentials = self.db.get_all_credentials()
        
        # Filter credentials based on search term
        search_term = search_text.lower()
        filtered_credentials = []
        
        for cred in credentials:
            cred_id, title, username, password, url, notes, category, date_created, date_modified = cred
            
            if (search_term in title.lower() or
                search_term in username.lower() or
                search_term in url.lower() or
                search_term in notes.lower() or
                search_term in category.lower()):
                filtered_credentials.append(cred)
        
        # Clear the table
        self.table_widget.setRowCount(0)
        
        # Populate the table with filtered results
        for cred in filtered_credentials:
            cred_id, title, username, password, url, notes, category, date_created, date_modified = cred
            
            row_position = self.table_widget.rowCount()
            self.table_widget.insertRow(row_position)
            
            self.table_widget.setItem(row_position, 0, QTableWidgetItem(title))
            self.table_widget.setItem(row_position, 1, QTableWidgetItem(username))
            self.table_widget.setItem(row_position, 2, QTableWidgetItem(url))
            self.table_widget.setItem(row_position, 3, QTableWidgetItem(category))
            self.table_widget.setItem(row_position, 4, QTableWidgetItem(date_modified))
            
            # Store credential ID as hidden data in first column
            self.table_widget.item(row_position, 0).setData(Qt.UserRole, cred_id)
        
        progress_dialog.close()
        
        # Update status
        self.status_label.setText(f"Found {self.table_widget.rowCount()} matching credentials")

class SplashScreen(QSplashScreen):
    def __init__(self):
        splash_pixmap = QPixmap(400, 300)
        splash_pixmap.fill(QColor("#c0c0c0"))
        
        super(SplashScreen, self).__init__(splash_pixmap)
        
        # Draw the splash screen content
        painter = QPainter(splash_pixmap)
        painter.setPen(Qt.black)
        painter.setFont(QFont("MS Sans Serif", 14))
        painter.drawText(QRect(0, 100, 400, 50), Qt.AlignCenter, "Secure Credentials Manager")
        painter.setFont(QFont("MS Sans Serif", 8))
        painter.drawText(QRect(0, 150, 400, 50), Qt.AlignCenter, "Loading...")
        painter.end()
        
        self.setPixmap(splash_pixmap)
        
        # Create progress bar
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setGeometry(50, 200, 300, 20)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #808080;
                border-radius: 0px;
                background-color: #ffffff;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #000080;
                width: 10px;
            }
        """)
        
        # Progress timer
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_progress)
        self.progress_value = 0
    
    def update_progress(self):
        self.progress_value += 5
        self.progress_bar.setValue(self.progress_value)
        
        # Display messages based on progress
        if self.progress_value == 20:
            self.showMessage("Initializing application...", Qt.AlignBottom | Qt.AlignCenter, Qt.black)
        elif self.progress_value == 40:
            self.showMessage("Loading configuration...", Qt.AlignBottom | Qt.AlignCenter, Qt.black)
        elif self.progress_value == 60:
            self.showMessage("Checking database...", Qt.AlignBottom | Qt.AlignCenter, Qt.black)
        elif self.progress_value == 80:
            self.showMessage("Almost ready...", Qt.AlignBottom | Qt.AlignCenter, Qt.black)
        
        if self.progress_value >= 100:
            self.timer.stop()
    
    def start_progress(self):
        self.timer.start(100)

def main():
    app = QApplication(sys.argv)
    
    # Create splash screen
    splash = SplashScreen()
    splash.show()
    splash.start_progress()
    
    # Process events to show splash screen
    app.processEvents()
    
    # Initialize paths
    app_paths = AppPaths()
    
    # Initialize configuration
    config_manager = ConfigManager(app_paths.get_config_path())
    
    # Check master password
    master_password_hash = config_manager.get("master_password_hash")
    
    # Simulate loading
    time.sleep(2)
    
    if master_password_hash is None:
        # First time setup
        setup_dialog = SetupDialog()
        result = setup_dialog.exec_()
        
        if result == QDialog.Accepted:
            # Hash and store master password
            password_hasher = PasswordHasher()
            master_password = setup_dialog.get_password()
            master_password_hash = password_hasher.hash_password(master_password)
            config_manager.set("master_password_hash", master_password_hash)
            
            # Create main window
            main_window = MainWindow(config_manager, app_paths.get_db_path(), master_password)
            splash.finish(main_window)
            main_window.show()
        else:
            # User canceled setup
            return
    else:
        # Login
        login_dialog = LoginDialog(master_password_hash)
        result = login_dialog.exec_()
        
        if result == QDialog.Accepted:
            # Create main window
            master_password = login_dialog.get_password()
            main_window = MainWindow(config_manager, app_paths.get_db_path(), master_password)
            splash.finish(main_window)
            main_window.show()
        else:
            # User canceled login
            return
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()