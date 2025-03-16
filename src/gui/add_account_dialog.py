"""
AddAccountDialog for TrueFA-Py GUI

Dialog for adding new TOTP accounts manually or via QR code
"""

import os
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTabWidget, QWidget,
                            QFileDialog, QMessageBox)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QPixmap, QImage

class AddAccountDialog(QDialog):
    """
    Dialog for adding new TOTP accounts
    
    Signals:
        account_added: Emitted when an account is added
            Parameters: account_data (dict)
    """
    
    # Signal emitted when an account is added
    account_added = pyqtSignal(dict)
    
    def __init__(self, totp_auth, parent=None):
        super().__init__(parent)
        
        # Store references
        self.totp_auth = totp_auth
        self.qr_image_path = None
        self.extracted_data = None
        
        # Set up dialog properties
        self.setWindowTitle("Add New Account")
        self.setMinimumWidth(500)
        self.setModal(True)
        
        # Create layout
        main_layout = QVBoxLayout(self)
        
        # Create tab widget
        tab_widget = QTabWidget()
        
        # Create tabs
        manual_tab = self.create_manual_tab()
        qr_tab = self.create_qr_tab()
        
        # Add tabs to widget
        tab_widget.addTab(manual_tab, "Manual Entry")
        tab_widget.addTab(qr_tab, "QR Code")
        
        # Add tab widget to main layout
        main_layout.addWidget(tab_widget)
    
    def create_manual_tab(self):
        """Create the manual entry tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Account name field
        layout.addWidget(QLabel("Account Name:"))
        self.account_name_input = QLineEdit()
        self.account_name_input.setPlaceholderText("e.g., personal@example.com")
        layout.addWidget(self.account_name_input)
        
        # Issuer field
        layout.addWidget(QLabel("Issuer (Optional):"))
        self.issuer_input = QLineEdit()
        self.issuer_input.setPlaceholderText("e.g., GitHub")
        layout.addWidget(self.issuer_input)
        
        # Secret key field
        layout.addWidget(QLabel("Secret Key:"))
        self.secret_input = QLineEdit()
        self.secret_input.setPlaceholderText("e.g., JBSWY3DPEHPK3PXP")
        layout.addWidget(self.secret_input)
        
        # Buttons
        buttons_layout = QHBoxLayout()
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        
        add_button = QPushButton("Add Account")
        add_button.clicked.connect(self.on_manual_add)
        add_button.setStyleSheet("""
            QPushButton {
                background-color: #4285F4;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3275E4;
            }
        """)
        
        buttons_layout.addWidget(cancel_button)
        buttons_layout.addStretch(1)
        buttons_layout.addWidget(add_button)
        
        layout.addSpacing(20)
        layout.addLayout(buttons_layout)
        
        return tab
    
    def create_qr_tab(self):
        """Create the QR code tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Instructions
        layout.addWidget(QLabel("Select a QR code image file to scan:"))
        
        # Image preview
        self.image_preview = QLabel("No image selected")
        self.image_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_preview.setMinimumHeight(200)
        self.image_preview.setStyleSheet("border: 1px solid #cccccc; background-color: #f0f0f0;")
        layout.addWidget(self.image_preview)
        
        # QR code info (after scanning)
        self.qr_info = QLabel("")
        layout.addWidget(self.qr_info)
        
        # Action buttons
        select_layout = QHBoxLayout()
        
        select_button = QPushButton("Select Image")
        select_button.clicked.connect(self.on_select_image)
        
        scan_button = QPushButton("Scan QR Code")
        scan_button.clicked.connect(self.on_scan_qr)
        
        select_layout.addWidget(select_button)
        select_layout.addStretch(1)
        select_layout.addWidget(scan_button)
        
        layout.addLayout(select_layout)
        
        # Buttons
        buttons_layout = QHBoxLayout()
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        
        add_button = QPushButton("Add Account")
        add_button.clicked.connect(self.on_qr_add)
        add_button.setEnabled(False)
        self.qr_add_button = add_button
        
        buttons_layout.addWidget(cancel_button)
        buttons_layout.addStretch(1)
        buttons_layout.addWidget(add_button)
        
        layout.addSpacing(20)
        layout.addLayout(buttons_layout)
        
        return tab
    
    def on_manual_add(self):
        """Handle manual account addition"""
        # Get input values
        account = self.account_name_input.text().strip()
        issuer = self.issuer_input.text().strip()
        secret = self.secret_input.text().strip().replace(" ", "")
        
        # Validate inputs
        if not account:
            QMessageBox.warning(self, "Input Error", "Please enter an account name.")
            return
        
        if not secret:
            QMessageBox.warning(self, "Input Error", "Please enter a secret key.")
            return
        
        try:
            # Validate secret format
            if not self.totp_auth.validate_totp_secret(secret):
                QMessageBox.warning(self, "Input Error", "Invalid secret key format. Please check your input.")
                return
            
            # Test generate a TOTP
            self.totp_auth.generate_totp(secret)
            
            # Create account data
            account_data = {
                "account": account,
                "issuer": issuer,
                "secret": secret,
                "method": "manual"
            }
            
            # Emit signal with account data
            self.account_added.emit(account_data)
            
            # Close dialog
            self.accept()
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create account: {str(e)}")
    
    def on_select_image(self):
        """Open file dialog to select QR code image"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select QR Code Image",
            "",
            "Image Files (*.png *.jpg *.jpeg *.bmp *.gif)"
        )
        
        if not file_path:
            return
        
        try:
            # Store the path
            self.qr_image_path = file_path
            
            # Display image preview
            pixmap = QPixmap(file_path)
            if not pixmap.isNull():
                pixmap = pixmap.scaled(300, 300, Qt.AspectRatioMode.KeepAspectRatio)
                self.image_preview.setPixmap(pixmap)
                self.image_preview.setText("")
            else:
                self.image_preview.setText("Failed to load image")
                self.qr_image_path = None
            
            # Reset QR info and button
            self.qr_info.setText("")
            self.qr_add_button.setEnabled(False)
            self.extracted_data = None
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load image: {str(e)}")
            self.qr_image_path = None
    
    def on_scan_qr(self):
        """Scan QR code from selected image"""
        if not self.qr_image_path:
            QMessageBox.warning(self, "Error", "Please select an image first.")
            return
        
        try:
            # Try to extract TOTP data from QR code
            self.setCursor(Qt.CursorShape.WaitCursor)
            
            # Call the TOTP auth component to process the QR code
            result, error_msg = self.totp_auth.process_qr_code(self.qr_image_path)
            
            self.setCursor(Qt.CursorShape.ArrowCursor)
            
            if error_msg:
                QMessageBox.warning(self, "QR Code Error", error_msg)
                return
            
            if not result:
                QMessageBox.warning(self, "QR Code Error", "No valid TOTP data found in QR code.")
                return
            
            # Store the extracted data
            self.extracted_data = result
            
            # Display the extracted info
            account = result.get("account", "Unknown")
            issuer = result.get("issuer", "")
            info_text = f"Account: {account}\n"
            if issuer:
                info_text += f"Issuer: {issuer}\n"
            self.qr_info.setText(info_text)
            
            # Enable add button
            self.qr_add_button.setEnabled(True)
        
        except Exception as e:
            self.setCursor(Qt.CursorShape.ArrowCursor)
            QMessageBox.critical(self, "Error", f"Failed to scan QR code: {str(e)}")
    
    def on_qr_add(self):
        """Add account from scanned QR code data"""
        if not self.extracted_data:
            QMessageBox.warning(self, "Error", "No QR code data available. Please scan a QR code first.")
            return
        
        try:
            # Add method field to identify how this account was added
            self.extracted_data["method"] = "qr_code"
            
            # Emit signal with account data
            self.account_added.emit(self.extracted_data)
            
            # Close dialog
            self.accept()
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add account: {str(e)}") 