"""
AddAccountDialog for TrueFA-Py GUI

Dialog for adding new TOTP accounts manually or via QR code
"""

import os
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTabWidget, QWidget,
                            QFileDialog, QMessageBox, QFrame, QProgressBar)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QPixmap, QImage
import tempfile

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
        layout.addWidget(QLabel("Select a QR code image file or use camera to scan:"))
        
        # Image preview
        self.image_preview = QLabel("No image selected")
        self.image_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_preview.setMinimumHeight(200)
        self.image_preview.setStyleSheet("border: 1px solid #cccccc; background-color: #f0f0f0;")
        layout.addWidget(self.image_preview)
        
        # QR code info (after scanning)
        self.qr_info = QLabel("")
        layout.addWidget(self.qr_info)
        
        # TOTP Token display
        self.token_frame = QFrame()
        self.token_frame.setFrameShape(QFrame.Shape.StyledPanel)
        self.token_frame.setVisible(False)  # Initially hidden
        token_layout = QVBoxLayout(self.token_frame)
        
        self.token_label = QLabel("TOTP Token:")
        self.token_label.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        
        self.token_display = QLabel("------")
        self.token_display.setFont(QFont("Monospace", 24, QFont.Weight.Bold))
        self.token_display.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.token_display.setMinimumHeight(50)
        self.token_display.setStyleSheet("background-color: #f0f0f0; border-radius: 4px; padding: 8px;")
        
        # TOTP timer
        self.token_timer = QProgressBar()
        self.token_timer.setRange(0, 30)
        self.token_timer.setValue(30)
        
        token_layout.addWidget(self.token_label)
        token_layout.addWidget(self.token_display)
        token_layout.addWidget(self.token_timer)
        
        layout.addWidget(self.token_frame)
        
        # Action buttons
        select_layout = QHBoxLayout()
        
        select_button = QPushButton("Select Image")
        select_button.clicked.connect(self.on_select_image)
        
        camera_button = QPushButton("Scan from Camera")
        camera_button.clicked.connect(self.on_scan_from_camera)
        
        scan_button = QPushButton("Scan QR Code")
        scan_button.clicked.connect(self.on_scan_qr)
        
        select_layout.addWidget(select_button)
        select_layout.addWidget(camera_button)
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
        
        # Initialize camera variables
        self.camera = None
        self.camera_timer = None
        
        # Initialize TOTP update timer
        self.totp_update_timer = QTimer(self)
        self.totp_update_timer.timeout.connect(self.update_totp)
        
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
    
    def on_scan_from_camera(self):
        """Open camera to scan QR code"""
        try:
            # Import OpenCV
            import cv2
            
            # Check if camera is already active
            if self.camera is not None:
                self.stop_camera()
                return
            
            # Try to initialize camera
            self.camera = cv2.VideoCapture(0)
            if not self.camera.isOpened():
                QMessageBox.warning(self, "Camera Error", "Failed to open the camera. Make sure your camera is connected and not in use by another application.")
                self.camera = None
                return
            
            # Update UI to show camera is active
            self.image_preview.setText("Camera active - scanning for QR codes...")
            
            # Create timer for camera updates
            self.camera_timer = QTimer(self)
            self.camera_timer.timeout.connect(self.update_camera_frame)
            self.camera_timer.start(100)  # Update every 100ms
            
        except ImportError:
            QMessageBox.warning(self, "Error", "OpenCV is required for camera scanning. Please install it with 'pip install opencv-python'.")
        except cv2.error as e:
            QMessageBox.critical(self, "Camera Error", f"OpenCV error: {str(e)}\n\nYour camera may not be properly configured or available.")
            self.stop_camera()
        except Exception as e:
            QMessageBox.critical(self, "Camera Error", f"Failed to initialize camera: {str(e)}")
            self.stop_camera()
    
    def update_camera_frame(self):
        """Update the camera frame and scan for QR codes"""
        if self.camera is None:
            return
            
        try:
            # Read frame from camera
            ret, frame = self.camera.read()
            if not ret:
                self.stop_camera()
                QMessageBox.warning(self, "Camera Error", "Failed to read from camera.")
                return
            
            # Try to detect QR codes in the frame
            import cv2
            detector = cv2.QRCodeDetector()
            data, bbox, _ = detector.detectAndDecode(frame)
            
            # If QR code detected, process it
            if data and data.startswith('otpauth://'):
                # Save the frame as a temporary file
                temp_file = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
                temp_file.close()
                cv2.imwrite(temp_file.name, frame)
                
                # Stop camera before processing
                self.stop_camera()
                
                # Process the QR code
                self.qr_image_path = temp_file.name
                
                # Try to extract TOTP data from QR code
                result, error_msg = self.totp_auth.process_qr_code(self.qr_image_path)
                
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
                secret = result.get("secret", "")
                
                info_text = f"Account: {account}\n"
                if issuer:
                    info_text += f"Issuer: {issuer}\n"
                self.qr_info.setText(info_text)
                
                # Set up the TOTP auth with the extracted secret
                self.totp_auth.set_secret(secret, issuer, account)
                
                # Show the token frame
                self.token_frame.setVisible(True)
                
                # Update token display
                self.update_totp()
                
                # Start the TOTP update timer
                self.totp_update_timer.start(1000)  # Update every second
                
                # Enable add button
                self.qr_add_button.setEnabled(True)
                
                # Show success message with option to add account
                confirm = QMessageBox.information(
                    self,
                    "QR Code Detected",
                    f"TOTP secret successfully extracted!\n\nAccount: {account}\nIssuer: {issuer or 'Not specified'}\n\nDo you want to add this account?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.Yes
                )
                
                # Automatically add the account if user confirms
                if confirm == QMessageBox.StandardButton.Yes:
                    self.on_qr_add()
                
                return
                
            # Convert frame to QImage for display
            rgb_image = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            h, w, ch = rgb_image.shape
            bytes_per_line = ch * w
            qt_image = QImage(rgb_image.data, w, h, bytes_per_line, QImage.Format.Format_RGB888)
            
            # Display the camera feed
            pixmap = QPixmap.fromImage(qt_image)
            scaled_pixmap = pixmap.scaled(400, 300, Qt.AspectRatioMode.KeepAspectRatio)
            self.image_preview.setPixmap(scaled_pixmap)
            
            # Draw bounding box if detected but not valid TOTP QR
            if bbox is not None and not data.startswith('otpauth://'):
                # Update status text
                self.qr_info.setText("QR code detected, but not a valid TOTP code")
                
                # Hide token frame if it was visible before
                self.token_frame.setVisible(False)
                
                # Stop TOTP timer if it was running
                self.totp_update_timer.stop()
            
        except Exception as e:
            self.stop_camera()
            QMessageBox.critical(self, "Camera Error", f"Error processing camera frame: {str(e)}")
    
    def stop_camera(self):
        """Stop the camera and cleanup resources"""
        if self.camera_timer is not None:
            self.camera_timer.stop()
            self.camera_timer = None
            
        if self.camera is not None:
            self.camera.release()
            self.camera = None
            
        # Don't reset the image preview if we have a valid QR code
        if not self.extracted_data:
            self.image_preview.setText("No image selected")
            self.image_preview.setPixmap(QPixmap())
    
    def on_scan_qr(self):
        """Scan QR code from selected image"""
        # Make sure camera is stopped if running
        self.stop_camera()
        
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
            secret = result.get("secret", "")
            
            info_text = f"Account: {account}\n"
            if issuer:
                info_text += f"Issuer: {issuer}\n"
            self.qr_info.setText(info_text)
            
            # Set up the TOTP auth with the extracted secret
            self.totp_auth.set_secret(secret, issuer, account)
            
            # Show the token frame
            self.token_frame.setVisible(True)
            
            # Update token display
            self.update_totp()
            
            # Start the TOTP update timer
            self.totp_update_timer.start(1000)  # Update every second
            
            # Enable add button
            self.qr_add_button.setEnabled(True)
            
            # Show success message
            confirm = QMessageBox.information(
                self,
                "QR Code Scanned",
                f"TOTP secret successfully extracted!\n\nAccount: {account}\nIssuer: {issuer or 'Not specified'}\n\nDo you want to add this account?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes
            )
            
            # Automatically add the account if user confirms
            if confirm == QMessageBox.StandardButton.Yes:
                self.on_qr_add()
        
        except Exception as e:
            self.setCursor(Qt.CursorShape.ArrowCursor)
            QMessageBox.critical(self, "Error", f"Failed to scan QR code: {str(e)}")
    
    def update_totp(self):
        """Update the TOTP token display"""
        if not hasattr(self, 'extracted_data') or not self.extracted_data:
            return
            
        try:
            secret = self.extracted_data.get("secret")
            if not secret:
                return
                
            # Generate TOTP token
            token, remaining = self.totp_auth.generate_totp(secret)
            
            if token:
                # Update token display
                self.token_display.setText(token)
                
                # Update timer
                self.token_timer.setValue(remaining)
        except Exception as e:
            self.token_display.setText("Error")
            self.totp_update_timer.stop()
    
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
    
    # Add cleanup to the close event
    def closeEvent(self, event):
        """Handle dialog close event"""
        self.stop_camera()
        self.totp_update_timer.stop()
        super().closeEvent(event)
    
    def reject(self):
        """Handle dialog rejection (Cancel button)"""
        self.stop_camera()
        self.totp_update_timer.stop()
        super().reject()
    
    def accept(self):
        """Handle dialog acceptance"""
        self.totp_update_timer.stop()
        super().accept() 