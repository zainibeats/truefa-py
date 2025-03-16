import sys
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, 
                            QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
                            QLineEdit, QMessageBox, QFileDialog, QDialog, 
                            QListWidget, QFrame, QStackedWidget, QProgressBar,
                            QCheckBox, QInputDialog)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QSize, QSettings
from PyQt6.QtGui import QIcon, QPixmap, QFont

# Import the existing TrueFA-Py modules - using safer, more limited imports for now
from src.totp.auth_opencv import TwoFactorAuth as TOTPAuth
from src.gui.secure_vault import SecureVault
from src.utils.logger import debug, info, warning, error, critical

# Import our custom UI components
from src.gui.token_display import TokenDisplay
from src.gui.account_list import AccountList
from src.gui.add_account_dialog import AddAccountDialog
from src.gui.style import get_style

class MainWindow(QMainWindow):
    """Main window for TrueFA-Py GUI application"""
    
    def __init__(self):
        super().__init__()
        
        # Initialize the TOTP auth component
        self.totp_auth = TOTPAuth()
        
        # Initialize the secure vault
        self.vault = SecureVault()
        
        # Initialize UI state
        self.current_secret = None
        self.current_account_name = None
        self.current_issuer = None
        self.is_vault_unlocked = False
        self.secrets_dict = {}
        
        # Load settings
        self.settings = QSettings("TrueFA", "TrueFA-Py")
        self.dark_mode = self.settings.value("dark_mode", False, type=bool)
        
        # Setup UI
        self.setup_ui()
        
        # Apply stylesheet
        self.apply_style()
        
        # Start TOTP update timer
        self.setup_totp_timer()
    
    def setup_ui(self):
        """Set up the main user interface"""
        self.setWindowTitle("TrueFA-Py - Secure TOTP Authenticator")
        self.setMinimumSize(800, 600)
        
        # Create central widget and main layout
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        
        # Create stacked widget for login/main screens
        self.stacked_widget = QStackedWidget()
        
        # Create login and main pages
        self.login_page = self.create_login_page()
        self.main_page = self.create_main_page()
        
        # Add pages to stacked widget
        self.stacked_widget.addWidget(self.login_page)
        self.stacked_widget.addWidget(self.main_page)
        
        # Start with login page
        self.stacked_widget.setCurrentIndex(0)
        
        # Add stacked widget to main layout
        main_layout.addWidget(self.stacked_widget)
        
        # Set central widget
        self.setCentralWidget(central_widget)
    
    def create_login_page(self):
        """Create the login page (vault authentication)"""
        page = QWidget()
        layout = QVBoxLayout(page)
        
        # Header with logo/title
        header_layout = QVBoxLayout()
        
        # Add icon above the title
        icon_label = QLabel()
        icon_pixmap = QPixmap("truefa2.png")
        if not icon_pixmap.isNull():
            icon_pixmap = icon_pixmap.scaled(128, 128, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            icon_label.setPixmap(icon_pixmap)
            icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        else:
            # If icon can't be loaded, use a placeholder text
            icon_label.setText("🔒")
            icon_label.setFont(QFont("Arial", 48))
            icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        title_label = QLabel("TrueFA-Py")
        title_label.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        subtitle_label = QLabel("Secure TOTP Authenticator")
        subtitle_label.setFont(QFont("Arial", 14))
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        header_layout.addWidget(icon_label)
        header_layout.addWidget(title_label)
        header_layout.addWidget(subtitle_label)
        
        # Create login form
        form_frame = QFrame()
        form_frame.setFrameShape(QFrame.Shape.StyledPanel)
        form_frame.setMaximumWidth(400)
        
        form_layout = QVBoxLayout(form_frame)
        
        # Check if vault exists
        vault_exists = self.check_vault_exists()
        
        if vault_exists:
            # Password input for existing vault
            self.password_label = QLabel("Enter Master Password:")
            self.password_input = QLineEdit()
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.password_input.setPlaceholderText("Master Password")
            self.password_input.returnPressed.connect(self.on_login)
            
            self.login_button = QPushButton("Unlock Vault")
            self.login_button.clicked.connect(self.on_login)
            
            form_layout.addWidget(self.password_label)
            form_layout.addWidget(self.password_input)
            form_layout.addWidget(self.login_button)
        else:
            # Create new vault
            self.password_label = QLabel("Create Master Password:")
            self.password_input = QLineEdit()
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.password_input.setPlaceholderText("New Master Password")
            
            self.confirm_label = QLabel("Confirm Password:")
            self.confirm_input = QLineEdit()
            self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.confirm_input.setPlaceholderText("Confirm Password")
            self.confirm_input.returnPressed.connect(self.on_create_vault)
            
            self.create_button = QPushButton("Create Vault")
            self.create_button.clicked.connect(self.on_create_vault)
            
            form_layout.addWidget(self.password_label)
            form_layout.addWidget(self.password_input)
            form_layout.addWidget(self.confirm_label)
            form_layout.addWidget(self.confirm_input)
            form_layout.addWidget(self.create_button)
        
        # Dark mode toggle
        self.login_dark_mode_checkbox = QCheckBox("Dark Mode")
        self.login_dark_mode_checkbox.setChecked(self.dark_mode)
        self.login_dark_mode_checkbox.toggled.connect(self.on_dark_mode_toggle)
        
        # Add form to layout
        layout.addStretch(1)
        layout.addLayout(header_layout)
        layout.addSpacing(30)
        layout.addWidget(form_frame, 0, Qt.AlignmentFlag.AlignCenter)
        layout.addSpacing(20)
        layout.addWidget(self.login_dark_mode_checkbox, 0, Qt.AlignmentFlag.AlignCenter)
        layout.addStretch(1)
        
        return page
    
    def create_main_page(self):
        """Create the main application page"""
        page = QWidget()
        layout = QVBoxLayout(page)
        
        # Create header with title
        header_layout = QHBoxLayout()
        
        title_label = QLabel("TrueFA-Py")
        title_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        
        # Lock button
        self.lock_button = QPushButton("Lock Vault")
        self.lock_button.clicked.connect(self.on_lock_vault)
        
        # Dark mode toggle
        self.dark_mode_checkbox = QCheckBox("Dark Mode")
        self.dark_mode_checkbox.setChecked(self.dark_mode)
        self.dark_mode_checkbox.toggled.connect(self.on_dark_mode_toggle)
        
        header_layout.addWidget(title_label)
        header_layout.addStretch(1)
        header_layout.addWidget(self.dark_mode_checkbox)
        header_layout.addWidget(self.lock_button)
        
        # Create tab widget for different functions
        self.tab_widget = QTabWidget()
        
        # Create tabs
        token_tab = self.create_token_tab()
        accounts_tab = self.create_accounts_tab()
        settings_tab = self.create_settings_tab()
        
        # Add tabs to widget
        self.tab_widget.addTab(token_tab, "TOTP Tokens")
        self.tab_widget.addTab(accounts_tab, "Accounts")
        self.tab_widget.addTab(settings_tab, "Settings")
        
        # Add layouts to page
        layout.addLayout(header_layout)
        layout.addWidget(self.tab_widget)
        
        return page
    
    def create_token_tab(self):
        """Create tab for TOTP token display"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Test TOTP section
        test_frame = QFrame()
        test_frame.setFrameShape(QFrame.Shape.StyledPanel)
        test_layout = QVBoxLayout(test_frame)
        
        test_title = QLabel("Test TOTP Token")
        test_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        
        self.test_secret_input = QLineEdit()
        self.test_secret_input.setPlaceholderText("Enter TOTP secret key")
        
        test_button = QPushButton("Generate Token")
        test_button.clicked.connect(self.on_generate_test_token)
        
        test_layout.addWidget(test_title)
        test_layout.addWidget(QLabel("Secret Key:"))
        test_layout.addWidget(self.test_secret_input)
        test_layout.addWidget(test_button)
        
        # Token display
        self.token_display = TokenDisplay()
        
        # Add to layout
        layout.addWidget(test_frame)
        layout.addWidget(self.token_display)
        layout.addStretch(1)
        
        return tab
    
    def create_accounts_tab(self):
        """Create tab for account management"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Account list
        self.account_list = AccountList()
        self.account_list.account_selected.connect(self.on_account_selected)
        
        # Account actions
        buttons_layout = QHBoxLayout()
        
        add_button = QPushButton("Add Account")
        add_button.clicked.connect(self.on_add_account)
        
        delete_button = QPushButton("Delete Account")
        delete_button.clicked.connect(self.on_delete_account)
        
        import_button = QPushButton("Import")
        import_button.clicked.connect(self.on_import_accounts)
        
        export_button = QPushButton("Export")
        export_button.clicked.connect(self.on_export_accounts)
        
        buttons_layout.addWidget(add_button)
        buttons_layout.addWidget(delete_button)
        buttons_layout.addStretch(1)
        buttons_layout.addWidget(import_button)
        buttons_layout.addWidget(export_button)
        
        # Add to layout
        layout.addWidget(QLabel("Saved Accounts:"))
        layout.addWidget(self.account_list)
        layout.addLayout(buttons_layout)
        
        return tab
    
    def create_settings_tab(self):
        """Create tab for application settings"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Appearance section
        appearance_frame = QFrame()
        appearance_frame.setFrameShape(QFrame.Shape.StyledPanel)
        appearance_layout = QVBoxLayout(appearance_frame)
        
        appearance_title = QLabel("Appearance")
        appearance_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        
        # Dark mode toggle
        self.settings_dark_mode_checkbox = QCheckBox("Dark Mode")
        self.settings_dark_mode_checkbox.setChecked(self.dark_mode)
        self.settings_dark_mode_checkbox.toggled.connect(self.on_dark_mode_toggle)
        
        appearance_layout.addWidget(appearance_title)
        appearance_layout.addWidget(self.settings_dark_mode_checkbox)
        
        # Security section
        security_frame = QFrame()
        security_frame.setFrameShape(QFrame.Shape.StyledPanel)
        security_layout = QVBoxLayout(security_frame)
        
        security_title = QLabel("Security")
        security_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        
        change_password_button = QPushButton("Change Master Password")
        change_password_button.clicked.connect(self.on_change_password)
        
        delete_vault_button = QPushButton("Delete Vault")
        delete_vault_button.setStyleSheet("background-color: #ff3860; color: white;")
        delete_vault_button.clicked.connect(self.on_delete_vault)
        
        security_layout.addWidget(security_title)
        security_layout.addWidget(change_password_button)
        security_layout.addWidget(delete_vault_button)
        
        # Testing section
        testing_frame = QFrame()
        testing_frame.setFrameShape(QFrame.Shape.StyledPanel)
        testing_layout = QVBoxLayout(testing_frame)
        
        testing_title = QLabel("Testing & Troubleshooting")
        testing_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        
        generate_qr_button = QPushButton("Generate Test QR Code")
        generate_qr_button.clicked.connect(self.on_generate_test_qr)
        
        testing_layout.addWidget(testing_title)
        testing_layout.addWidget(generate_qr_button)
        
        # About section
        about_frame = QFrame()
        about_frame.setFrameShape(QFrame.Shape.StyledPanel)
        about_layout = QVBoxLayout(about_frame)
        
        about_title = QLabel("About")
        about_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        
        about_text = QLabel("TrueFA-Py - Secure TOTP Authenticator\nVersion 0.1.0")
        about_layout.addWidget(about_title)
        about_layout.addWidget(about_text)
        
        # Add to layout
        layout.addWidget(appearance_frame)
        layout.addWidget(security_frame)
        layout.addWidget(testing_frame)
        layout.addWidget(about_frame)
        layout.addStretch(1)
        
        return tab
    
    def setup_totp_timer(self):
        """Set up timer for TOTP updates"""
        self.totp_timer = QTimer(self)
        self.totp_timer.timeout.connect(self.update_totp)
        self.totp_timer.start(1000)  # Update every second
    
    def update_totp(self):
        """Update the TOTP token display"""
        if self.current_secret:
            # Get the current token and remaining seconds
            token, remaining = self.totp_auth.generate_totp(self.current_secret)
            
            # Update the display
            self.token_display.set_token(token, remaining)
    
    def apply_style(self):
        """Apply stylesheet based on dark mode setting"""
        style = get_style(self.dark_mode)
        self.setStyleSheet(style)
        
        # Sync dark mode checkbox states
        if hasattr(self, 'dark_mode_checkbox'):
            self.dark_mode_checkbox.setChecked(self.dark_mode)
        
        if hasattr(self, 'settings_dark_mode_checkbox'):
            self.settings_dark_mode_checkbox.setChecked(self.dark_mode)
            
        if hasattr(self, 'login_dark_mode_checkbox'):
            self.login_dark_mode_checkbox.setChecked(self.dark_mode)
    
    def on_dark_mode_toggle(self, checked):
        """Handle dark mode toggle"""
        self.dark_mode = checked
        self.settings.setValue("dark_mode", checked)
        
        # Apply new style
        self.apply_style()
        
        # Sync other checkboxes
        if self.sender() == self.dark_mode_checkbox:
            self.settings_dark_mode_checkbox.setChecked(checked)
            if hasattr(self, 'login_dark_mode_checkbox'):
                self.login_dark_mode_checkbox.setChecked(checked)
        elif self.sender() == self.settings_dark_mode_checkbox:
            self.dark_mode_checkbox.setChecked(checked)
            if hasattr(self, 'login_dark_mode_checkbox'):
                self.login_dark_mode_checkbox.setChecked(checked)
        elif hasattr(self, 'login_dark_mode_checkbox') and self.sender() == self.login_dark_mode_checkbox:
            if hasattr(self, 'dark_mode_checkbox'):
                self.dark_mode_checkbox.setChecked(checked)
            if hasattr(self, 'settings_dark_mode_checkbox'):
                self.settings_dark_mode_checkbox.setChecked(checked)
    
    def check_vault_exists(self):
        """Check if the vault exists"""
        try:
            return self.vault.exists()
        except Exception as e:
            error(f"Error checking if vault exists: {str(e)}")
            return False
    
    def on_login(self):
        """Handle login button click"""
        password = self.password_input.text()
        
        if not password:
            QMessageBox.warning(self, "Error", "Please enter a password")
            return
        
        try:
            # Try to unlock the vault
            success = self.vault.unlock(password)
            
            if success:
                # Load secrets
                self.secrets_dict = self.vault.load_secrets() or {}
                
                # Update account list
                self.update_account_list()
                
                # Switch to main page
                self.stacked_widget.setCurrentIndex(1)
                self.is_vault_unlocked = True
                
                # Clear password input
                self.password_input.clear()
                
                info("Vault unlocked successfully")
            else:
                QMessageBox.warning(self, "Error", "Incorrect password")
                error("Failed to unlock vault: incorrect password")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to unlock vault: {str(e)}")
            error(f"Error unlocking vault: {str(e)}")
    
    def on_create_vault(self):
        """Handle create vault button click"""
        password = self.password_input.text()
        confirm = self.confirm_input.text()
        
        if not password:
            QMessageBox.warning(self, "Error", "Please enter a password")
            return
        
        if password != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match")
            return
        
        try:
            # Create and initialize the vault
            success = self.vault.create(password)
            
            if success:
                # Clear inputs
                self.password_input.clear()
                self.confirm_input.clear()
                
                # Create empty secrets dictionary
                self.secrets_dict = {}
                
                # Make sure the vault state is properly recognized
                self.is_vault_unlocked = True
                
                # Switch to main page
                self.stacked_widget.setCurrentIndex(1)
                
                info("Vault created successfully")
                QMessageBox.information(self, "Success", "Vault created successfully")
            else:
                QMessageBox.warning(self, "Error", "Failed to create vault")
                error("Failed to create vault")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create vault: {str(e)}")
            error(f"Error creating vault: {str(e)}")
    
    def refresh_login_page(self):
        """Refresh the login page UI based on whether vault exists"""
        # Check if vault exists
        vault_exists = self.check_vault_exists()
        
        # Remove old login page and create a new one
        old_login_page = self.login_page
        self.login_page = self.create_login_page()
        
        # Replace in stacked widget
        self.stacked_widget.removeWidget(old_login_page)
        self.stacked_widget.insertWidget(0, self.login_page)
        
        info(f"Refreshed login page. Vault exists: {vault_exists}")
        return vault_exists
    
    def on_lock_vault(self):
        """Handle lock vault button click"""
        try:
            # Lock the vault
            self.vault.lock()
            
            # Clear current state
            self.current_secret = None
            self.current_account_name = None
            self.current_issuer = None
            self.token_display.clear()
            
            # Refresh the login page to ensure it shows the correct UI
            self.refresh_login_page()
            
            # Switch to login page
            self.stacked_widget.setCurrentIndex(0)
            self.is_vault_unlocked = False
            
            info("Vault locked successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to lock vault: {str(e)}")
            error(f"Error locking vault: {str(e)}")
    
    def on_generate_test_token(self):
        """Generate a test TOTP token"""
        secret = self.test_secret_input.text().strip()
        
        if not secret:
            QMessageBox.warning(self, "Error", "Please enter a secret key")
            return
        
        try:
            # Validate the secret format
            if not self.totp_auth.validate_totp_secret(secret):
                QMessageBox.warning(self, "Error", "Invalid secret key format. Please check your input.")
                return
            
            # Set current secret and display
            self.current_secret = secret
            self.current_account_name = "Test Account"
            self.current_issuer = "Test"
            
            # Set up the TOTP auth with the extracted secret
            self.totp_auth.set_secret(secret, self.current_issuer, self.current_account_name)
            
            # Update display
            self.token_display.set_account(self.current_account_name, self.current_issuer)
            self.update_totp()
            
            # Display a success message
            QMessageBox.information(
                self,
                "TOTP Token Generated",
                f"Test token successfully generated!\n\nUse this token with your authentication service."
            )
            
            info(f"Generated test token for secret of length {len(secret)}")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate token: {str(e)}")
            error(f"Error generating token: {str(e)}")
            self.current_secret = None
            self.token_display.clear()
    
    def on_account_selected(self, name, secret):
        """Handle account selection from the list"""
        if name and secret:
            # Set current values
            account_data = self.secrets_dict.get(name, {})
            self.current_secret = secret
            self.current_account_name = name
            self.current_issuer = account_data.get("issuer", "")
            
            # Update display
            self.token_display.set_account(name, self.current_issuer)
            self.update_totp()
            
            debug(f"Selected account: {name}")
    
    def on_add_account(self):
        """Handle add account button click"""
        dialog = AddAccountDialog(self.totp_auth, self)
        dialog.account_added.connect(self.on_account_added)
        dialog.exec()
    
    def on_account_added(self, account_data):
        """Handle new account added from dialog"""
        if not account_data:
            return
        
        # Extract data
        name = account_data.get("account", "")
        issuer = account_data.get("issuer", "")
        secret = account_data.get("secret", "")
        
        if not name or not secret:
            QMessageBox.warning(self, "Error", "Invalid account data")
            return
        
        # Check if account with this name already exists
        if name in self.secrets_dict:
            # Ask for confirmation to overwrite
            confirm = QMessageBox.question(
                self, "Confirm Overwrite", 
                f"An account named '{name}' already exists. Do you want to overwrite it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if confirm != QMessageBox.StandardButton.Yes:
                return
        
        # Add to secrets dictionary
        self.secrets_dict[name] = account_data
        
        # Save to vault
        try:
            if self.is_vault_unlocked:
                self.vault.save_secrets(self.secrets_dict)
                
                # Update account list
                self.update_account_list()
                
                # Select the newly added account in the account list
                self.account_list.select_account(name)
                
                # Switch to the account for immediate token display
                self.current_secret = secret
                self.current_account_name = name
                self.current_issuer = issuer
                
                # Update token display
                self.token_display.set_account(name, issuer)
                self.update_totp()
                
                # Switch to the tokens tab to show the new token
                if hasattr(self, 'tab_widget'):
                    self.tab_widget.setCurrentIndex(0)  # Tokens tab
                
                info(f"Added account: {name}")
                QMessageBox.information(self, "Success", f"Account '{name}' added successfully")
            else:
                QMessageBox.warning(self, "Error", "Vault is locked, cannot save account")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save account: {str(e)}")
            error(f"Error saving account: {str(e)}")
    
    def on_delete_account(self):
        """Handle delete account button click"""
        selected_account = self.account_list.get_selected_account()
        
        if not selected_account:
            QMessageBox.warning(self, "Error", "No account selected")
            return
        
        name = selected_account.get("name", "")
        
        if not name:
            return
        
        # Confirm deletion
        confirm = QMessageBox.question(
            self, "Confirm Deletion", 
            f"Are you sure you want to delete the account '{name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm != QMessageBox.StandardButton.Yes:
            return
        
        # Remove from dictionary
        if name in self.secrets_dict:
            del self.secrets_dict[name]
            
            # Save to vault
            try:
                if self.is_vault_unlocked:
                    self.vault.save_secrets(self.secrets_dict)
                    
                    # Update account list
                    self.update_account_list()
                    
                    # Clear current display if it was the deleted account
                    if self.current_account_name == name:
                        self.current_secret = None
                        self.current_account_name = None
                        self.current_issuer = None
                        self.token_display.clear()
                    
                    info(f"Deleted account: {name}")
                else:
                    QMessageBox.warning(self, "Error", "Vault is locked, cannot delete account")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save changes: {str(e)}")
                error(f"Error saving changes: {str(e)}")
    
    def on_import_accounts(self):
        """Handle import accounts button click"""
        # Open file dialog to select import file
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Accounts",
            "",
            "All Files (*);;JSON Files (*.json);;Text Files (*.txt)"
        )
        
        if not file_path:
            return
        
        # Ask for import password
        password, ok = QInputDialog.getText(
            self,
            "Import Password",
            "Enter the password for the encrypted file:",
            QLineEdit.EchoMode.Password
        )
        
        if not ok or not password:
            return
        
        try:
            # Import secrets using the SecretImporter class
            from src.security.importers import SecretImporter
            importer = SecretImporter()
            
            # Show importing message
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            
            # Attempt to import
            imported_secrets, error_msg = importer.import_from_file(file_path, password)
            
            # Restore cursor
            QApplication.restoreOverrideCursor()
            
            if error_msg:
                QMessageBox.critical(self, "Import Error", error_msg)
                error(f"Import error: {error_msg}")
                return
            
            if not imported_secrets:
                QMessageBox.warning(self, "Import Warning", "No accounts were found in the import file.")
                warning("No accounts found in import file")
                return
            
            # Ask for confirmation to import
            confirm_msg = f"Found {len(imported_secrets)} accounts to import. Continue?"
            confirm = QMessageBox.question(
                self, 
                "Confirm Import", 
                confirm_msg,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if confirm != QMessageBox.StandardButton.Yes:
                return
            
            # Process imported secrets
            duplicates = []
            for name, secret_data in imported_secrets.items():
                if name in self.secrets_dict:
                    duplicates.append(name)
                else:
                    self.secrets_dict[name] = secret_data
            
            # Handle duplicates if any
            if duplicates:
                options = ["Skip duplicates", "Overwrite duplicates", "Cancel import"]
                duplicate_msg = f"Found {len(duplicates)} duplicate accounts.\nHow would you like to proceed?"
                choice, ok = QInputDialog.getItem(
                    self,
                    "Duplicate Accounts",
                    duplicate_msg,
                    options,
                    0,
                    False
                )
                
                if not ok or choice == "Cancel import":
                    return
                
                if choice == "Overwrite duplicates":
                    for name, secret_data in imported_secrets.items():
                        self.secrets_dict[name] = secret_data
            
            # Save updated secrets to vault
            if self.is_vault_unlocked:
                self.vault.save_secrets(self.secrets_dict)
                
                # Update account list
                self.update_account_list()
                
                info(f"Successfully imported {len(imported_secrets)} accounts")
                QMessageBox.information(self, "Import Successful", f"Successfully imported {len(imported_secrets)} accounts.")
            else:
                QMessageBox.warning(self, "Error", "Vault is locked, cannot save imported accounts")
        
        except Exception as e:
            QApplication.restoreOverrideCursor()
            QMessageBox.critical(self, "Import Error", f"Failed to import accounts: {str(e)}")
            error(f"Import error: {str(e)}")
    
    def on_export_accounts(self):
        """Handle export accounts button click"""
        if not self.secrets_dict:
            QMessageBox.warning(self, "Export Warning", "No accounts to export.")
            return
        
        # Ask for export password
        password, ok = QInputDialog.getText(
            self,
            "Export Password",
            "Enter a password to encrypt the export file:",
            QLineEdit.EchoMode.Password
        )
        
        if not ok or not password:
            return
        
        # Confirm password
        confirm_password, ok = QInputDialog.getText(
            self,
            "Confirm Password",
            "Confirm the export password:",
            QLineEdit.EchoMode.Password
        )
        
        if not ok or password != confirm_password:
            QMessageBox.warning(self, "Password Error", "Passwords do not match.")
            return
        
        # Get export file path
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Accounts",
            "",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            # Export secrets using the SecretExporter class
            from src.security.exporters import SecretExporter
            exporter = SecretExporter()
            
            # Show exporting message
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            
            # Attempt to export
            success = exporter.export_to_encrypted_json(self.secrets_dict, file_path, password)
            
            # Restore cursor
            QApplication.restoreOverrideCursor()
            
            if success:
                info(f"Successfully exported {len(self.secrets_dict)} accounts to {file_path}")
                QMessageBox.information(self, "Export Successful", f"Successfully exported {len(self.secrets_dict)} accounts.")
            else:
                QMessageBox.critical(self, "Export Error", "Failed to export accounts.")
                error("Failed to export accounts")
        
        except Exception as e:
            QApplication.restoreOverrideCursor()
            QMessageBox.critical(self, "Export Error", f"Failed to export accounts: {str(e)}")
            error(f"Export error: {str(e)}")
            
    def on_change_password(self):
        """Handle change master password button click"""
        if not self.is_vault_unlocked:
            QMessageBox.warning(self, "Error", "Vault must be unlocked to change the password.")
            return
        
        # Ask for current password
        current_password, ok = QInputDialog.getText(
            self,
            "Current Password",
            "Enter your current master password:",
            QLineEdit.EchoMode.Password
        )
        
        if not ok or not current_password:
            return
        
        # Verify current password
        if not self.vault.verify_password(current_password):
            QMessageBox.critical(self, "Authentication Error", "Current password is incorrect.")
            return
        
        # Ask for new password
        new_password, ok = QInputDialog.getText(
            self,
            "New Password",
            "Enter your new master password:",
            QLineEdit.EchoMode.Password
        )
        
        if not ok or not new_password:
            return
        
        # Confirm new password
        confirm_password, ok = QInputDialog.getText(
            self,
            "Confirm New Password",
            "Confirm your new master password:",
            QLineEdit.EchoMode.Password
        )
        
        if not ok or new_password != confirm_password:
            QMessageBox.warning(self, "Password Error", "New passwords do not match.")
            return
        
        try:
            # Change the master password
            success = self.vault.change_password(current_password, new_password)
            
            if success:
                info("Master password changed successfully")
                QMessageBox.information(self, "Success", "Master password changed successfully.")
            else:
                error("Failed to change master password")
                QMessageBox.critical(self, "Error", "Failed to change master password.")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to change master password: {str(e)}")
            error(f"Error changing master password: {str(e)}")
    
    def on_delete_vault(self):
        """Handle delete vault button click"""
        # Show critical warning
        confirm = QMessageBox.critical(
            self,
            "Delete Vault?",
            "WARNING: This will permanently delete your vault and all stored accounts.\n\n"
            "This action CANNOT be undone. Are you absolutely sure?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if confirm != QMessageBox.StandardButton.Yes:
            return
        
        # Double-confirm with password
        password, ok = QInputDialog.getText(
            self,
            "Confirm with Password",
            "Enter your master password to confirm vault deletion:",
            QLineEdit.EchoMode.Password
        )
        
        if not ok or not password:
            return
        
        # Verify password
        if not self.vault.verify_password(password):
            QMessageBox.warning(self, "Error", "Incorrect password. Vault deletion canceled.")
            return
        
        try:
            # Get vault path
            vault_path = self.vault.vault_path
            
            # Lock vault first
            self.vault.lock()
            
            # Delete vault file
            if os.path.exists(vault_path):
                os.remove(vault_path)
                
                # Show success message
                QMessageBox.information(
                    self,
                    "Vault Deleted",
                    "Your vault has been permanently deleted."
                )
                
                # Reset UI state
                self.is_vault_unlocked = False
                self.secrets_dict = {}
                self.current_secret = None
                self.current_account_name = None
                self.current_issuer = None
                
                # Refresh the login page to reflect the vault deletion
                self.refresh_login_page()
                
                # Switch to login page
                self.stacked_widget.setCurrentIndex(0)
                
                # Log deletion
                info("Vault deleted successfully")
            else:
                QMessageBox.warning(self, "Error", "Vault file not found.")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to delete vault: {str(e)}")
            error(f"Error deleting vault: {str(e)}")
    
    def on_generate_test_qr(self):
        """Generate a test QR code for scanning tests"""
        try:
            # Import necessary modules
            import qrcode
            from PIL import Image
            import tempfile
            import os
            
            # Ask for a test secret key
            test_secret, ok = QInputDialog.getText(
                self,
                "Test Secret",
                "Enter a test secret (or leave empty for a sample one):",
                QLineEdit.EchoMode.Normal,
                "JBSWY3DPEHPK3PXP"  # Google's sample TOTP secret
            )
            
            if not ok:
                return
            
            # Use default if empty
            if not test_secret:
                test_secret = "JBSWY3DPEHPK3PXP"
            
            # Create OTPAuth URI
            issuer = "TrueFA-Test"
            account = "test@example.com"
            otpauth_uri = f"otpauth://totp/{issuer}:{account}?secret={test_secret}&issuer={issuer}"
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(otpauth_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Save to temporary file
            temp_dir = tempfile.gettempdir()
            qr_path = os.path.join(temp_dir, "truefa_test_qr.png")
            img.save(qr_path)
            
            # Show success message with the file path
            QMessageBox.information(
                self,
                "QR Code Generated",
                f"A test QR code has been saved to:\n{qr_path}\n\n"
                f"You can use this file to test the QR code scanning functionality.\n\n"
                f"Secret: {test_secret}"
            )
            
            # Try to open the folder containing the QR code
            try:
                if sys.platform == 'win32':
                    os.startfile(temp_dir)
                elif sys.platform == 'darwin':  # macOS
                    import subprocess
                    subprocess.Popen(['open', temp_dir])
                else:  # Linux
                    import subprocess
                    subprocess.Popen(['xdg-open', temp_dir])
            except Exception:
                pass  # Ignore errors when trying to open folder
            
        except ImportError:
            QMessageBox.warning(
                self,
                "Missing Dependencies",
                "The qrcode and Pillow packages are required to generate QR codes.\n"
                "Install them with: pip install qrcode pillow"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate QR code: {str(e)}")
    
    def update_account_list(self):
        """Update the account list with current secrets"""
        self.account_list.clear()
        
        for name, account_data in self.secrets_dict.items():
            issuer = account_data.get("issuer", "")
            secret = account_data.get("secret", "")
            self.account_list.add_account(name, issuer, secret) 