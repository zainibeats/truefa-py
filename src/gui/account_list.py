"""
AccountList component for TrueFA-Py GUI

Displays a list of TOTP accounts and allows selection.
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QListWidget, QListWidgetItem
from PyQt6.QtCore import pyqtSignal, Qt

class AccountList(QWidget):
    """
    Widget for displaying and selecting TOTP accounts
    
    Signals:
        account_selected: Emitted when an account is selected
            Parameters: name (str), secret (str)
    """
    
    # Signal emitted when an account is selected
    account_selected = pyqtSignal(str, str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        # Initialize data storage
        self.accounts = {}  # name -> {name, issuer, secret}
        
        # Set up UI
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface"""
        # Create main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Create list widget
        self.list_widget = QListWidget()
        self.list_widget.setAlternatingRowColors(True)
        self.list_widget.currentItemChanged.connect(self.on_item_changed)
        
        # Add list widget to layout
        layout.addWidget(self.list_widget)
    
    def add_account(self, name, issuer, secret):
        """
        Add an account to the list
        
        Args:
            name (str): Account name
            issuer (str): Issuer name
            secret (str): TOTP secret
        """
        # Store account data
        self.accounts[name] = {
            "name": name,
            "issuer": issuer,
            "secret": secret
        }
        
        # Create display text
        display_text = f"{issuer}: {name}" if issuer else name
        
        # Create and add list item
        item = QListWidgetItem(display_text)
        item.setData(Qt.ItemDataRole.UserRole, name)  # Store name as user data
        self.list_widget.addItem(item)
    
    def clear(self):
        """Clear the account list"""
        self.list_widget.clear()
        self.accounts = {}
    
    def on_item_changed(self, current, previous):
        """
        Handle item selection change
        
        Args:
            current: Currently selected item
            previous: Previously selected item
        """
        if current:
            # Get account name from item data
            name = current.data(Qt.ItemDataRole.UserRole)
            
            # Get account data
            account_data = self.accounts.get(name, {})
            secret = account_data.get("secret", "")
            
            # Emit signal with account data
            if name and secret:
                self.account_selected.emit(name, secret)
    
    def get_selected_account(self):
        """
        Get the currently selected account
        
        Returns:
            dict: Account data or None if no account is selected
        """
        current_item = self.list_widget.currentItem()
        if current_item:
            name = current_item.data(Qt.ItemDataRole.UserRole)
            return self.accounts.get(name)
        
        return None 