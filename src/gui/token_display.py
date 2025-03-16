"""
TokenDisplay component for TrueFA-Py GUI

Displays TOTP tokens with a countdown timer and visual indicators.
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar, QFrame
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont

class TokenDisplay(QWidget):
    """
    Widget for displaying TOTP tokens with countdown timer
    
    Features:
    - Large, easy-to-read token display
    - Visual countdown timer
    - Account information display
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        # Initialize state
        self.token = None
        self.remaining = 0
        self.account_name = None
        self.issuer = None
        
        # Set up UI
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface"""
        # Create main layout
        layout = QVBoxLayout(self)
        
        # Create token frame
        token_frame = QFrame()
        token_frame.setFrameShape(QFrame.Shape.StyledPanel)
        token_frame.setMinimumHeight(150)
        
        token_layout = QVBoxLayout(token_frame)
        
        # Account info
        self.account_label = QLabel("No account selected")
        self.account_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.account_label.setFont(QFont("Arial", 12))
        
        # Token display
        self.token_label = QLabel("------")
        self.token_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.token_label.setFont(QFont("Monospace", 32, QFont.Weight.Bold))
        
        # Progress bar for countdown
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 30)  # TOTP typically uses 30-second intervals
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        
        # Remaining time
        self.time_label = QLabel("0s")
        self.time_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.time_label.setFont(QFont("Arial", 10))
        
        # Add widgets to layout
        token_layout.addWidget(self.account_label)
        token_layout.addWidget(self.token_label)
        token_layout.addWidget(self.progress_bar)
        token_layout.addWidget(self.time_label)
        
        # Add token frame to main layout
        layout.addWidget(token_frame)
    
    def set_token(self, token, remaining):
        """
        Update the displayed token and remaining time
        
        Args:
            token (str): The TOTP token to display
            remaining (int): Seconds remaining until token expires
        """
        if token != self.token or remaining != self.remaining:
            self.token = token
            self.remaining = remaining
            
            # Format token with space in the middle for readability
            if len(token) == 6:
                formatted_token = f"{token[:3]} {token[3:]}"
            else:
                formatted_token = token
            
            # Update UI
            self.token_label.setText(formatted_token)
            self.progress_bar.setValue(remaining)
            self.time_label.setText(f"{remaining}s")
            
            # Change color based on remaining time
            if remaining <= 5:
                self.progress_bar.setStyleSheet("QProgressBar::chunk { background-color: #ff3860; }")
            elif remaining <= 10:
                self.progress_bar.setStyleSheet("QProgressBar::chunk { background-color: #ffdd57; }")
            else:
                self.progress_bar.setStyleSheet("QProgressBar::chunk { background-color: #23d160; }")
    
    def set_account(self, name, issuer=""):
        """
        Set the account information
        
        Args:
            name (str): Account name
            issuer (str, optional): Issuer name
        """
        self.account_name = name
        self.issuer = issuer
        
        if issuer:
            self.account_label.setText(f"{issuer}: {name}")
        else:
            self.account_label.setText(name)
    
    def clear(self):
        """Clear the display"""
        self.token = None
        self.remaining = 0
        self.account_name = None
        self.issuer = None
        
        self.token_label.setText("------")
        self.account_label.setText("No account selected")
        self.progress_bar.setValue(0)
        self.time_label.setText("0s")
        self.progress_bar.setStyleSheet("") 