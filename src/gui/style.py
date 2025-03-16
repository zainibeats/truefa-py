"""
Style module for TrueFA-Py GUI

Provides styling for the GUI application with light and dark mode support.
"""

def get_style(dark_mode=False):
    """
    Get the application stylesheet based on the selected theme
    
    Args:
        dark_mode (bool): Whether to use dark mode
        
    Returns:
        str: The stylesheet for the application
    """
    if dark_mode:
        return _get_dark_style()
    else:
        return _get_light_style()

def _get_light_style():
    """Get the light mode stylesheet"""
    return """
        /* Light Mode */
        QMainWindow, QDialog {
            background-color: #f5f5f5;
            color: #333333;
        }
        
        QWidget {
            background-color: #f5f5f5;
            color: #333333;
        }
        
        QLabel {
            color: #333333;
        }
        
        QPushButton {
            background-color: #e0e0e0;
            border: 1px solid #c0c0c0;
            border-radius: 4px;
            padding: 6px 12px;
            color: #333333;
        }
        
        QPushButton:hover {
            background-color: #d0d0d0;
        }
        
        QPushButton:pressed {
            background-color: #c0c0c0;
        }
        
        QLineEdit {
            background-color: #ffffff;
            border: 1px solid #c0c0c0;
            border-radius: 4px;
            padding: 4px;
            color: #333333;
        }
        
        QTabWidget::pane {
            border: 1px solid #c0c0c0;
            background-color: #ffffff;
        }
        
        QTabBar::tab {
            background-color: #e0e0e0;
            border: 1px solid #c0c0c0;
            border-bottom: none;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            padding: 6px 12px;
            color: #333333;
        }
        
        QTabBar::tab:selected {
            background-color: #ffffff;
            border-bottom: 1px solid #ffffff;
        }
        
        QTabBar::tab:hover:!selected {
            background-color: #d0d0d0;
        }
        
        QFrame {
            border: 1px solid #c0c0c0;
            border-radius: 4px;
            background-color: #ffffff;
        }
        
        QListWidget {
            background-color: #ffffff;
            border: 1px solid #c0c0c0;
            border-radius: 4px;
            alternate-background-color: #f0f0f0;
        }
        
        QListWidget::item {
            padding: 4px;
            border-bottom: 1px solid #e0e0e0;
        }
        
        QListWidget::item:selected {
            background-color: #0078d7;
            color: #ffffff;
        }
        
        QListWidget::item:hover:!selected {
            background-color: #e0e0e0;
        }
        
        QProgressBar {
            border: 1px solid #c0c0c0;
            border-radius: 4px;
            background-color: #ffffff;
            text-align: center;
        }
        
        QProgressBar::chunk {
            background-color: #0078d7;
            width: 10px;
        }
        
        QCheckBox {
            color: #333333;
        }
        
        QCheckBox::indicator {
            width: 16px;
            height: 16px;
            border: 1px solid #c0c0c0;
            border-radius: 3px;
            background-color: #ffffff;
        }
        
        QCheckBox::indicator:checked {
            background-color: #0078d7;
            border: 1px solid #0078d7;
        }
    """

def _get_dark_style():
    """Get the dark mode stylesheet"""
    return """
        /* Dark Mode */
        QMainWindow, QDialog {
            background-color: #1e1e1e;
            color: #f0f0f0;
        }
        
        QWidget {
            background-color: #1e1e1e;
            color: #f0f0f0;
        }
        
        QLabel {
            color: #f0f0f0;
        }
        
        QPushButton {
            background-color: #2d2d2d;
            border: 1px solid #3d3d3d;
            border-radius: 4px;
            padding: 6px 12px;
            color: #f0f0f0;
        }
        
        QPushButton:hover {
            background-color: #3d3d3d;
        }
        
        QPushButton:pressed {
            background-color: #4d4d4d;
        }
        
        QLineEdit {
            background-color: #2d2d2d;
            border: 1px solid #3d3d3d;
            border-radius: 4px;
            padding: 4px;
            color: #f0f0f0;
        }
        
        QTabWidget::pane {
            border: 1px solid #3d3d3d;
            background-color: #2d2d2d;
        }
        
        QTabBar::tab {
            background-color: #2d2d2d;
            border: 1px solid #3d3d3d;
            border-bottom: none;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            padding: 6px 12px;
            color: #f0f0f0;
        }
        
        QTabBar::tab:selected {
            background-color: #3d3d3d;
            border-bottom: 1px solid #3d3d3d;
        }
        
        QTabBar::tab:hover:!selected {
            background-color: #4d4d4d;
        }
        
        QFrame {
            border: 1px solid #3d3d3d;
            border-radius: 4px;
            background-color: #2d2d2d;
        }
        
        QListWidget {
            background-color: #2d2d2d;
            border: 1px solid #3d3d3d;
            border-radius: 4px;
            alternate-background-color: #252525;
        }
        
        QListWidget::item {
            padding: 4px;
            border-bottom: 1px solid #3d3d3d;
        }
        
        QListWidget::item:selected {
            background-color: #0078d7;
            color: #f0f0f0;
        }
        
        QListWidget::item:hover:!selected {
            background-color: #3d3d3d;
        }
        
        QProgressBar {
            border: 1px solid #3d3d3d;
            border-radius: 4px;
            background-color: #2d2d2d;
            text-align: center;
        }
        
        QProgressBar::chunk {
            background-color: #0078d7;
            width: 10px;
        }
        
        QCheckBox {
            color: #f0f0f0;
        }
        
        QCheckBox::indicator {
            width: 16px;
            height: 16px;
            border: 1px solid #3d3d3d;
            border-radius: 3px;
            background-color: #2d2d2d;
        }
        
        QCheckBox::indicator:checked {
            background-color: #0078d7;
            border: 1px solid #0078d7;
        }
    """ 