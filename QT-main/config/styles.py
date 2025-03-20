"""
Configuration file for application styles and colors
"""

COLORS = {
    'background': '#FFFFFF',      # White background
    'foreground': '#000000',      # Black text
    'primary': '#F5F5F5',        # Very light gray
    'secondary': '#E0E0E0',      # Light gray
    'accent': '#BDBDBD',         # Medium gray
    'border': '#9E9E9E',         # Dark gray
    'vt_color': '#4CAF50',       # Green for VirusTotal
    'abuse_color': '#FF9800',    # Orange for Abuse.ch
    'ipstack_color': '#2196F3',  # Blue for IPStack
    'error': '#F44336',          # Red for errors
    'success': '#4CAF50',        # Green for success
    'warning': '#FFC107'         # Yellow for warnings
}

STYLESHEET = f"""
    /* Main Widget Styles */
    QWidget {{
        background-color: {COLORS['background']};
        color: {COLORS['foreground']};
        border-radius: 8px;
        font-family: 'Segoe UI', sans-serif;
        font-size: 14px;
    }}

    /* Input Field Styles */
    QLineEdit {{
        background-color: {COLORS['background']};
        color: {COLORS['foreground']};
        border: 1px solid {COLORS['border']};
        border-radius: 6px;
        padding: 7px;
        margin: 2px;
    }}

    QLineEdit:focus {{
        border: 2px solid {COLORS['accent']};
    }}

    /* Button Styles */
    QPushButton {{
        background-color: {COLORS['primary']};
        color: {COLORS['foreground']};
        border: none;
        border-radius: 6px;
        padding: 10px 20px;
        font-weight: bold;
        min-width: 80px;
    }}

    QPushButton:hover {{
        background-color: {COLORS['secondary']};
    }}

    QPushButton:pressed {{
        background-color: {COLORS['accent']};
    }}

    QPushButton:disabled {{
        background-color: {COLORS['border']};
        color: {COLORS['secondary']};
    }}

    /* Table Styles */
    QTableWidget {{
        background-color: {COLORS['background']};
        border: 1px solid {COLORS['border']};
        gridline-color: {COLORS['border']};
        border-radius: 4px;
    }}

    QTableWidget::item {{
        padding: 7px;
        color: {COLORS['foreground']};
    }}

    QTableWidget::item:selected {{
        background-color: {COLORS['accent']};
        color: {COLORS['background']};
    }}

    QHeaderView::section {{
        background-color: {COLORS['primary']};
        color: {COLORS['foreground']};
        border: 1px solid {COLORS['border']};
        padding: 7px;
        font-weight: bold;
    }}

    /* Tab Widget Styles */
    QTabWidget::pane {{
        border: 1px solid {COLORS['border']};
        background-color: {COLORS['background']};
        border-radius: 4px;
    }}

    QTabBar::tab {{
        background-color: {COLORS['background']};
        color: {COLORS['foreground']};
        border: 1px solid {COLORS['border']};
        border-bottom: none;
        padding: 8px 15px;
        margin-right: 2px;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
    }}

    QTabBar::tab:selected {{
        background-color: {COLORS['accent']};
        color: {COLORS['background']};
    }}

    QTabBar::tab:hover:!selected {{
        background-color: {COLORS['secondary']};
    }}

    /* Progress Bar Styles */
    QProgressBar {{
        border: 1px solid {COLORS['border']};
        border-radius: 4px;
        text-align: center;
        padding: 1px;
        background-color: {COLORS['background']};
    }}

    QProgressBar::chunk {{
        background-color: {COLORS['success']};
        border-radius: 3px;
    }}

    /* Scroll Bar Styles */
    QScrollBar:vertical {{
        border: none;
        background-color: {COLORS['background']};
        width: 10px;
        margin: 0px;
    }}

    QScrollBar::handle:vertical {{
        background-color: {COLORS['border']};
        border-radius: 5px;
        min-height: 20px;
    }}

    QScrollBar::handle:vertical:hover {{
        background-color: {COLORS['accent']};
    }}

    QScrollBar:horizontal {{
        border: none;
        background-color: {COLORS['background']};
        height: 10px;
        margin: 0px;
    }}

    QScrollBar::handle:horizontal {{
        background-color: {COLORS['border']};
        border-radius: 5px;
        min-width: 20px;
    }}

    QScrollBar::handle:horizontal:hover {{
        background-color: {COLORS['accent']};
    }}

    /* Message Box Styles */
    QMessageBox {{
        background-color: {COLORS['background']};
    }}

    QMessageBox QPushButton {{
        min-width: 100px;
    }}

    /* Label Styles */
    QLabel {{
        color: {COLORS['foreground']};
        padding: 2px;
    }}

    /* Tooltip Styles */
    QToolTip {{
        background-color: {COLORS['background']};
        color: {COLORS['foreground']};
        border: 1px solid {COLORS['border']};
        padding: 5px;
    }}
"""

# Additional style configurations
FONT_SIZES = {
    'small': '12px',
    'medium': '14px',
    'large': '16px',
    'header': '18px',
    'title': '24px'
}

MARGINS = {
    'small': '5px',
    'medium': '10px',
    'large': '15px'
}

PADDING = {
    'small': '5px',
    'medium': '10px',
    'large': '15px'
}

# Icon sizes
ICON_SIZES = {
    'small': 16,
    'medium': 24,
    'large': 32,
    'xlarge': 48
}

# Animation durations (in milliseconds)
ANIMATIONS = {
    'fast': 150,
    'normal': 250,
    'slow': 350
}
