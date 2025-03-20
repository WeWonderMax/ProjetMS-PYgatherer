"""
Search Bar Component
"""

from PyQt6.QtWidgets import (
    QWidget,
    QHBoxLayout,
    QLineEdit,
    QPushButton
)
from PyQt6.QtCore import pyqtSignal

class SearchBar(QWidget):
    """Search bar component"""
    
    # Signal émis lors d'une recherche
    search_triggered = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.setup_connections()

    def setup_ui(self):
        """Setup the search bar UI"""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Search input
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter IP, domain, URL or file hash...")
        layout.addWidget(self.search_input)
        
        # Search button
        self.search_button = QPushButton("Search")
        layout.addWidget(self.search_button)
        
        # Set style
        self.setStyleSheet("""
            QLineEdit {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 3px;
            }
            QPushButton {
                padding: 5px 15px;
                background-color: #007bff;
                color: white;
                border: none;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
        """)

    def setup_connections(self):
        """Setup signal connections"""
        self.search_button.clicked.connect(self.trigger_search)
        self.search_input.returnPressed.connect(self.trigger_search)

    def trigger_search(self):
        """Emit search signal with input text"""
        search_text = self.search_input.text().strip()
        if search_text:
            self.search_triggered.emit(search_text)
