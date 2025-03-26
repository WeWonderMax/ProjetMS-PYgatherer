"""
Custom Tab Widget Component
"""

from PyQt6.QtWidgets import (
    QTabWidget,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QSplitter,
    QTabBar
)
from PyQt6.QtCore import Qt

from .result_table import ResultTable
from .map_view import MapView
import ast

class CustomTabWidget(QTabWidget):
    """Custom tab widget with closable tabs"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        """Setup the tab widget UI"""
        self.setTabsClosable(True)
        self.setMovable(True)
        self.tabCloseRequested.connect(self.close_tab)
        
        # Welcome tab
        self.add_welcome_tab()

    def add_welcome_tab(self):
        """Add welcome tab"""
        welcome_widget = QWidget()
        layout = QVBoxLayout(welcome_widget)
        
        welcome_label = QLabel("Welcome to Threat Intelligence Tool")
        welcome_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(welcome_label)
        
        self.addTab(welcome_widget, "Welcome")
        self.setTabsClosable(True)
        # Disable close button for welcome tab
        self.tabBar().setTabButton(0, QTabBar.ButtonPosition.RightSide, None)

    def close_tab(self, index):
        """Close tab at given index"""       
        with open("ioc.csv", mode='r', encoding='utf-8') as fichier_csv:
            lignes = fichier_csv.readlines()       
        with open("ioc.csv", "w+") as file:
            new_count=1
            old_count=1
            for ligne in lignes:
                ioc_dict = ast.literal_eval(ligne)
                if index != next(iter(ioc_dict)):
                    dictionnary = {new_count:ioc_dict[old_count]}
                    file.write(str(dictionnary)+"\n")
                    new_count+=1
                old_count+=1
        if index != 0:  # Don't close welcome tab
             self.removeTab(index)

class TabManager:
    """Manager for handling tabs"""
    
    def __init__(self, tab_widget):
        self.tab_widget = tab_widget
        self.tabs = {}  # Store tab references

    def create_results_tab(self, search_term):
        """Create new tab for search results"""
        # Create tab content
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create splitter for table and map
        splitter = QSplitter()
        splitter.setOrientation(Qt.Orientation.Horizontal)
        
        # Add result table
        result_table = ResultTable()
        splitter.addWidget(result_table)
        
        # Add map view if search term looks like an IP
        map_view = None
        if "." in search_term and not any(c.isalpha() for c in search_term):
            map_view = MapView()
            splitter.addWidget(map_view)
            # Set splitter proportions
            splitter.setStretchFactor(0, 2)  # Table takes 2/3
            splitter.setStretchFactor(1, 1)  # Map takes 1/3
        
        layout.addWidget(splitter)
        
        # Add tab
        tab_title = f"Search: {search_term}"
        index = self.tab_widget.addTab(tab, tab_title)
        self.tab_widget.setCurrentIndex(index)
        
        # Store references
        self.tabs[tab_title] = {
            'widget': tab,
            'table': result_table,
            'map': map_view
        }
        
        return result_table, map_view  # Return both table and map view

    def get_current_table(self):
        """Get result table of current tab"""
        current_widget = self.tab_widget.currentWidget()
        if current_widget:
            return current_widget.findChild(ResultTable)
        return None

    def close_all_results(self):
        """Close all result tabs"""
        while self.tab_widget.count() > 1:  # Keep welcome tab
            self.tab_widget.removeTab(1)
        self.tabs.clear()
        with open('ioc.csv', 'w') as file:
            pass