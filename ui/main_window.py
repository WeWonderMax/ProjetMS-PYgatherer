import datetime, ast
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QPushButton, 
    QFileDialog, QMessageBox
)
from PyQt6.QtCore import QTimer
from .components import SearchBar, CustomTabWidget, TabManager
from .components.report_generator import ReportGenerator
from api.api import ThreatIntelClient

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.api_client = ThreatIntelClient()
        self.setup_ui()
        self.setup_connections()

    def setup_ui(self):
        """Setup the main window UI"""
        self.setWindowTitle("Threat Intelligence Tool")
        self.resize(1200, 800)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Search bar
        self.search_bar = SearchBar()
        layout.addWidget(self.search_bar)

        # Tab widget
        self.tab_widget = CustomTabWidget()
        self.tab_manager = TabManager(self.tab_widget)
        layout.addWidget(self.tab_widget)
        
        # Report button
        self.report_button = QPushButton("Generate Report")
        self.report_button.setEnabled(False)  # Disabled by default
        self.report_button.setStyleSheet("""
            QPushButton {
                padding: 8px 15px;
                background-color: #28a745;
                color: white;
                border: none;
                border-radius: 4px;
                margin: 5px;
            }
            QPushButton:hover {
                background-color: #218838;
            }
            QPushButton:disabled {
                background-color: #6c757d;
            }
        """)
        layout.addWidget(self.report_button)
        
        # Status bar
        self.statusBar().showMessage("Ready")

    def setup_connections(self):
        """Setup signal connections"""
        self.search_bar.search_triggered.connect(self.handle_search)
        self.report_button.clicked.connect(self.generate_report)
    
    def database(self, results):
        with open("ioc.csv", "r+") as nb:
            lines_number = len(nb.readlines())
        with open("ioc.csv", "a+") as file:
            print(lines_number)
            dictionnary = {lines_number+1:results}
            file.write(str(dictionnary)+"\n")
    
    def handle_search(self, search_term):
        """Handle search request"""
        result_table, map_view = self.tab_manager.create_results_tab(search_term)
        self.statusBar().showMessage(f"Searching for: {search_term}...")
        # Perform search
        results = self.api_client.analyze_ioc(search_term)
        result_table.update_data([results])
        self.database(results)
        # Update map if available
        if map_view and "ipstack" in results:
            ipstack_info = results["ipstack"]
            if ipstack_info:
                lat = ipstack_info.get("latitude")
                lon = ipstack_info.get("longitude")
                details = f"{ipstack_info.get('city', 'Unknown City')}, {ipstack_info.get('country', 'Unknown Country')}"
                map_view.update_location(lat, lon, details)
        
        # Enable report button
        self.report_button.setEnabled(True)
        
        QTimer.singleShot(2000, lambda: self.statusBar().showMessage("Ready"))

    def generate_report(self):
        """Generate and save PDF report"""
        try:
            # Get save file name
            filename, _ = QFileDialog.getSaveFileName(
                self,
                "Save Report",
                f"threat_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                "PDF Files (*.pdf)"
            )
            if filename:
                report = ReportGenerator(filename)
                report.report_header()
                count=1
                with open("ioc.csv", "r") as file:
                    for ioc in file:
                        ioc_dict = ast.literal_eval(ioc)
                        report.generate_report(ioc_dict[count], filename, ioc_dict[count]['ioc'])
                        count+=1
                report.pdf_build()
                QMessageBox.information(
                    self,
                    "Success",
                    f"Report successfully generated and saved to:\n{filename}"
                    )        
        except Exception as e:
            print(e)
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to generate report:\n{str(e)}"
            )
