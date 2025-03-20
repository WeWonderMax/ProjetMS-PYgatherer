"""
Result Table Component
"""

from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView
from PyQt6.QtCore import Qt

class ResultTable(QTableWidget):
    """Table for displaying search results"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        """Setup the table UI"""
        # Set columns
        self.setColumnCount(4)
        self.setHorizontalHeaderLabels([
            "IOC",
            "Type",
            "Risk Score",
            "Details"
        ])
        
        # Set table properties
        self.setAlternatingRowColors(True)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        
        # Set column widths
        header = self.horizontalHeader()
        header.setStretchLastSection(True)
        
        # Set style
        self.setStyleSheet("""
            QTableWidget {
                background-color: white;
                alternate-background-color: #f5f5f5;
                gridline-color: #ddd;
            }
            QHeaderView::section {
                background-color: #f0f0f0;
                padding: 5px;
                border: 1px solid #ddd;
            }
            QTableWidget::item {
                padding: 5px;
            }
        """)

    def add_result(self, ioc: str, ioc_type: str, risk_score: int, details: str):
        """Add a result row to the table"""
        row = self.rowCount()
        self.insertRow(row)
        
        # Add items
        self.setItem(row, 0, QTableWidgetItem(ioc))
        self.setItem(row, 1, QTableWidgetItem(ioc_type))
        self.setItem(row, 2, QTableWidgetItem(str(risk_score)))
        self.setItem(row, 3, QTableWidgetItem(details))

    def update_data(self, data_list):
        """Update table with new data"""
        self.setRowCount(0)  # Clear existing rows
        
        for data in data_list:
            ioc = data.get("ioc", "N/A")
            ioc_type = data.get("ioc_type", "N/A")
            
            # Format details with clear API source identification
            details = []
            
            # VirusTotal Information
            vt_info = data.get("virustotal", {})
            if vt_info:
                details.append("=== VirusTotal Analysis ===")
                details.append(f"Detection Ratio: {vt_info.get('detection_ratio', 'N/A')}")
                details.append(f"Malicious: {vt_info.get('malicious', 0)}")
                details.append(f"Suspicious: {vt_info.get('suspicious', 0)}")
                details.append(f"Total Scans: {vt_info.get('total_scans', 0)}")
                details.append("")  # Empty line for separation

            # Type-specific additional information
            if ioc_type == "ip":
                ipstack_info = data.get("ipstack", {})
                if ipstack_info:
                    details.append("=== IPStack Geolocation ===")
                    details.append(f"Country: {ipstack_info.get('country', 'N/A')}")
                    details.append(f"Region: {ipstack_info.get('region', 'N/A')}")
                    details.append(f"City: {ipstack_info.get('city', 'N/A')}")
                    details.append(f"Latitude: {ipstack_info.get('latitude', 'N/A')}")
                    details.append(f"Longitude: {ipstack_info.get('longitude', 'N/A')}")
                    details.append("")

            elif ioc_type == "hash":
                abuse_info = data.get("abusech", {})
                if abuse_info:
                    details.append("=== Abuse.ch MalwareBazaar ===")
                    details.append(f"File Type: {abuse_info.get('file_type', 'N/A')}")
                    details.append(f"Signature: {abuse_info.get('signature', 'N/A')}")
                    details.append(f"Reporter: {abuse_info.get('reporter', 'N/A')}")
                    details.append(f"Tags: {', '.join(abuse_info.get('tags', []))}")
                    details.append("")

            # Calculate risk score based on VirusTotal results
            if vt_info:
                malicious = vt_info.get('malicious', 0)
                suspicious = vt_info.get('suspicious', 0)
                total = vt_info.get('total_scans', 0)
                if total > 0:
                    risk_score = f"{malicious + suspicious}/{total}"
                else:
                    risk_score = "N/A"
            else:
                risk_score = "N/A"

            # Add row to table
            row = self.rowCount()
            self.insertRow(row)
            
            # Create and set items
            ioc_item = QTableWidgetItem(ioc)
            type_item = QTableWidgetItem(ioc_type)
            score_item = QTableWidgetItem(risk_score)
            details_item = QTableWidgetItem("\n".join(details))

            # Set items with custom formatting
            self.setItem(row, 0, ioc_item)
            self.setItem(row, 1, type_item)
            self.setItem(row, 2, score_item)
            self.setItem(row, 3, details_item)

            # Adjust row height for multi-line content
            self.resizeRowToContents(row)

            # Optional: Add some styling
            for col in range(4):
                item = self.item(row, col)
                if item:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
