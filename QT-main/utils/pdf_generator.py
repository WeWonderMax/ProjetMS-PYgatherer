"""
PDF Generator utility for creating detailed threat intelligence reports
"""

import os
from datetime import datetime
import logging
from typing import Dict, List, Optional, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image,
    PageBreak,
    Flowable
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HorizontalLine(Flowable):
    """Custom Flowable for drawing horizontal lines"""
    
    def __init__(self, width: int, color: str = '#000000'):
        Flowable.__init__(self)
        self.width = width
        self.color = color

    def draw(self):
        """Draw the line"""
        self.canv.setStrokeColor(self.color)
        self.canv.line(0, 0, self.width, 0)

class PDFGenerator:
    """Generator class for creating PDF reports from threat intelligence data"""

    def __init__(self, output_dir: str = "reports"):
        """
        Initialize PDF Generator
        
        Args:
            output_dir: Directory where reports will be saved
        """
        self.output_dir = output_dir
        self.ensure_output_dir()
        self.setup_styles()

    def ensure_output_dir(self):
        """Ensure output directory exists"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def setup_styles(self):
        """Setup document styles"""
        self.styles = getSampleStyleSheet()
        
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#2196F3'),
            alignment=TA_CENTER
        ))
        
        # Heading styles
        self.styles.add(ParagraphStyle(
            name='CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=12,
            textColor=colors.HexColor('#1976D2')
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=10,
            textColor=colors.HexColor('#4CAF50')
        ))
        
        # Normal text style
        self.styles.add(ParagraphStyle(
            name='CustomNormal',
            parent=self.styles['Normal'],
            fontSize=12,
            spaceAfter=8,
            textColor=colors.HexColor('#333333')
        ))
        
        # Table header style
        self.styles.add(ParagraphStyle(
            name='TableHeader',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.white,
            alignment=TA_CENTER
        ))

    def generate_report(self, data: Dict[str, Any], filename: Optional[str] = None) -> str:
        """
        Generate PDF report from threat intelligence data
        
        Args:
            data: Dictionary containing threat intelligence data
            filename: Optional custom filename for the report
            
        Returns:
            Path to the generated PDF file
        """
        try:
            # Generate filename if not provided
            if filename is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"threat_intel_report_{timestamp}.pdf"
            
            filepath = os.path.join(self.output_dir, filename)
            
            # Create document
            doc = SimpleDocTemplate(
                filepath,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )
            
            # Build story (content)
            story = []
            story.extend(self._create_header(data))
            story.extend(self._create_summary(data))
            
            # Add data sections
            if 'virustotal' in data:
                story.extend(self._create_virustotal_section(data['virustotal']))
            
            if 'abusech' in data:
                story.extend(self._create_abusech_section(data['abusech']))
            
            if 'ipstack' in data:
                story.extend(self._create_ipstack_section(data['ipstack']))
            
            # Add footer
            story.extend(self._create_footer())
            
            # Build PDF
            doc.build(story)
            logger.info(f"Report generated successfully: {filepath}")
            
            return filepath
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            raise

    def _create_header(self, data: Dict[str, Any]) -> List[Flowable]:
        """Create report header section"""
        elements = []
        
        # Title
        elements.append(Paragraph(
            "Threat Intelligence Report",
            self.styles['CustomTitle']
        ))
        
        # Timestamp and IOC info
        elements.append(Paragraph(
            f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            self.styles['CustomNormal']
        ))
        
        if 'ioc' in data:
            elements.append(Paragraph(
                f"Indicator of Compromise: {data['ioc']}",
                self.styles['CustomNormal']
            ))
            elements.append(Paragraph(
                f"Type: {data.get('ioc_type', 'Unknown')}",
                self.styles['CustomNormal']
            ))
        
        elements.append(HorizontalLine(450))
        elements.append(Spacer(1, 20))
        
        return elements

    def _create_summary(self, data: Dict[str, Any]) -> List[Flowable]:
        """Create executive summary section"""
        elements = []
        
        elements.append(Paragraph(
            "Executive Summary",
            self.styles['CustomHeading1']
        ))
        
        # Create summary based on available data
        summary_points = []
        
        if 'virustotal' in data:
            vt_data = data['virustotal']
            if vt_data:
                detection_ratio = vt_data.get('detection_ratio', '0/0')
                summary_points.append(f"VirusTotal Analysis: Detection ratio {detection_ratio}")
        
        if 'abusech' in data:
            abuse_data = data['abusech']
            if abuse_data:
                summary_points.append(f"Abuse.ch Analysis: {abuse_data.get('status', 'No status available')}")
        
        if 'ipstack' in data:
            ip_data = data['ipstack']
            if ip_data:
                location = f"{ip_data.get('city', '')}, {ip_data.get('country', '')}"
                summary_points.append(f"Geolocation: {location.strip(', ')}")
        
        summary_text = "This report provides analysis results from multiple threat intelligence sources.\n\n"
        summary_text += "\n".join(f"• {point}" for point in summary_points)
        
        elements.append(Paragraph(summary_text, self.styles['CustomNormal']))
        elements.append(Spacer(1, 20))
        
        return elements

    def _create_virustotal_section(self, vt_data: Dict[str, Any]) -> List[Flowable]:
        """Create VirusTotal section"""
        elements = []
        
        elements.append(Paragraph(
            "VirusTotal Analysis",
            self.styles['CustomHeading2']
        ))
        
        if vt_data:
            # Create table data
            table_data = [[
                Paragraph("Metric", self.styles['TableHeader']),
                Paragraph("Value", self.styles['TableHeader'])
            ]]
            
            for key, value in vt_data.items():
                table_data.append([
                    Paragraph(str(key), self.styles['CustomNormal']),
                    Paragraph(str(value), self.styles['CustomNormal'])
                ])
            
            # Create and style table
            table = Table(table_data, colWidths=[200, 300])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2196F3')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(table)
        else:
            elements.append(Paragraph(
                "No VirusTotal data available.",
                self.styles['CustomNormal']
            ))
        
        elements.append(Spacer(1, 20))
        return elements

    def _create_abusech_section(self, abuse_data: Dict[str, Any]) -> List[Flowable]:
        """Create Abuse.ch section"""
        elements = []
        
        elements.append(Paragraph(
            "Abuse.ch Analysis",
            self.styles['CustomHeading2']
        ))
        
        if abuse_data:
            table_data = [[
                Paragraph("Attribute", self.styles['TableHeader']),
                Paragraph("Value", self.styles['TableHeader'])
            ]]
            
            for key, value in abuse_data.items():
                table_data.append([
                    Paragraph(str(key), self.styles['CustomNormal']),
                    Paragraph(str(value), self.styles['CustomNormal'])
                ])
            
            table = Table(table_data, colWidths=[200, 300])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4CAF50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(table)
        else:
            elements.append(Paragraph(
                "No Abuse.ch data available.",
                self.styles['CustomNormal']
            ))
        
        elements.append(Spacer(1, 20))
        return elements

    def _create_ipstack_section(self, ipstack_data: Dict[str, Any]) -> List[Flowable]:
        """Create IPStack section"""
        elements = []
        
        elements.append(Paragraph(
            "Geolocation Analysis",
            self.styles['CustomHeading2']
        ))
        
        if ipstack_data:
            table_data = [[
                Paragraph("Location Attribute", self.styles['TableHeader']),
                Paragraph("Value", self.styles['TableHeader'])
            ]]
            
            for key, value in ipstack_data.items():
                table_data.append([
                    Paragraph(str(key), self.styles['CustomNormal']),
                    Paragraph(str(value), self.styles['CustomNormal'])
                ])
            
            table = Table(table_data, colWidths=[200, 300])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#FF9800')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(table)
        else:
            elements.append(Paragraph(
                "No geolocation data available.",
                self.styles['CustomNormal']
            ))
        
        elements.append(Spacer(1, 20))
        return elements

    def _create_footer(self) -> List[Flowable]:
        """Create report footer"""
        elements = []
        
        elements.append(HorizontalLine(450))
        elements.append(Spacer(1, 10))
        
        footer_text = (
            "This report was automatically generated. "
            "The information provided should be validated before taking action."
        )
        elements.append(Paragraph(
            footer_text,
            self.styles['CustomNormal']
        ))
        
        return elements

if __name__ == "__main__":
    # Test the PDF generator
    test_data = {
        'ioc': '8.8.8.8',
        'ioc_type': 'IP',
        'virustotal': {
            'detection_ratio': '0/72',
            'total_scans': 72,
            'malicious': 0
        },
        'abusech': {
            'status': 'clean',
            'file_type': 'N/A',
            'signature': 'N/A'
        },
        'ipstack': {
            'country': 'United States',
            'city': 'Mountain View',
            'latitude': '37.386051',
            'longitude': '-122.083855'
        }
    }
    
    generator = PDFGenerator()
    pdf_path = generator.generate_report(test_data)
    print(f"Report generated: {pdf_path}")
