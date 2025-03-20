"""
Report Generator Component
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from datetime import datetime

class ReportGenerator:
    """Generate PDF reports from analysis results"""

    @staticmethod
    def generate_report(results, filename):
        """Generate PDF report from analysis results"""
        doc = SimpleDocTemplate(filename, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        )
        story.append(Paragraph("Threat Intelligence Report", title_style))
        
        # Timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        story.append(Paragraph(f"Generated on: {timestamp}", styles["Normal"]))
        story.append(Spacer(1, 20))

        # IOC Information
        story.append(Paragraph("IOC Details", styles["Heading2"]))
        ioc_data = [
            ["Indicator", results.get("ioc", "N/A")],
            ["Type", results.get("ioc_type", "N/A")]
        ]
        ioc_table = Table(ioc_data, colWidths=[2*inch, 4*inch])
        ioc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(ioc_table)
        story.append(Spacer(1, 20))

        # VirusTotal Results
        if "virustotal" in results:
            story.append(Paragraph("VirusTotal Analysis", styles["Heading2"]))
            vt_info = results["virustotal"]
            if vt_info:
                vt_data = [
                    ["Detection Ratio", vt_info.get("detection_ratio", "N/A")],
                    ["Malicious", str(vt_info.get("malicious", "N/A"))],
                    ["Suspicious", str(vt_info.get("suspicious", "N/A"))],
                    ["Total Scans", str(vt_info.get("total_scans", "N/A"))]
                ]
                vt_table = Table(vt_data, colWidths=[2*inch, 4*inch])
                vt_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(vt_table)
            story.append(Spacer(1, 20))

        # Abuse.ch Results
        if "abusech" in results:
            story.append(Paragraph("Abuse.ch Analysis", styles["Heading2"]))
            abuse_info = results["abusech"]
            if abuse_info:
                abuse_data = [
                    ["File Type", abuse_info.get("file_type", "N/A")],
                    ["Signature", abuse_info.get("signature", "N/A")],
                    ["Reporter", abuse_info.get("reporter", "N/A")],
                    ["Tags", ", ".join(abuse_info.get("tags", []))]
                ]
                abuse_table = Table(abuse_data, colWidths=[2*inch, 4*inch])
                abuse_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(abuse_table)
            story.append(Spacer(1, 20))

        # IPStack Results
        if "ipstack" in results:
            story.append(Paragraph("Geolocation Information", styles["Heading2"]))
            ip_info = results["ipstack"]
            if ip_info:
                ip_data = [
                    ["Country", ip_info.get("country", "N/A")],
                    ["Region", ip_info.get("region", "N/A")],
                    ["City", ip_info.get("city", "N/A")],
                    ["Latitude", str(ip_info.get("latitude", "N/A"))],
                    ["Longitude", str(ip_info.get("longitude", "N/A"))]
                ]
                ip_table = Table(ip_data, colWidths=[2*inch, 4*inch])
                ip_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(ip_table)

        # Build PDF
        doc.build(story)
