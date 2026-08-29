from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import styles
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from datetime import datetime


def generate_pdf(results, risk_score, risk_level):

    filename = f"pulse_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    doc = SimpleDocTemplate(filename)

    elements = []
    style = styles.getSampleStyleSheet()

    title_style = ParagraphStyle(
        'TitleStyle',
        parent=style['Heading1'],
        textColor=colors.HexColor("#003366")
    )

    elements.append(Paragraph("PULSE - Executive Security Report", title_style))
    elements.append(Spacer(1, 0.5 * inch))

    elements.append(Paragraph(f"Generated: {datetime.now()}", style['Normal']))
    elements.append(Spacer(1, 0.2 * inch))

    elements.append(Paragraph(f"Overall Risk Score: {risk_score}", style['Normal']))
    elements.append(Paragraph(f"Overall Risk Level: {risk_level}", style['Normal']))
    elements.append(Spacer(1, 0.5 * inch))

    for host, data in results.items():

        elements.append(Paragraph(f"Host: {host}", style['Heading2']))
        elements.append(Spacer(1, 0.2 * inch))

        # Open Ports Table
        port_data = [["Port", "Service", "Version"]]
        for port, info in data["ports"].items():
            port_data.append([
                str(port),
                info["service"],
                info["version"]
            ])

        if len(port_data) > 1:
            table = Table(port_data, repeatRows=1)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            elements.append(table)
            elements.append(Spacer(1, 0.5 * inch))

        # CVE Section
        if data.get("cves"):
            elements.append(Paragraph("Detected CVEs:", style['Heading3']))
            elements.append(Spacer(1, 0.2 * inch))

            for cve in data["cves"]:
                elements.append(Paragraph(
                    f"{cve['cve_id']} | {cve['severity']} | Score: {cve['score']}",
                    style['Normal']
                ))
                elements.append(Paragraph(cve["description"], style['Normal']))
                elements.append(Spacer(1, 0.2 * inch))

        elements.append(Spacer(1, 0.5 * inch))

    doc.build(elements)

    return filename
