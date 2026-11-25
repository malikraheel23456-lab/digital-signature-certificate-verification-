"""PDF report generation for an individual verification attempt."""
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import mm


def create_verification_pdf(result):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm,
                            topMargin=18*mm, bottomMargin=18*mm)
    styles = getSampleStyleSheet()
    story = [Paragraph("Digital Signature Verification Report", styles["Title"]),
             Spacer(1, 8*mm),
             Paragraph("Academic prototype report — RSA-PSS + SHA-256", styles["Normal"]),
             Spacer(1, 8*mm)]
    rows = [
        ["Field", "Result"],
        ["Document", result.get("filename", "Unknown")],
        ["Verification time", result.get("timestamp", "")],
        ["Digital signature", result.get("signature_status", "NOT CHECKED")],
        ["Simulated key trust", result.get("trust_status", "NOT CHECKED")],
        ["Trust record owner", result.get("owner") or "Not supplied"],
        ["SHA-256 public-key fingerprint", result.get("fingerprint", "")],
    ]
    table = Table(rows, colWidths=[55*mm, 110*mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#17365D")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#B7C9D6")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 7),
        ("RIGHTPADDING", (0,0), (-1,-1), 7),
        ("TOPPADDING", (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
    ]))
    story.extend([table, Spacer(1, 8*mm),
                  Paragraph("Interpretation", styles["Heading2"]),
                  Paragraph(result.get("interpretation", ""), styles["BodyText"]),
                  Spacer(1, 5*mm),
                  Paragraph("Important: A valid signature confirms that the corresponding private key signed these exact document bytes. The simulated trust record is an educational model, not an X.509 certificate or production certificate authority.", styles["Italic"])])
    doc.build(story)
    return buffer.getvalue()
