from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def generate_report(
    filename,
    risk,
    score,
    reasons,
    recommendation,
    word_count,
    link_count,
    attachment_count,
    threat_count,
    header_results
):

    c = canvas.Canvas(filename, pagesize=letter)

    y = 760

    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, y, "AI Phishing Email Detector Report")

    y -= 40

    c.setFont("Helvetica", 12)

    c.drawString(50, y, f"Risk Level: {risk}")
    y -= 20

    c.drawString(50, y, f"Confidence Score: {score}%")
    y -= 20

    c.drawString(50, y, f"Threats Detected: {threat_count}")
    y -= 30

    c.drawString(50, y, "Email Statistics")
    y -= 20

    c.drawString(70, y, f"Words: {word_count}")
    y -= 20

    c.drawString(70, y, f"Links: {link_count}")
    y -= 20

    c.drawString(70, y, f"Attachments: {attachment_count}")
    y -= 30

    c.drawString(50, y, "Detected Issues")
    y -= 20

    for reason in reasons:
        c.drawString(70, y, "- " + reason)
        y -= 20

    y -= 10

    c.drawString(50, y, "Header Analysis")
    y -= 20

    for result in header_results:
        c.drawString(70, y, "- " + result)
        y -= 20

    y -= 10

    c.drawString(50, y, "AI Recommendation")
    y -= 20

    c.drawString(70, y, recommendation)

    c.save()