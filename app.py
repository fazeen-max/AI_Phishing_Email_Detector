from flask import Flask, render_template, request, send_file
import re
import time
from pdf_report import generate_report
app = Flask(__name__)
@app.route("/", methods=["GET", "POST"])
def home():

    if request.method == "POST":
        start_time = time.time()

        # -----------------------------
        # Get Form Data
        # -----------------------------
        sender = request.form.get("sender", "")
        subject = request.form.get("subject", "")
        email = request.form.get("email", "")
        header = request.form.get("header", "")

        # -----------------------------
        # Upload .eml File
        # -----------------------------
        email_file = request.files.get("email_file")

        if email_file and email_file.filename.endswith(".eml"):
            email = email_file.read().decode("utf-8", errors="ignore")

        # -----------------------------
        # Email Statistics
        # -----------------------------
        word_count = len(email.split())
        link_count = len(re.findall(r'https?://\S+', email))
        attachment_count = 0

        # -----------------------------
        # URL Detection
        # -----------------------------
        urls = re.findall(r'https?://\S+', email)

        trusted_domains = [
            "google.com",
            "microsoft.com",
            "github.com",
            "openai.com",
            "amazon.com",
            "paypal.com",
            "apple.com",
            "linkedin.com",
            "facebook.com"
        ]

        url_results = []

        for url in urls:

            if any(short in url for short in ["bit.ly", "tinyurl.com", "t.co"]):
                url_results.append((url, "🔴 High Risk - Shortened URL"))

            elif any(domain in url for domain in trusted_domains):
                url_results.append((url, "🟢 Trusted Domain"))

            else:
                url_results.append((url, "🟡 Unknown or Suspicious Domain"))

        # -----------------------------
        # Initialize Variables
        # -----------------------------
        sender_lower = sender.lower()

        score = 0
        risk = "LOW"
        reasons = []
        threat_count = 0
        header_results = []
        # -----------------------------
        # Email Header Analysis
        # -----------------------------
        if header:

            if "spf: fail" in header.lower():
                header_results.append("❌ SPF Authentication Failed")
                score += 15
                threat_count += 1

            elif "spf: pass" in header.lower():
                header_results.append("✅ SPF Passed")

            if "dkim: fail" in header.lower():
                header_results.append("❌ DKIM Authentication Failed")
                score += 15
                threat_count += 1

            elif "dkim: pass" in header.lower():
                header_results.append("✅ DKIM Passed")

            if "dmarc: fail" in header.lower():
                header_results.append("❌ DMARC Authentication Failed")
                score += 15
                threat_count += 1

            elif "dmarc: pass" in header.lower():
                header_results.append("✅ DMARC Passed")

            ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", header)

            if ip_match:
                header_results.append(f"🌍 Sender IP: {ip_match.group()}")

        # -----------------------------
        # Sender Analysis
        # -----------------------------
        if (
            "gmail.com" in sender_lower
            or "yahoo.com" in sender_lower
            or "hotmail.com" in sender_lower
        ):
            score += 20
            reasons.append("⚠ Uses a free email provider")
            threat_count += 1

        if (
            "paypal" in sender_lower
            or "amazon" in sender_lower
            or "bank" in sender_lower
        ):
            score += 20
            reasons.append("⚠ Sender may impersonate a trusted organization")
            threat_count += 1

        # -----------------------------
        # Email Content Analysis
        # -----------------------------
        phishing_keywords = {
            "password": 25,
            "otp": 25,
            "urgent": 20,
            "verify": 15,
            "login": 15,
            "account": 10,
            "click here": 20,
            "confirm": 10,
            "gift": 15,
            "winner": 15,
            "bank": 20
        }

        email_lower = email.lower()
        subject_lower = subject.lower()

        for keyword, points in phishing_keywords.items():

            if keyword in email_lower or keyword in subject_lower:
                score += points
                threat_count += 1
                reasons.append(f"⚠ Suspicious keyword detected: {keyword}")
                # -----------------------------
        # Detect Dangerous Attachments
        # -----------------------------
        dangerous_extensions = [".exe", ".zip", ".rar", ".js", ".bat", ".scr"]

        for ext in dangerous_extensions:
            if ext in email.lower():
                attachment_count += 1
                score += 20
                threat_count += 1
                reasons.append(f"📎 Dangerous attachment detected: {ext}")

        # -----------------------------
        # Decide Risk Level
        # -----------------------------
        if score >= 70:
            risk = "HIGH"
        elif score >= 35:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        # -----------------------------
        # AI Recommendation
        # -----------------------------
        if risk == "HIGH":
            recommendation = (
                "❌ Do NOT click any links or download attachments. "
                "This email is very likely a phishing attempt."
            )
        elif risk == "MEDIUM":
            recommendation = (
                "⚠ Be cautious. Verify the sender and any links before responding."
            )
        else:
            recommendation = (
                "✅ This email appears relatively safe, but always verify the sender "
                "before sharing sensitive information."
            )
            

        # -----------------------------
        # Show Results
        # -----------------------------
        scan_time = round(time.time() - start_time, 3)
        return render_template(
            "result.html",
            risk=risk,
            reasons=reasons,
            score=score,
            recommendation=recommendation,
            word_count=word_count,
            link_count=link_count,
            attachment_count=attachment_count,
            url_results=url_results,
            threat_count=threat_count,
            header_results=header_results,
            scan_time=scan_time,
        )

    return render_template("index.html")
@app.route("/download-report")
def download_report():

    filename = "AI_Phishing_Report.pdf"

    generate_report(
        filename=filename,
        risk="HIGH",
        score=85,
        reasons=[
            "Requests your password",
            "Contains shortened URL",
            "Dangerous attachment detected"
        ],
        recommendation="Do NOT click links or download attachments.",
        word_count=120,
        link_count=2,
        attachment_count=1,
        threat_count=4,
        header_results=[
            "❌ SPF Authentication Failed",
            "❌ DKIM Authentication Failed",
            "❌ DMARC Authentication Failed"
        ]
    )

    return send_file(filename, as_attachment=True)
if __name__ == "__main__":
    app.run(debug=True)
