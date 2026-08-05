from flask import Flask, render_template, request
import re

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":

        sender = request.form["sender"]
        subject = request.form["subject"]
        email = request.form["email"]

        # Email statistics
        word_count = len(email.split())
        link_count = email.lower().count("http")
        attachment_count = 0

        # Detect URLs
        urls = re.findall(r'https?://\S+', email)

        url_results = []

        for url in urls:
            if "bit.ly" in url:
                url_results.append((url, "🔴 High Risk - Shortened URL"))
            elif "google.com" in url:
                url_results.append((url, "🟢 Trusted Domain"))
            else:
                url_results.append((url, "🟡 Unknown Domain"))

        sender_lower = sender.lower()

        score = 0
        risk = "LOW"
        reasons = []

        # Detect suspicious senders
        if "gmail.com" in sender_lower or "yahoo.com" in sender_lower or "hotmail.com" in sender_lower:
            score += 20
            reasons.append("⚠ Uses a free email provider")

        if "paypal" in sender_lower or "amazon" in sender_lower or "bank" in sender_lower:
            score += 20
            reasons.append("⚠ Sender impersonates a trusted organization")

        # Detect phishing keywords
        if "password" in email.lower():
            score += 25
            reasons.append("⚠ Requests your password")

        if "otp" in email.lower():
            score += 25
            reasons.append("⚠ Requests OTP")

        if "urgent" in subject.lower():
            score += 20
            reasons.append("⚠ Uses urgent language")

        if "bit.ly" in email.lower():
            score += 30
            reasons.append("⚠ Contains a shortened suspicious link")

        # Detect dangerous attachments
        attachments = [".exe", ".zip", ".rar", ".js", ".bat", ".scr"]

        for file in attachments:
            if file in email.lower():
                attachment_count += 1
                score += 20
                reasons.append(f"📎 Dangerous attachment detected: {file}")

        # Decide risk level
        if score >= 70:
            risk = "HIGH"
        elif score >= 35:
            risk = "MEDIUM"

        # Security recommendation
        if risk == "HIGH":
            recommendation = "❌ Do NOT click any links or download attachments. This email is very likely a phishing attempt."
        elif risk == "MEDIUM":
            recommendation = "⚠ Be cautious. Verify the sender and any links before responding."
        else:
            recommendation = "✅ This email appears relatively safe, but always verify the sender before sharing sensitive information."

        return render_template(
            "result.html",
            risk=risk,
            reasons=reasons,
            score=score,
            recommendation=recommendation,
            word_count=word_count,
            link_count=link_count,
            attachment_count=attachment_count,
            url_results=url_results
        )

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)