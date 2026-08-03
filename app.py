from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        sender = request.form["sender"]
        subject = request.form["subject"]
        email = request.form["email"]

        score = 0
        risk = "LOW"

        if "password" in email.lower():
            score += 25

        if "otp" in email.lower():
            score += 25

        if "urgent" in subject.lower():
            score += 20

        if "bit.ly" in email.lower():
            score += 30

        if score >= 70:
            risk = "HIGH"
        elif score >= 35:
            risk = "MEDIUM"

        return f"""
        <h1>AI Phishing Detection Result</h1>

        <h2>Risk Level: {risk}</h2>

        <h2>AI Confidence Score: {score}%</h2>

        <a href="/">Scan Another Email</a>
        """

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)