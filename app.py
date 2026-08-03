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
        reasons = []

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

        if score >= 70:
            risk = "HIGH"
        elif score >= 35:
            risk = "MEDIUM"

        return render_template(
            "result.html",
            risk=risk,
            score=score,
            reasons=reasons
        )

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)