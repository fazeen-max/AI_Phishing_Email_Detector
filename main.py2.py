print("========== AI PHISHING EMAIL DETECTOR ==========")

# User Input
sender = input("Enter sender email: ")
subject = input("Enter email subject: ")
email = input("Enter email content:\n")

# Variables
count = 0
score = 0
reasons = []

link_found = False
fake_sender = False
exclamation_found = False

# Lists
trusted_names = [
    "google",
    "paypal",
    "amazon",
    "microsoft",
    "bank"
]

suspicious_domains = [
    "g00gle",
    "paypaI",
    "amaz0n",
    "micr0soft",
    "faceb00k",
    "appIe",
    "0utlook"
]

suspicious_subjects = [
    "urgent",
    "verify",
    "congratulations",
    "won",
    "security alert",
    "action required",
    "limited time",
    "claim reward",
    "account suspended"
]

keywords = [
    "urgent",
    "verify",
    "password",
    "bank",
    "click",
    "account",
    "login",
    "otp",
    "payment",
    "winner",
    "alert",
    "reward",
    "gift",
    "limited",
    "offer",
    "claim",
    "free",
    "expired",
    "security",
    "update",
    "confirm",
    "invoice",
    "refund",
    "reset",
    "important",
    "immediately",
    "action required"
]

sensitive_info = [
    "password",
    "otp",
    "pin",
    "cvv",
    "credit card",
    "debit card",
    "bank account",
    "security code",
    "ssn"
]

attachments = [
    ".exe",
    ".zip",
    ".rar",
    ".js",
    ".scr",
    ".bat"
]

urgent_words = [
    "urgent",
    "immediately",
    "action required",
    "expired"
]

print("\n----- Scanning Email -----")

# Fake sender
for name in trusted_names:
    if name in email.lower():
        if "0" in email or "1" in email or "@" in email:
            print("⚠ Possible fake sender detected!")
            reasons.append("Possible fake sender")
            count += 1
            score += 10
            fake_sender = True

# Suspicious domain
for domain in suspicious_domains:
    if domain.lower() in sender.lower():
        print("⚠ Suspicious domain detected!")
        reasons.append("Suspicious look-alike domain")
        count += 2
        score += 15

# Subject check
for item in suspicious_subjects:
    if item in subject.lower():
        print(f"⚠ Suspicious subject: {item}")
        reasons.append(f"Subject contains '{item}'")
        count += 2
        score += 10

# Keywords
for word in keywords:
    if word in email.lower():
        print(f"⚠ Suspicious keyword: {word}")
        reasons.append(f"Keyword: {word}")
        count += 1
        score += 5

# Sensitive information
for item in sensitive_info:
    if item in email.lower():
        print(f"⚠ Sensitive information requested: {item}")
        reasons.append(f"Sensitive info: {item}")
        count += 2
        score += 15

# Suspicious links
if ("http://" in email.lower()
        or "https://" in email.lower()
        or "bit.ly" in email.lower()
        or "tinyurl" in email.lower()):
    print("⚠ Suspicious link detected!")
    reasons.append("Contains suspicious link")
    count += 2
    score += 20
    link_found = True

# Urgent language
for word in urgent_words:
    if word in email.lower():
        print(f"⚠ Urgent language: {word}")
        reasons.append(f"Urgent language: {word}")
        count += 1
        score += 10

# Attachments
for file in attachments:
    if file in email.lower():
        print(f"⚠ Suspicious attachment: {file}")
        reasons.append(f"Attachment: {file}")
        count += 2
        score += 15

# Exclamation marks
if email.count("!") >= 3:
    print("⚠ Too many exclamation marks!")
    reasons.append("Too many exclamation marks")
    count += 1
    score += 5
    # ---------------- SECURITY REPORT ----------------

if score > 100:
    score = 100

print("\n========== SECURITY REPORT ==========")

print(f"AI Confidence Score: {score}%")

if score >= 70:
    print("🔴 Risk Level: HIGH")
elif score >= 35:
    print("🟡 Risk Level: MEDIUM")
else:
    print("🟢 Risk Level: LOW")

print("\n========== AI ANALYSIS REPORT ==========")

if len(reasons) == 0:
    print("✅ No suspicious indicators found.")
else:
    for reason in reasons:
        print("•", reason)

print("======================================")

print("\n🛡 SECURITY TIPS")

if score >= 70:
    print("❌ Do NOT click any links.")
    print("❌ Do NOT download attachments.")
    print("❌ Never share your password or OTP.")
    print("✅ Verify the sender before replying.")
elif score >= 35:
    print("⚠ Be careful.")
    print("⚠ Verify the sender before taking action.")
    print("⚠ Avoid clicking unknown links.")
else:
    print("✅ This email appears relatively safe.")
    print("✅ Stay alert for future phishing attempts.")

print("\n========== Scan Completed ==========")