print("========== AI Phishing Email Detector ==========")

email = input("Please enter the email content to analyze:\n")

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
    "winner"
]

count = 0
link_found = False
exclamation_found = False
reasons=[]

print("\n----- Scanning Email -----")

# Check suspicious keywords
for word in keywords:
    if word.lower() in email.lower():
        print(f"⚠ Suspicious keyword found: {word}")
        reasons.append(f"Suspicious keyword: {word}")
        count += 1

# Check suspicious links
if "http://" in email or "https://" in email or "bit.ly" in email or "tinyurl" in email:
    print("⚠ Suspicious link detected!")
    link_found = True
    reasons.append("Contains a suspicious link")

# Check too many exclamation marks
if email.count("!") >= 3:
    print("⚠ Too many exclamation marks detected!")
    exclamation_found = True
    reasons.append("Uses too many exclamation marks")
print("\n========== SECURITY REPORT ==========")


if count >= 5 or (link_found and count >= 2):
    print("\n🔴 Risk Level: HIGH")
elif count >= 2:
    print("\n🟡 Risk Level: MEDIUM")
else:
    print("\n🟢 Risk Level: LOW")

print("====================================")
print("\n========== AI ANALYSIS REPORT ==========")

if reasons:
    for reason in reasons:
        print("•", reason)
else:
    print("No suspicious indicators found.")

print("========================================")