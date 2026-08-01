print("=== AI Phishing Email Detector ===")

email = input("Paste the email here:\n")

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

for word in keywords:
    if word.lower() in email.lower():
        print(f"⚠ Suspicious keyword found: {word}")
        count += 1

print("\nTotal suspicious keywords:", count)

if count == 0:
    print("🟢 Risk Level: LOW")
elif count <= 3:
    print("🟡 Risk Level: MEDIUM")
else:
    print("🔴 Risk Level: HIGH")