print("=== AI Phishing Email Detector ===")

email = input("Paste the email here:\n")

if "urgent" in email:
    print("⚠ Warning: The email contains the word 'urgent'.")
else:
    print("✅ No urgent keyword found.")