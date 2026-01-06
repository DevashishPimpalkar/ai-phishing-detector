import re

PHISHING_KEYWORDS = [
    "urgent", "verify", "account suspended", "click below",
    "login immediately", "password", "confirm details",
    "security alert", "unusual activity"
]

SUSPICIOUS_DOMAINS = [
    ".ru", ".cn", ".tk", ".xyz"
]

def analyze_email(email_text):
    score = 0
    email_text_lower = email_text.lower()

    # Keyword check
    for word in PHISHING_KEYWORDS:
        if word in email_text_lower:
            score += 1

    # URL check
    urls = re.findall(r'https?://\S+', email_text_lower)
    for url in urls:
        for domain in SUSPICIOUS_DOMAINS:
            if domain in url:
                score += 2

    if score >= 5:
        return "🚨 Highly Suspicious (Phishing Likely)"
    elif score >= 3:
        return "⚠️ Suspicious — Be Careful"
    else:
        return "✅ Likely Safe"

if __name__ == "__main__":
    print("=== Phishing Email Detector ===")
    email = input("Paste email content here:\n\n")
    result = analyze_email(email)
    print("\nAnalysis Result:", result)

