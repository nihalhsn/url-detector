import random
import csv
import os

phishing_keywords = [
    "login", "verify", "secure", "account", "update",
    "banking", "confirm", "password", "alert", "security",
    "billing", "urgent", "wallet", "crypto", "signin"
]

domains = [
    "paypal", "google", "facebook", "amazon", "netflix",
    "apple", "bankofamerica", "microsoft", "instagram",
    "whatsapp", "binance", "icloud", "steam"
]

tlds = [".com", ".net", ".org", ".xyz", ".tk", ".cf", ".ga", ".ml"]

legit_sites = [
    "https://google.com",
    "https://amazon.in",
    "https://facebook.com",
    "https://github.com",
    "https://stackoverflow.com",
    "https://microsoft.com",
    "https://apple.com",
    "https://linkedin.com",
    "https://twitter.com",
    "https://netflix.com",
    "https://flipkart.com",
    "https://wikipedia.org",
    "https://openai.com"
]

def generate_phishing_url():
    domain = random.choice(domains)
    keyword = random.choice(phishing_keywords)
    tld = random.choice(tlds)

    patterns = [
        f"http://{domain}-{keyword}{tld}",
        f"http://{keyword}-{domain}{tld}",
        f"http://{domain}-{keyword}-secure{tld}",
        f"http://secure-{domain}-{keyword}{tld}",
        f"http://{domain}.verify-{keyword}{tld}",
        f"http://{domain}-account-{keyword}{tld}"
    ]

    return random.choice(patterns)

data = []

# 500 phishing
for _ in range(500):
    data.append([generate_phishing_url(), 1])

# 500 legit
for _ in range(500):
    data.append([random.choice(legit_sites), 0])

# Shuffle dataset
random.shuffle(data)

# Save to CSV
with open("phishing_dataset.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["url", "label"])
    writer.writerows(data)

print("Dataset generated successfully!")

print("Saved at:", os.path.abspath("phishing_dataset.csv"))