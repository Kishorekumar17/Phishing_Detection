import requests
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
import pickle
import re
import tldextract
from sklearn.metrics import roc_curve

# Fetch real-time phishing URLs
def fetch_phishing_urls():
    print("🔍 Fetching real-time phishing URLs...")
    urls = []
    try:
        response = requests.get("https://phishunt.io/feed.txt")
        if response.status_code == 200:
            lines = response.text.splitlines()
            urls = [line for line in lines if line.startswith("http")]
    except Exception as e:
        print("❌ Error fetching phishing URLs:", e)

    print(f"✅ Dataset created with {len(urls)} URLs!")
    return urls[:100]  # Limit to 100 for performance

# Feature extraction
def extract_features(url):
    features = {
        "url_length": len(url),
        "has_ip": 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,
        "count_https": url.count("https"),
        "count_www": url.count("www"),
        "count_dots": url.count("."),
        "count_hyphens": url.count("-"),
        "count_slashes": url.count("/"),
        "count_@": url.count("@"),
        "count_?": url.count("?"),
        "count_=": url.count("="),
        "count_%": url.count("%"),
        "count_&": url.count("&"),
        "count_#": url.count("#"),
        "count_~": url.count("~"),
        "count_+": url.count("+"),
        "count_:": url.count(":"),
        "count_;": url.count(";"),
        "count_,": url.count(","),
        "count_$": url.count("$"),
        "count_space": url.count(" "),
        "count_http": url.count("http"),
        "tld_length": len(tldextract.extract(url).suffix),
        "domain_length": len(tldextract.extract(url).domain),
        "subdomain_length": len(tldextract.extract(url).subdomain),
        "https_in_url": int("https" in url),
        "num_digits": sum(char.isdigit() for char in url),
        "has_suspicious_word": int(bool(re.search(r"(login|update|secure|account|webscr|signin|banking)", url.lower()))),
        "contains_email": int("@" in url),
        "contains_client": int("client" in url.lower()),
    }
    return list(features.values())

# Label URLs
def label_urls(urls):
    data = []
    for url in urls:
        features = extract_features(url)
        data.append((features, 1))  # 1 = phishing
    return data

# Generate training data
print("🛠️ Training model...")
phishing_urls = fetch_phishing_urls()
phishing_data = label_urls(phishing_urls)

# Generate some synthetic legitimate data
legit_urls = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://www.github.com",
    "https://www.microsoft.com",
    "https://www.openai.com",
    "https://www.youtube.com",
    "https://www.amazon.com",
    "https://www.stackoverflow.com"
]
legit_data = [(extract_features(url), 0) for url in legit_urls]  # 0 = legit

# Combine and prepare dataset
all_data = phishing_data + legit_data
X = np.array([d[0] for d in all_data])
y = np.array([d[1] for d in all_data])

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = XGBClassifier(use_label_encoder=False, eval_metric='logloss')
model.fit(X_train, y_train)

# Save model
with open("phishing_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ Model trained and saved as phishing_model.pkl")

# 🔍 Save evaluation metrics for visualization in app.py
y_proba = model.predict_proba(X_test)[:, 1]
np.savez("metrics.npz", y_test=y_test, y_proba=y_proba)
print("📊 Evaluation metrics saved to metrics.npz")
