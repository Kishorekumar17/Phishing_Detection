import pandas as pd
import re
import tldextract

def extract_features(url_list):
    """
    Extracts features from URLs for phishing detection.
    Returns a pandas DataFrame of extracted features.
    """
    features_list = []

    for url in url_list:
        features = {}

        # URL Length
        features["url_length"] = len(url)

        # Count of digits in URL
        features["digit_count"] = sum(c.isdigit() for c in url)

        # Count of special characters
        features["special_char_count"] = len(re.findall(r'[!@#$%^&*()_+=]', url))

        # TLD Extraction
        extracted = tldextract.extract(url)
        features["tld_length"] = len(extracted.suffix)

        # Presence of "https"
        features["https"] = 1 if url.startswith("https") else 0

        # Count of subdomains
        features["subdomain_count"] = len(extracted.subdomain.split(".")) if extracted.subdomain else 0

        features_list.append(features)

    return pd.DataFrame(features_list)
