import requests
import tldextract
import ssl
import socket
import smtplib
from email.mime.text import MIMEText
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
import random

def extract_features(url):
    features = []
    parsed = urlparse(url)
    domain_info = tldextract.extract(url)

    features.append(len(url))  # 1
    features.append(1 if parsed.scheme == 'https' else 0)  # 2
    features.append(url.count('@'))  # 3
    features.append(url.count('.'))  # 4
    features.append(url.count('-'))  # 5
    features.append(url.count('='))  # 6
    features.append(url.count('&'))  # 7
    features.append(url.count('?'))  # 8
    features.append(url.count('%'))  # 9
    features.append(url.count('/'))  # 10
    features.append(url.count('//'))  # 11
    features.append(url.count('www'))  # 12
    features.append(1 if domain_info.domain.replace('.', '').isdigit() else 0)  # 13

    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, "html.parser")
        features.append(len(soup.find_all('a')))  # 14
        features.append(len(soup.find_all('form')))  # 15
    except:
        features += [0, 0]  # If network fails

    return features  # ✅ Total: 15 features

def get_tls_certificate_info(url):
    features = []
    try:
        hostname = urlparse(url).netloc.split(":")[0]
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(3)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            valid_days = (not_after - datetime.utcnow()).days
            features.append(valid_days)  # 1
            features.append(1 if valid_days > 0 else 0)  # 2
            features.append(len(cert.get('subject', [])))  # 3
            features.append(len(cert.get('issuer', [])))  # 4
            features.append(len(cert.get('subjectAltName', [])) if 'subjectAltName' in cert else 0)  # 5
    except Exception:
        features += [0] * 5  # On error, return zeroed features

    return features  # ✅ Total: 5 features

def take_screenshot(url):
    # Replace with actual image processing if needed
    # Dummy 9 features to reach total of 29
    return [random.randint(0, 1) for _ in range(9)]  # ✅ Total: 9 features

def send_email_alert(phishing_url):
    sender_email = "kishorekumar200417@gmail.com"
    sender_password = "123"
    receiver_email = "kishorekumar200417@gmail.com"

    message = MIMEText(f"🚨 Phishing Detected:\n\nURL: {phishing_url}")
    message['Subject'] = "Phishing Alert 🚨"
    message['From'] = sender_email
    message['To'] = receiver_email

    try:
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, message.as_string())
        server.quit()
    except Exception as e:
        print("Failed to send email:", e)
