import streamlit as st
import numpy as np
import pickle
from sklearn.metrics import roc_curve, auc, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import re
import tldextract

# Load the trained model
with open("phishing_model.pkl", "rb") as f:
    model = pickle.load(f)

# Feature extraction function
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

# Streamlit UI
st.set_page_config(page_title="Phishing Detector", layout="centered")
st.title("🔒 Real-Time Phishing URL Detector")

tab1, tab2 = st.tabs(["🌐 Predict Phishing", "📊 Model Performance"])

# === Prediction Tab ===
with tab1:
    url = st.text_input("Enter a URL to analyze:")
    if st.button("Predict"):
        features = extract_features(url)
        features_np = np.array(features).reshape(1, -1)
        prediction = model.predict(features_np)[0]
        proba = model.predict_proba(features_np)[0][1]

        if prediction == 1:
            st.error(f"⚠️ This URL is likely a *phishing* site. (Confidence: {proba:.2f})")
        else:
            st.success(f"✅ This URL seems *legitimate*. (Confidence: {1 - proba:.2f})")

# === Visualization Tab ===
with tab2:
    st.subheader("📈 ROC Curve & Confusion Matrix")

    try:
        data = np.load("metrics.npz")
        y_test = data["y_test"]
        y_proba = data["y_proba"]

        # ROC Curve
        fpr, tpr, _ = roc_curve(y_test, y_proba)
        roc_auc = auc(fpr, tpr)

        st.markdown("**🔵 ROC Curve**")
        fig, ax = plt.subplots()
        ax.plot(fpr, tpr, color='blue', lw=2, label=f'AUC = {roc_auc:.2f}')
        ax.plot([0, 1], [0, 1], color='gray', linestyle='--')
        ax.set_xlim([0.0, 1.0])
        ax.set_ylim([0.0, 1.05])
        ax.set_xlabel('False Positive Rate')
        ax.set_ylabel('True Positive Rate')
        ax.set_title('Receiver Operating Characteristic (ROC)')
        ax.legend(loc="lower right")
        st.pyplot(fig)

        # Confusion Matrix
        preds = (y_proba >= 0.5).astype(int)
        cm = confusion_matrix(y_test, preds)

        st.markdown("**🟢 Confusion Matrix**")
        fig2, ax2 = plt.subplots()
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", ax=ax2)
        ax2.set_xlabel("Predicted Label")
        ax2.set_ylabel("True Label")
        ax2.set_title("Confusion Matrix")
        st.pyplot(fig2)

    except Exception as e:
        st.warning("⚠️ Unable to load evaluation metrics. Please ensure you've run `train_model.py`.")
        st.text(str(e))
