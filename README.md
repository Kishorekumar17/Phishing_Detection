# 🛡️ Real-Time Phishing Detection System

A powerful machine learning-based Streamlit web app to detect **phishing URLs in real-time** using features, TLS certificate inspection, and screenshot similarity.

---

## 🚀 Features

✅ Real-time phishing URL detection  
✅ Feature-based, TLS-based, and screenshot-based analysis  
✅ XGBoost-powered ML model  
✅ Visualized model performance (Confusion Matrix, ROC Curve, Classification Report)  
✅ Email alert on phishing detection  
✅ Deployed using Streamlit Cloud  

---

## 🧠 How It Works

1. 🔍 **Feature Extraction**: Extracts lexical, domain, and structural features from the input URL  
2. 🔐 **TLS Inspection**: Validates TLS certificate for expiration, subject, issuer, etc.  
3. 🖼️ **Screenshot Comparison** *(Optional)*: SSIM comparison for phishing mimic detection  
4. 🤖 **Model Prediction**: Uses trained XGBoost model to classify URL  
5. 📧 **Email Alert**: Sends alert on phishing detection to admin email  

---

## 📊 Model Performance

- Trained on real-time phishing URLs fetched from [Phishunt.io](https://phishunt.io)
- Accuracy: **>92%**
- ROC-AUC Score: **0.95+**

> Visualized with Seaborn & Matplotlib on Streamlit

---

## 📂 Project Structure

