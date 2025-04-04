import streamlit as st
import joblib
import numpy as np
import pandas as pd
import logging
from feature_extraction import extract_features

# Load the model
model = joblib.load("phishing_model.pkl")

# Set classification threshold
THRESHOLD = 0.7  # Adjust as needed

# Configure logging
logging.basicConfig(level=logging.INFO, filename="app.log", filemode="w",
                    format="%(asctime)s - %(levelname)s - %(message)s")

st.title("🔍 Real-Time Phishing Detection System")
st.subheader("Enter a URL to check if it's phishing or safe")

# User input
url = st.text_input("🔗 Enter URL", "")

if st.button("Check URL"):
    if url:
        try:
            # Extract features
            features_df = extract_features([url])
            logging.info(f"Extracted features for {url}: {features_df.values}")
            
            # Ensure correct feature shape
            if features_df is not None and not features_df.empty:
                # Get model prediction
                prediction_prob = model.predict_proba(features_df)[:, 1][0]
                prediction = 1 if prediction_prob > THRESHOLD else 0
                
                logging.info(f"Prediction probability: {prediction_prob}, Classified as: {prediction}")
                
                # Display results
                if prediction == 1:
                    st.error("🚨 Phishing Website Detected!")
                elif prediction == 0:
                    st.success("✅ Safe Website!")
                else:
                    st.warning("⚠️ Uncertain Prediction")
            else:
                st.warning("⚠️ Could not extract features. Please check the URL format.")
        except Exception as e:
            st.error("❌ Error processing URL. Please try again.")
            logging.error(f"Error processing URL {url}: {str(e)}")
    else:
        st.warning("⚠️ Please enter a valid URL.")
