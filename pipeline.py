import re
import pandas as pd
import streamlit as st
from sklearn.ensemble import IsolationForest

# --- 1. STREAMLIT WEB PAGE SETUP ---
st.set_page_config(page_title="DevOps Threat Control Room", layout="wide", page_icon="🛡️")
st.title("🛡️ Intelligent Server Log Anomaly Detector")
st.markdown("### *Real-time AI Infused Security Monitoring & Telemetry*")
st.write("---")

# --- 2. DATA ENGINEERING & PARSING ---
log_pattern = r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>.*?)\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d+) (?P<size>\d+)'
parsed_lines = []

# Using 'server_log.txt' to match your exact filename
try:
    with open("server_log.txt", "r") as file:
        for line in file:
            match = re.match(log_pattern, line)
            if match:
                parsed_lines.append(match.groupdict())

    df = pd.DataFrame(parsed_lines)
    df['status'] = df['status'].astype(int)
    df['size'] = df['size'].astype(int)

    # --- 3. FEATURE ENGINEERING (AGGREGATION) ---
    ip_counts = df['ip'].value_counts().reset_index()
    ip_counts.columns = ['ip', 'total_requests']

    df['is_error'] = df['status'].apply(lambda x: 1 if x >= 400 else 0)
    ip_errors = df.groupby('ip')['is_error'].sum().reset_index()

    features = pd.merge(ip_counts, ip_errors, on='ip')

    # --- 4. MACHINE LEARNING ANOMALY DETECTION ---
    X = features[['total_requests', 'is_error']]
    model = IsolationForest(contamination=0.20, random_state=42)
    features['anomaly_score'] = model.fit_predict(X)

    # Split anomalies from normal traffic
    anomalies_df = features[features['anomaly_score'] == -1]
    normal_df = features[features['anomaly_score'] == 1]

    # --- 5. RENDER USER INTERFACE METRIC CARDS ---
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(label="📊 Total Unique IPs Tracked", value=len(features))
    with col2:
        st.metric(label="🟢 Safe & Normal IPs", value=len(normal_df))
    with col3:
        # If threats are greater than 0, highlight it in red
        st.metric(label="🚨 Flagged Threat Alerts", value=len(anomalies_df), delta=f"{len(anomalies_df)} Critical", delta_color="inverse")

    st.write("---")

    # --- 6. DISPLAY INTERACTIVE DATA LAYOUTS ---
    left_col, right_col = st.columns(2)

    with left_col:
        st.subheader("🔴 Flagged Security Blacklist (Anomalies)")
        if not anomalies_df.empty:
            st.warning("The AI model detected anomalous baseline shifts from the following sources:")
            st.dataframe(anomalies_df[['ip', 'total_requests', 'is_error']], use_container_width=True)
        else:
            st.success("All operational entities are within expected baseline parameters.")

    with right_col:
        st.subheader("🟢 Active Network Traffic Profile")
        st.dataframe(features[['ip', 'total_requests', 'is_error', 'anomaly_score']], use_container_width=True)

except FileNotFoundError:
    st.error("Error: 'server_log.txt' file not detected in the current workspace directory.")