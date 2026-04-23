import streamlit as st
import pandas as pd
import plotly.express as px

st.header("Key Insights & Intelligence Summary")

st.markdown("""
### **1. Types of Infrastructure Adversaries Are Using**
- Attackers rely on **IP:port C2 servers** (443, 995, 2078) to blend into encrypted banking traffic.
- Malware families like **QakBot, Emotet, Feodo** use **consistent C2 endpoints** for credential theft.
- Ramnit uses **fast‑rotating DGA domains**, making blocking difficult for banks.

### **2. Emerging Threats Toward the Banking Industry**
- Phishing URLs impersonate **bank brands** using terms like *login, secure, verify*.
- Daily phishing activity shows **continuous targeting** of online banking users.
- Malware clusters align with **account takeover, credential harvesting, and ransomware delivery**.

### **3. How Analytics Provide Intelligence or Defense**
- IOC analysis helps banks prioritize **high‑risk C2 detection**.
- Phishing URL patterns support **early fraud alerts**.
- Heatmaps highlight **which malware families pose the greatest risk**.
- Text‑mining and clustering detect **new phishing domains** targeting financial users.
""")

st.divider()
st.subheader("Summary Visualization")

# -----------------------------------------
# Dropdown to choose visualization
# -----------------------------------------
option = st.selectbox(
    "Choose a visualization:",
    ["Malware Family vs IOC Type", "Phishing Activity Timeline"]
)

# -----------------------------------------
# Visualization 1: Malware vs IOC Type Heatmap
# -----------------------------------------
if option == "Malware Family vs IOC Type":
    try:
        df_threat = pd.read_csv("data/filtered_iocs_threatfox.csv")

        heatmap_df = df_threat.groupby(["malware_printable", "ioc_type"]).size().reset_index(name="count")
        pivot = heatmap_df.pivot(index="malware_printable", columns="ioc_type", values="count").fillna(0)

        fig = px.imshow(
            pivot,
            aspect="auto",
            color_continuous_scale="YlOrRd",
            title="Banking Threat Concentration: Malware Family vs IOC Type",
            labels={"x": "IOC Type", "y": "Malware Family", "color": "Count"},
        )

        st.plotly_chart(fig, use_container_width=True)

    except:
        st.warning("Heatmap could not be generated. Ensure the ThreatFox CSV is available.")

# -----------------------------------------
# Visualization 2: Phishing Timeline
# -----------------------------------------
elif option == "Phishing Activity Timeline":
    try:
        df_phish = pd.read_csv("data/verified_online_banking_finance.csv")
        df_phish["submission_time"] = pd.to_datetime(df_phish["submission_time"], errors="coerce")

        timeline = df_phish.groupby(df_phish["submission_time"].dt.date).size().reset_index(name="count")

        fig2 = px.line(
            timeline,
            x="submission_time",
            y="count",
            markers=True,
            title="Phishing Activity Timeline (Banking Sector)",
            labels={"submission_time": "Date", "count": "Phishing Submissions"},
        )

        st.plotly_chart(fig2, use_container_width=True)

    except:
        st.warning("Phishing timeline could not be generated. Ensure the phishing CSV is available.")