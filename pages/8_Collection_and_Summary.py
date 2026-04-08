"""Collection Strategy and Data Summary Page"""

import streamlit as st
import pandas as pd

st.title("Collection Strategy and Data Summary")
st.caption("Overview of how phishing and malware indicators were collected, processed, and prepared for analysis.")

col1, col2 = st.columns([1.2, 1], gap="large")

# -----------------------------
# LEFT COLUMN – Collection Strategy
# -----------------------------
with col1:
    st.subheader("Collection Strategy")
    st.markdown(
        """
The dataset was collected from two open‑source intelligence feeds: **PhishTank** and **ThreatFox**.  
PhishTank provided verified phishing URLs, while ThreatFox contributed malware‑related indicators such as domains and IP addresses associated with banking‑focused threats.

Both datasets were downloaded in CSV format and manually reviewed to ensure relevance to the banking sector.  
Indicators were then cleaned, deduplicated, and normalized into a unified schema to support consistent analysis across the CTI platform.

The final combined dataset was saved for use in dashboards, enrichment workflows, and threat‑monitoring activities.
        """
    )

# -----------------------------
# RIGHT COLUMN – Data Summary
# -----------------------------
with col2:
    st.subheader("Data Summary")
    st.markdown(
        """
The combined dataset includes phishing URLs from PhishTank and malware infrastructure indicators from ThreatFox.  
All entries were standardized into common fields, including **indicator**, **type**, **source**, **first_seen**, and **tags**.

The dataset primarily reflects phishing activity targeting banking customers and malware infrastructure linked to families such as **QakBot**, **IcedID**, and **Gozi**.

This consolidated dataset supports fraud‑prevention workflows, SOC monitoring, and intelligence enrichment within the CTI platform.
        """
    )

# -----------------------------
# FULL-WIDTH SECTION – Load CSV
# -----------------------------
st.subheader("Combined IOC Dataset Viewer")

try:
    df = pd.read_csv("data/combined_iocs.csv")  # Update filename if needed
    st.dataframe(df, use_container_width=True)

    st.markdown("### Dataset Summary")
    st.write(f"**Total Records:** {len(df)}")


except FileNotFoundError:
    st.error("❌ Could not find `data/combined_iocs.csv`. Please place the file inside the `data/` folder.")
