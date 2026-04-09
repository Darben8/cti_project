"""Collection Strategy and Data Summary Page"""

import streamlit as st

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

- **PhishTank** data was downloaded manually in CSV format and provided verified phishing URLs.  
- **ThreatFox** indicators were retrieved live through the API and supplied malware‑related infrastructure linked to banking‑focused threats.

Both sources were cleaned, reviewed, and normalized into a consistent structure to support analysis within the CTI platform.

The combined dataset is used for dashboards, enrichment workflows, and threat‑monitoring activities.
        """
    )

# -----------------------------
# RIGHT COLUMN – Data Summary
# -----------------------------
with col2:
    st.subheader("Data Summary")
    st.markdown(
        """
The unified dataset contains:

- Phishing URLs collected from the PhishTank CSV  
- Malware‑related indicators retrieved live from the ThreatFox API  

All entries were standardized into a common schema to ensure consistency across phishing and malware data.

The dataset reflects activity relevant to banking‑related phishing attempts and malware infrastructure, supporting fraud‑prevention workflows, SOC monitoring, and intelligence enrichment.
        """
    )
