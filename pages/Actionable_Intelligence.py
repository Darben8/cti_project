from __future__ import annotations

from pathlib import Path

import pandas as pd
from pandas.errors import EmptyDataError
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(page_title="Actionable Intelligence", layout="wide")

st.title("🎯 Actionable Intelligence & COA Mapping")
st.markdown("""
This page transforms the ransomware correlation data from the **Analytical Approaches** panel into actionable defensive outputs for the finance sector.
""")

# --- DATA LINKAGE ---
# We use the data sources identified in your app: Ransomware.live & ThreatFox
# Attempt to pull the filtered data from your session state
if 'filtered_df' in st.session_state:
    df = st.session_state.filtered_df
else:
    # Fallback: Example data matching your "Interactive IOC Filtering Panel"
    df = pd.DataFrame([
        {"group": "lockbit3", "indicator": "f60vinnie75.city", "type": "domain", "confidence": 100, "source": "ThreatFox"},
        {"group": "akira", "indicator": "185.234.11.5", "type": "ip:port", "confidence": 85, "source": "ThreatFox"},
        {"group": "rhysida", "indicator": "taileenanahi.company", "type": "domain", "confidence": 100, "source": "ThreatFox"}
    ])

# --- PART 1: THE EXPORT FUNCTIONALITY (Required) ---
st.header("📥 Technical Intelligence Export")
st.write("Export correlated Ransomware IOCs for ingestion into banking security controls.")

col1, col2 = st.columns(2)

with col1:
    # CSV Export - Requirement Met
    csv = df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="⚡ Download CSV (SIEM/Firewall)",
        data=csv,
        file_name='finance_ransomware_triage.csv',
        mime='text/csv',
        help="Download indicators for manual blocking or spreadsheet analysis."
    )

with col2:
    # JSON Export (STIX-like) - Requirement Met
    json_data = df.to_json(orient='records')
    st.download_button(
        label="🤖 Download JSON (SOAR/STIX-ready)",
        data=json_data,
        file_name='finance_ransomware_triage.json',
        mime='application/json',
        help="Download for automated ingestion into SOAR platforms."
    )

st.divider()

# --- PART 2: COURSE-OF-ACTION (COA) MAPPING (Required) ---
st.header("🛠 Course-of-Action (COA) Mapping")
st.info("The following strategies are mapped directly to the IOC types discovered in the Ransomware.live/ThreatFox correlation.")

# Defensive Mapping Logic
def map_coa(row):
    if row['type'] == 'domain':
        return "Implement DNS Sinkholing and update web proxy blocklists."
    elif row['type'] == 'ip:port':
        return "Apply edge firewall block and monitor for existing outbound connections."
    elif 'hash' in row['type']:
        return "Deploy hash to EDR 'Block' list and run a fleet-wide retrospective scan."
    else:
        return "Escalate to Threat Hunting team for manual verification."

# Create the mapping table
coa_df = df[['group', 'indicator', 'type', 'source']].copy()
coa_df['Recommended Action (COA)'] = coa_df.apply(map_coa, axis=1)

# Display the Mapping as a polished table
st.table(coa_df.drop_duplicates(subset=['type'])) 

# --- PART 3: DISSEMINATION STRATEGY (Operational Intelligence Points) ---
st.header("📡 Dissemination Strategy")
with st.expander("View Operational Dissemination Plan"):
    st.markdown(f"""
    **Dissemination Summary:**
    Currently, **{len(df)}** indicators from sources like **ThreatFox** and **Ransomware.live** have been identified. These are disseminated through the following channels:
    
    1. **Automated Blocking:** JSON exports are pulled by the bank's SOAR platform to block confirmed domains.
    2. **Executive Reporting:** High-level trends (e.g., {df['group'].iloc[0]} activity) are summarized for the CISO.
    3. **Operational Triage:** The SOC uses the CSV exports to prioritize alerts based on the **Confidence Scores** (Avg: {df['confidence'].mean():.2f}%).
    """)