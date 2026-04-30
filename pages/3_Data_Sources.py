import pandas as pd
import streamlit as st


st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600;700&display=swap');

    html, body, [data-testid="stAppViewContainer"] {
        background-color: #080f1a;
        color: #c9d1d9;
        font-family: 'IBM Plex Sans', sans-serif;
    }
    [data-testid="stSidebar"] {
        background-color: #0d1526 !important;
        border-right: 1px solid #1e3a5f;
    }
    [data-testid="stSidebar"] * {
        color: #8ba3c0 !important;
        font-family: 'IBM Plex Sans', sans-serif !important;
    }
    [data-testid="stSidebar"] [aria-selected="true"] {
        background-color: #0f2644 !important;
        color: #38bdf8 !important;
        border-left: 3px solid #38bdf8;
    }
    .block-container {
        padding-top: 2rem;
        max-width: 1180px;
    }
    h1, h2, h3, h4, h5 {
        color: #e6edf3;
        font-family: 'IBM Plex Sans', sans-serif;
    }
    p, li, label, .stMarkdown, [data-testid="stCaptionContainer"] {
        color: #8ba3c0;
    }
    .dash-hero {
        background: linear-gradient(135deg, #0f2644 0%, #080f1a 58%, #091a10 100%);
        border: 1px solid #1e3a5f;
        border-radius: 12px;
        padding: 2rem 2.4rem;
        margin-bottom: 1.5rem;
        position: relative;
        overflow: hidden;
    }
    .dash-hero::before {
        content: '';
        position: absolute;
        top: -70px;
        right: -55px;
        width: 240px;
        height: 240px;
        border-radius: 50%;
        background: radial-gradient(circle, rgba(56,189,248,0.10) 0%, transparent 70%);
    }
    .dash-eyebrow {
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.72rem;
        letter-spacing: 0.18em;
        color: #38bdf8;
        text-transform: uppercase;
        margin-bottom: 0.65rem;
    }
    .dash-title {
        color: #e6edf3;
        font-size: 2rem;
        font-weight: 700;
        line-height: 1.15;
        margin: 0 0 0.5rem;
    }
    .dash-title span {
        color: #e6edf3;
    }
    .dash-sub {
        color: #8ba3c0;
        max-width: 760px;
        line-height: 1.55;
        margin-bottom: 1rem;
    }
    .dash-tags {
        display: flex;
        gap: 0.55rem;
        flex-wrap: wrap;
    }
    .dash-tag {
        background: rgba(56,189,248,0.08);
        border: 1px solid rgba(56,189,248,0.25);
        color: #38bdf8;
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.7rem;
        padding: 0.25rem 0.65rem;
        border-radius: 4px;
        letter-spacing: 0.05em;
    }
    [data-testid="stTabs"] [role="tablist"] {
        gap: 0.5rem;
        border-bottom: 1px solid #1e3a5f;
    }
    [data-testid="stTabs"] [role="tab"] {
        background: #0d1526;
        border: 1px solid #1e3a5f;
        border-bottom: none;
        border-radius: 8px 8px 0 0;
        padding: 0.55rem 1rem;
        color: #38bdf8 !important;
    }
    [data-testid="stTabs"] [role="tab"] p {
        color: #38bdf8 !important;
    }
    [data-testid="stTabs"] [aria-selected="true"] {
        color: #38bdf8 !important;
        background: #0f2644;
        border-color: #2d5a8e;
    }
    [data-testid="stMetric"] {
        background: #0d1526;
        border: 1px solid #1e3a5f;
        border-radius: 10px;
        padding: 0.85rem 1rem;
    }
    [data-testid="stMetricLabel"] {
        color: #8ba3c0 !important;
        font-family: 'IBM Plex Mono', monospace;
        letter-spacing: 0.04em;
    }
    [data-testid="stMetricValue"] {
        color: #38bdf8 !important;
    }
    div[data-testid="stDataFrame"], div[data-testid="stDataEditor"] {
        border: 1px solid #1e3a5f;
        border-radius: 10px;
        overflow: hidden;
    }
    div[data-testid="stAlert"] {
        background: rgba(56,189,248,0.07);
        border: 1px solid rgba(56,189,248,0.18);
        color: #c9d1d9;
    }
    .stButton > button, .stDownloadButton > button {
        background: #0f2644;
        border: 1px solid #38bdf8;
        color: #e6edf3;
        border-radius: 6px;
    }
    .stButton > button:hover, .stDownloadButton > button:hover {
        border-color: #7dd3fc;
        color: #38bdf8;
    }
    hr {
        border-color: #1e3a5f;
    }
    #MainMenu, footer, header { visibility: hidden; }
    </style>
    """,
    unsafe_allow_html=True,
)


st.title("CTI Data Sources: PhishTank & ThreatFox")

tab1, tab2, tab3 = st.tabs(["PhishTank", "ThreatFox", "Collection & Summary"])

# PhishTank Tab
with tab1:
    st.header("PhishTank")

    col1, col2 = st.columns([1, 1], gap="large")

    with col1:
        st.subheader("Background")
        st.markdown("""
- Community-driven phishing intelligence platform (Cisco Talos)
- Provides verified phishing URLs
- Used in threat intelligence and fraud detection
""")
        st.subheader("Value for Banking")
        st.markdown("""
**Primary banking threat: Phishing**

- Detect fake banking login pages
- Identify phishing campaigns targeting customers/employees
- Block malicious URLs
- Analyze attacker infrastructure
""")

        st.subheader("Who Generates the Data?")
        st.markdown("""
- Security researchers
- Open-source intelligence contributors
- Automated submissions
- Anti-phishing vendors
""")

    with col2:
        st.subheader("How Much Data Is Available?")
        st.markdown("""
- Tens of thousands of active phishing URLs
- Historical archive spanning years of phishing campaigns
- Daily updates with new submissions
""")

        st.subheader("Industry Usage")
        st.markdown("""
Used by financial institutions and cybersecurity vendors:

- Fraud prevention teams
- SOC analysts
- Email security providers

Integrated into SIEM and fraud detection systems.
""")

# BELOW BOTH COLUMNS 
        st.subheader("Why This Data Source? (Diamond Model)")

        st.image(
    "images/Diamond_model.png",
    caption="Diamond Model for Phishing Threats",
    use_container_width=True
)


# ThreatFox Tab
with tab2:
    st.header("ThreatFox")

    col1, col2 = st.columns([1, 1], gap="large")

    with col1:
        st.subheader("Background")
        st.markdown("""
- OSINT platform by abuse.ch & Spamhaus
- Shares malware Indicators of Compromise (IOCs)
- Links IOCs to specific malware families (e.g., QakBot, TrickBot)
""")

        st.subheader("Value for Banking")
        st.markdown("""
**Banks are prime targets for malware & banking trojans**

ThreatFox helps:
- Block C2 servers used by banking malware
- Detect credential theft & fraudulent activity
- Prioritize threats using IOC confidence scores
- Use real-time, up-to-date threat intelligence
""")
        st.subheader("Who Generates the Data?")
        st.markdown("""
- **Community:** Security researchers and analysts submit IOCs associated with malware botnets
- **Spamhaus:** abuse.ch integrated with Spamhaus and has become one of the largest independently crowdsourced intelligence sources for tracked malware and botnets
""")

    with col2:

        st.subheader("How Much Data Is Available?")
        st.markdown("""
- Over **1.7 million IOCs** shared on ThreatFox
- ~**95 million API requests** answered in a single 30-day period (October 2024)
- Enables real-time insights for threat hunting and mitigation
""")
        

        st.subheader("Industry Usage")
        st.markdown("""
Used by financial institutions via threat intelligence platforms:

- FS-ISAC member banks
- SOC analysts
- Fraud detection teams

Integrated into MISP and SIEM systems for real-time threat blocking.
""")
# BELOW BOTH COLUMNS 
        st.subheader("Why This Data Source? (Diamond Model)")

        st.image(
    "images/Diamond_model2.png",
    caption="Diamond Model for Phishing Threats",
    use_container_width=True
)

# Collection & Summary Tab
with tab3:
    st.header("Data Collection & Summary")

    col1, col2 = st.columns([1, 1], gap="large")
    
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

# RIGHT COLUMN – Data Summary
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
