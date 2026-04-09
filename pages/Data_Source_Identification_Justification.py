import pandas as pd
import streamlit as st

st.title("CTI Data Sources: PhishTank & ThreatFox")

tab1, tab2 = st.tabs(["PhishTank", "ThreatFox"])

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
    "images/diamond_model.png",
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

        st.subheader("Why This Data Source? (Diamond Model)")
        threatfox_diamond = pd.DataFrame({
            "Element": ["Capability", "Infrastructure"],
            "Relevance": [
                "Maps IOCs to malware families (credential theft, fraud)",
                "Tracks active C2 servers (IPs, domains)",
            ],
        })
        st.table(threatfox_diamond)

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
    "images/diamond_model2.png",
    caption="Diamond Model for Phishing Threats",
    use_container_width=True
)
