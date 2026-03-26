"""Threat trends and critical assets page."""

import pandas as pd
import streamlit as st

st.title("📈 Threat Trends and Critical Asset Identification")
st.caption("Global + U.S. banking threat summary with ATT&CK mapping and asset risk context.")

st.subheader("Key Threat Trends (Approved Inputs)")
trend_df = pd.DataFrame(
    [
        {
            "Threat": "Credential Theft / Account Takeover",
            "Why it matters in banking": "Direct path to fraud and customer account abuse across online channels.",
            "MITRE ATT&CK": "T1110, T1078, T1556",
        },
        {
            "Threat": "Phishing / Social Engineering",
            "Why it matters in banking": "High success against customers and staff; enables credential capture and BEC-like fraud.",
            "MITRE ATT&CK": "T1566, T1056",
        },
        {
            "Threat": "Ransomware / System Intrusion",
            "Why it matters in banking": "Disrupts core operations, payment systems, and customer trust via encryption + extortion.",
            "MITRE ATT&CK": "T1486, T1021, T1071",
        },
        {
            "Threat": "Web Application Attacks",
            "Why it matters in banking": "Targets internet-facing portals and APIs handling sensitive transactions.",
            "MITRE ATT&CK": "T1190, T1505",
        },
    ]
)
st.dataframe(trend_df, use_container_width=True, hide_index=True)

st.markdown(
    """
### Global and U.S. Context
- External actors account for a substantial share of banking/finance intrusions.
- Top access vectors include credential abuse, vulnerability exploitation, and phishing.
- Banking remains attractive due to immediate monetization paths, high-value personal data, and real-time transaction infrastructure.
- Emerging concern: AI-enabled phishing and fraud workflows that accelerate social engineering.
    """
)

st.subheader("Critical Assets (at least 5)")
assets = pd.read_csv("data/critical_assets.csv")
st.dataframe(assets, use_container_width=True, hide_index=True)

with st.expander("Critical Asset Justification"):
    st.markdown(
        """
- **Core banking systems:** Backbone for account operations and transaction integrity.
- **Payment processing rails:** Directly tied to settlement, customer trust, and liquidity operations.
- **Customer identity platforms (IAM/AD):** High-value target enabling privilege escalation and lateral movement.
- **Online/mobile banking applications:** Primary internet-facing attack surface for credential and session abuse.
- **Customer databases:** Contain regulated data and are prime extortion targets.
- **SOC/SIEM and monitoring tools:** Essential for detection, response, and regulatory evidence trails.
        """
    )

st.subheader("Threat Intel Sources in Scope")
st.markdown(
    """
- **PhishTank**: phishing indicators and URLs.
- **ransomware.live**: public victim and group activity tracking.
- **Shodan**: exposure intelligence for internet-facing assets.

These sources are used as practical, open-source inputs for early CTI triage and prioritization in Milestone 1.
    """
)
