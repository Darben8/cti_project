"""Threat trends page."""

import pandas as pd
import streamlit as st

st.title("Threat Trends")
st.caption("Summary of global and U.S. banking threats, supporting evidence, relevance, and CTI sources.")

st.subheader("Key Threat Trends")
trend_df = pd.DataFrame(
    [
        {
            "Threat Trend": "Credential theft and account takeover",
            "Evidence": "Frequent targeting of customer logins, employee access, and weak or reused credentials.",
            "Relevance to Banking": "Creates a direct path to fraud, account abuse, and unauthorized fund movement.",
            "MITRE ATT&CK": "T1110, T1078, T1556",
        },
        {
            "Threat Trend": "Phishing and social engineering",
            "Evidence": "Bank customers and staff remain high-value targets for credential capture and payment fraud lures.",
            "Relevance to Banking": "Enables account compromise, business email compromise, and downstream intrusion activity.",
            "MITRE ATT&CK": "T1566, T1056",
        },
        {
            "Threat Trend": "Ransomware and system intrusion",
            "Evidence": "Financial entities face extortion-driven attacks that disrupt operations and expose sensitive data.",
            "Relevance to Banking": "Can impair core operations, payment processing, recovery timelines, and public trust.",
            "MITRE ATT&CK": "T1486, T1021, T1071",
        },
        {
            "Threat Trend": "Web application and API attacks",
            "Evidence": "Internet-facing portals and APIs are regularly probed for exploitable weaknesses and session abuse.",
            "Relevance to Banking": "Targets the digital channels customers rely on for account access and transactions.",
            "MITRE ATT&CK": "T1190, T1505",
        },
    ]
)
st.dataframe(trend_df, use_container_width=True, hide_index=True)

st.subheader("Global and U.S. Context")
st.markdown(
    """
- External actors account for a substantial share of banking and finance intrusions.
- Common initial access paths include phishing, credential abuse, and exploitation of exposed services.
- U.S. banks remain attractive because they combine monetizable data, direct payment capability, and customer-facing digital channels.
- The growth of AI-enabled phishing and fraud campaigns increases the speed and scale of social engineering.
    """
)

st.subheader("Threat Intel Sources in Scope")
st.markdown(
    """
- **PhishTank**: phishing indicators and malicious URL reporting useful for triage and monitoring.
- **ransomware.live**: visibility into publicly tracked victim disclosures and extortion activity.
- **Shodan**: exposure intelligence for identifying internet-facing systems and misconfiguration risk.

These sources support early CTI triage by helping analysts monitor active phishing, ransomware reporting, and external exposure trends relevant to the U.S. banking sector.
    """
)
