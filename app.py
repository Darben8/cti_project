"""Milestone 1 CTI Streamlit app for US Banking."""

import streamlit as st

st.set_page_config(
    page_title="US Banking CTI Platform - Milestone 1",
    page_icon="🏦",
    layout="wide",
)

CHASE_BLUE = "#117ACA"
DARK_BLUE = "#0B3A69"
LIGHT_BG = "#F4F8FC"

# st.markdown(
#     f"""
#     <style>
#     .stApp {{ background-color: {LIGHT_BG}; }}
#     h1, h2, h3 {{ color: {DARK_BLUE}; }}
#     [data-testid="stMetricValue"] {{ color: {CHASE_BLUE}; }}
#     .block-container {{ padding-top: 1.2rem; }}
#     </style>
#     """,
#     unsafe_allow_html=True,
# )

st.title("🏦 Cyber Threat Intelligence Platform: U.S. Banking")
#st.caption("Milestone 1 - Industry baseline, threat trends, diamond models, and dashboard starter.")

with st.container(border=True):
    with st.expander("📌 Milestone 1"):
        st.subheader("✅ What's Changed in Milestone 1")
        st.checkbox("We tightened our industry focus to the banking sector within the finance industry", value=True, disabled=True)
        st.checkbox("We focused on banking in North America (United States)", value=True, disabled=True)
        st.checkbox("We removed AZSecure as a relevant data source", value=True, disabled=True)
        st.checkbox(
            "We prioritized top banking threats as credential theft then phishing, followed by ransomware and web application attacks",
            value=True,
            disabled=True,
        )

with st.container(border=True):
    with st.expander("📌 Milestone 2"):
        st.subheader("✅ What's New in Milestone 2")
        st.checkbox("We created the data explorer", value=True, disabled=True)
        st.checkbox("We updated team roles in the pages subfolder", value=True, disabled=True)
        st.checkbox("We included Threatfox as a datasource and worked with APIs rather than synthetic data", value=True, disabled=True)
        st.checkbox("We updated the dashboard starter with new filters, metrics, data and charts that correlate banking assets with threat indicators", value=True, disabled=True)
        st.checkbox("New supporting pages were added around collection strategy, data source identification/justification, and references.", value=True, disabled=True)
        st.checkbox("We download threat intelligence data from phishtank and  in the data folder", value=True, disabled=True)

with st.container(border=True):
     with st.expander("📌 Milestone 3"):
        st.subheader("✅ Milestone 3: New Features")
        st.checkbox("Analytical Approaches: Phishing URL Text Mining & Ransomware Event Correlation", value=True, disabled=True)
        st.checkbox("Interactive Analytics Panel: Multi-source filtering with unique-key state management", value=True, disabled=True)
        st.checkbox("Preliminary Visualizations: Temporal trends and threat distribution with process/value justifications", value=True, disabled=True)
        st.checkbox("Operational Metrics: Implementation of MTTD reduction estimates and Indicator Precision tracking", value=True, disabled=True)
        st.checkbox("Enhanced UI: Wide-mode dashboard layout and automated EST refresh timestamps", value=True, disabled=True)
        st.checkbox("Validation: Added error analysis and data limitation documentation", value=True, disabled=True)

#st.success("Milestone 3 requirements fully implemented and documented in the Dashboard.")

st.divider()

col1, col2 = st.columns([1.2, 1], gap="large")

with col1:
    st.subheader("Ethics and Data Governance")
    st.markdown(
        """
   1) All data comes from approved documented sources. No stolen or unauthorized data is used.

   2) Only data relevant to the U.S. banking sector is included.

   3) Our app does not expose sensitive or proprietary information, or any details that could increase operational risk.
        """)

with col2:
    st.subheader("Security-Aware Development Practices")
    st.markdown(
        """
1) Secrets are stored in environment variables and not hardcoded in the codebase.

2) We implemented request timeouts and error handling for all API calls to prevent hanging and ensure graceful failure.

3) We use a requirements.txt file to manage dependencies and ensure consistent environments across development and deployment.
""")



st.info("Use the sidebar to navigate to Industry Background, Threat Trends, Critical Assets, Diamond Models, and Dashboard pages.")
