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

st.markdown(
    f"""
    <style>
      .stApp {{ background-color: {LIGHT_BG}; }}
      h1, h2, h3 {{ color: {DARK_BLUE}; }}
      [data-testid="stMetricValue"] {{ color: {CHASE_BLUE}; }}
      .block-container {{ padding-top: 1.2rem; }}
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🏦 Cyber Threat Intelligence Platform: U.S. Banking")
st.caption("Milestone 1 - Industry baseline, threat trends, diamond models, and dashboard starter.")

with st.container(border=True):
    st.subheader("✅ What's New in This Milestone")
    st.checkbox("We tightened our industry focus to the banking sector within the finance industry", value=True, disabled=True)
    st.checkbox("We focused on banking in North America (United States)", value=True, disabled=True)
    st.checkbox("We removed AZSecure as a relevant data source", value=True, disabled=True)
    st.checkbox(
        "We prioritized top banking threats as credential theft then phishing, followed by ransomware and web application attacks",
        value=True,
        disabled=True,
    )

# col1, col2 = st.columns([1.2, 1], gap="large")

# with col1:
#     st.subheader("Industry Background")
#     st.markdown(
#         """
# - **Industry focus:** U.S. banking sector within the broader finance and insurance ecosystem.
# - **Core services/products:** retail banking, commercial banking, digital payments, lending, wealth management, and treasury services.
# - **Major industry players:** JPMorgan Chase, Bank of America, Citigroup, Wells Fargo, HSBC, MUFG, and Standard Chartered.
# - **Why IT is mission-critical:** always-on online banking, real-time transaction processing, fraud detection pipelines, API-driven integrations, and regulatory reporting depend on secure digital infrastructure.
# - **Risk concentration:** banking remains highly targeted due to access to capital, high-value identity data, internet-facing services, and transaction velocity.
#         """
#     )

#     st.subheader("CTI Use Case / Threat-Model-Backed Design")
#     st.markdown(
#         """
# This platform helps security teams **prioritize high-impact banking threats** and **defend critical assets** by combining:
# 1. Threat-trend intelligence (phishing, ransomware, exposed infrastructure),
# 2. Asset-centric risk context,
# 3. MITRE ATT&CK-aligned adversary behavior,
# 4. A dynamic dashboard for rapid triage and decision support.

# **Decisions enabled:**
# - Which threat categories should be prioritized this week?
# - Which assets require immediate hardening and monitoring?
# - Which ATT&CK techniques should drive detections, controls, and executive reporting?
#         """
#     )

# with col2:
#     st.subheader("Stakeholders and User Stories")
#     st.markdown(
#         """
# **1) SOC Analyst - Jordan**
# - View near-real-time threat trends targeting banking infrastructure.
# - Filter and prioritize high-risk assets for monitoring.

# **2) CISO - Alicia**
# - Track executive KPIs (threat volume and exposure levels).
# - Review adversary capabilities and attack paths for budget planning.

# **3) Threat Intelligence Analyst - Rahul**
# - Use adversary profiles and diamond models for leadership briefings.
# - Detect patterns using category-filtered threat dashboards.
#         """
#     )

#     st.subheader("Intelligence Buy-In")
#     st.markdown(
#         """
# - Banking faces persistent pressure from credential abuse, phishing, ransomware, and web app attacks.
# - A CTI-led approach reduces uncertainty by translating external threat data into action for controls, detection engineering, and prioritization.
# - Intelligence-backed prioritization helps reduce breach likelihood and expected financial impact by focusing resources on the highest-probability, highest-impact scenarios.
# - This supports measurable outcomes for both technical teams and executive stakeholders.
#         """
#     )

st.header("References (APA-style summary)")
st.markdown(
    """
- IBM. (2026). *X-Force Threat Intelligence Index 2026*.
- Verizon. (2025a). *Data Breach Investigations Report*.
- Verizon. (2025b). *DBIR finance-sector analysis excerpts used in class*.
- MITRE ATT&CK. (n.d.). *Enterprise Matrix*. https://attack.mitre.org/
- PhishTank. (n.d.). https://phishtank.org/
- Ransomware.live. (n.d.). https://ransomware.live/
- Shodan. (n.d.). https://www.shodan.io/
- Deloitte. (2026).*Banking industry outlook 2026. Deloitte Insights* https://www.deloitte.com/us/en/insights/industry/financial-services/financial-services-industry-outlooks/banking-industry-outlook.html 
- IBM Institute for Business Value. (2026). *026 banking and financial markets outlook* IBM. https://www.ibm.com/thought-leadership/institute-business-value/en-us/report/2026-banking-financial-markets-outlook 
- KPMG. (2026). *Top banking trends for 2026* KPMG. https://kpmg.com/us/en/articles/2026/banking-trends.html 
- McKinsey & Company. (2024). *Global banking annual review*. McKinsey. https://www.mckinsey.com/industries/financial-services/our-insights/global-banking-annual-review 
- Moody’s Investors Service. (2026). *Global banking industry outlook 2026*. Moody’s. https://www.moodys.com/web/en/us/insights/credit-risk/outlooks/banking-2026.html 
- Wipfli. (2026). *State of the banking industry 2026*. Wipfli LLP. https://www.wipfli.com/insights/research/state-of-the-banking-industry-2026 
    """
)

st.info("Use the sidebar to navigate to Industry Background, Threat Trends, Critical Assets, Diamond Models, and Dashboard pages.")
