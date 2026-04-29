"""CTI Platform – root entry point. Pure router/config. No visible content."""

import streamlit as st

st.set_page_config(
    page_title="CTI Platform: U.S. Banking",
    page_icon="🏦",
    layout="wide",
    initial_sidebar_state="expanded",
)

pg = st.navigation(
    [
        st.Page("pages/0_Home.py",                                          title="Home",                           icon="🏠"),
        st.Page("pages/1_Overview.py",                           title="Industry Overview",            icon="🏛️"),
        st.Page("pages/2_Threat_Trends.py",                                 title="Threat Trends",                  icon="📈"),
        st.Page("pages/3_Critical_Assets.py",                               title="Critical Assets",                icon="🔒"),
        st.Page("pages/4_Diamond_Models.py",                                title="Diamond Models",                 icon="♦️"),
        st.Page("pages/5_Intel_Buyin.py",                                   title="Intel Buy-in",                   icon="💼"),
        st.Page("pages/6_Dashboard.py",                                     title="Dashboard",                      icon="📊"),
        st.Page("pages/9_Analytical_approaches.py",                         title="Analytical Approaches",          icon="🧠"),
        st.Page("pages/8_Data_Sources.py",                                  title="Data Sources",                   icon="📂"),
        st.Page("pages/10_References.py",                                   title="References",                     icon="📚"),
        st.Page("pages/11_Team.py",                                         title="Team",                           icon="👥"),
        st.Page("pages/12_Future_Directions.py",                            title="Future Directions",              icon="🔭"),
        st.Page("pages/13_Key_insights_and_intelligence_summary.py",   title="Key Insights & Intelligence Summary", icon="🧩"),
        st.Page("pages/14_Operational_Intelligence_and_Dissemination.py",   title="Operational Intelligence & Dissemination", icon="🚨"),
        st.Page("pages/15_Analytics.py",   title="Role-based Analytics", icon="📊"),
    ]
)

pg.run()


# """Milestone 1 CTI Streamlit app for US Banking."""

# import streamlit as st

# st.set_page_config(
#     page_title="US Banking CTI Platform - Milestone 1",
#     page_icon="🏦",
#     layout="wide",
# )

# CHASE_BLUE = "#117ACA"
# DARK_BLUE = "#0B3A69"
# LIGHT_BG = "#F4F8FC"

# # st.markdown(
# #     f"""
# #     <style>
# #     .stApp {{ background-color: {LIGHT_BG}; }}
# #     h1, h2, h3 {{ color: {DARK_BLUE}; }}
# #     [data-testid="stMetricValue"] {{ color: {CHASE_BLUE}; }}
# #     .block-container {{ padding-top: 1.2rem; }}
# #     </style>
# #     """,
# #     unsafe_allow_html=True,
# # )

# st.title("🏦 Cyber Threat Intelligence Platform: U.S. Banking")
# #st.caption("Milestone 1 - Industry baseline, threat trends, diamond models, and dashboard starter.")

# with st.container(border=True):
#     with st.expander("📌 Milestone 1"):
#         st.subheader("✅ What's Changed in Milestone 1")
#         st.checkbox("We tightened our industry focus to the banking sector within the finance industry", value=True, disabled=True)
#         st.checkbox("We focused on banking in North America (United States)", value=True, disabled=True)
#         st.checkbox("We removed AZSecure as a relevant data source", value=True, disabled=True)
#         st.checkbox(
#             "We prioritized top banking threats as credential theft then phishing, followed by ransomware and web application attacks",
#             value=True,
#             disabled=True,
#         )

# with st.container(border=True):
#     with st.expander("📌 Milestone 2"):
#         st.subheader("✅ What's New in Milestone 2")
#         st.checkbox("We created the data explorer", value=True, disabled=True)
#         st.checkbox("We updated team roles in the pages subfolder", value=True, disabled=True)
#         st.checkbox("We included Threatfox as a datasource and worked with APIs rather than synthetic data", value=True, disabled=True)
#         st.checkbox("We updated the dashboard starter with new filters, metrics, data and charts that correlate banking assets with threat indicators", value=True, disabled=True)
#         st.checkbox("New supporting pages were added around collection strategy, data source identification/justification, and references.", value=True, disabled=True)
#         st.checkbox("We download threat intelligence data from phishtank and  in the data folder", value=True, disabled=True)

# with st.container(border=True):
#     with st.expander("📌 Milestone 3"):
#         st.subheader("✅ Milestone 3: New Features")
#         st.checkbox("Analytical Approaches: Phishing URL Text Mining, Ransomware Event Correlation and Kmeans clustering with threatfox data", value=True, disabled=True)
#         st.checkbox("Interactive Analytics Panel: Multi-source filtering of analytics with unique-key state management", value=True, disabled=True)
#         st.checkbox("Preliminary Visualizations: Temporal trends and threat distribution with process/value justifications", value=True, disabled=True)
#         st.checkbox("Operational Metrics: Implementation of MTTD reduction estimates and Indicator Precision tracking", value=True, disabled=True)
#         st.checkbox("Enhanced UI: Wide-mode dashboard layout and automated EST refresh timestamps", value=True, disabled=True)
#         st.checkbox("Validation: Added error analysis and data limitation documentation", value=True, disabled=True)

# with st.container(border=True):
#     with st.expander("📌 Milestone 4"):
#         st.subheader("✅ Milestone 4: What Changed")
#         st.checkbox("K-means: Updated kmeans algorithm, included kmeans outputs in analytics panel ", value=True, disabled=True)
#         st.checkbox("Role-based Tabs: Executive Summary and Analyst Drill-Down", value=True, disabled=True)
#         st.checkbox("Preliminary Visualizations: Temporal trends and threat distribution with process/value justifications", value=True, disabled=True)
#         st.checkbox("", value=True, disabled=True)
#         st.checkbox("", value=True, disabled=True)
#         st.checkbox("", value=True, disabled=True)

# st.info("Use the sidebar to navigate to Industry Background, Threat Trends, Critical Assets, Dashboard, and Analytics Panel.")
