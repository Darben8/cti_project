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
        st.Page("pages/1_Overview.py",                                      title="Overview",            icon="🏛️"),
        st.Page("pages/2_Dashboard.py",                                     title="Dashboard",                      icon="📊"),
        st.Page("pages/7_Data_Explorer.py",                                 title="Data Explorer",                  icon="🔍"),
        st.Page("pages/8_Data_Sources.py",                                  title="Data Sources",                   icon="📂"),
        st.Page("pages/9_Analytical_approaches.py",                         title="Analytical Approaches",          icon="🧠"),
        st.Page("pages/10_References.py",                                   title="References",                     icon="📚"),
        st.Page("pages/11_Team.py",                                         title="Team",                           icon="👥"),
        st.Page("pages/12_Future_Directions.py",                            title="Future Directions",              icon="🔭"),
        st.Page("pages/13_Key_insights_and_intelligence_summary.py",   title="Key Insights & Intelligence Summary", icon="🧩"),
        st.Page("pages/14_Operational_Intelligence_and_Dissemination.py",   title="Operational Intelligence & Dissemination", icon="🚨"),
        st.Page("pages/15_Analytics.py",   title="Role-based Analytics", icon="📊"),
    ]
)

pg.run()


