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
        st.Page("pages/0_Home.py",                          title="Home",                           icon="🏠"),
        st.Page("pages/1_Overview.py",                      title="Overview",                        icon="🏛️"),
        st.Page("pages/2_Dashboard.py",                     title="Dashboard",                      icon="📊"),
        st.Page("pages/3_Data_Sources.py",                  title="Data Sources",                   icon="📂"),
        st.Page("pages/4_Key_insights.py",                  title="Key Insights & Intelligence Summary", icon="🧩"),
        st.Page("pages/5_Operational_Intelligence_and_Dissemination.py",   title="Operational Intelligence & Dissemination", icon="🚨"),
        st.Page("pages/6_Analytics.py",                     title="Role-based Analytics",      icon="📊"),
        st.Page("pages/7_Future_Directions.py",             title="Future Directions",         icon="🔭"),
        st.Page("pages/8_Actionable_Outputs.py",   title="Actionable Outputs",              icon="🎯"),
        st.Page("pages/9_Team.py",                     title="Team",                        icon="👥"),
        st.Page("pages/10_References.py",              title="References",                  icon="📚"),
    ]
)

pg.run()


