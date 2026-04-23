import streamlit as st

LIGHT_TEAL = "#E9F8F6"

st.markdown(
    f"""
    <style>
    .stApp {{ background-color: {LIGHT_TEAL}; }}
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("Team Roles & Contributions")

team_members = [
    {
        "name": "Jemima Lumbala",
        "milestone_1": "Alignment, streamlit app page navigation, threat intel buy-in page",
        "milestone_2": "Data Source Identification and Justification",
        "milestone_3": "Interactive anlytics panel development and write-up",
        "signature": "Jemima Lumbala (04/09/2026)",
    },
    {
        "name": "Abena Darko",
        "milestone_1": "Threat Intelligence Research & API integration, dashboard development, and write-up",
        "milestone_2": "Ethics and Data Governance, Security-Aware Development Practices, App review",
        "milestone_3": "Phishing URL text mining, ransomware event correlation and analytics panel",
        "signature": "Abena Darko (04/22/2026)",
    },
    {
        "name": "Shani Nanje",
        "milestone_1": "Threat Intelligence Use Case Development",
        "milestone_2": "Data Source Identification and Justification",
        "milestone_3": "Clustering analysis of threatfox data and write-up",
        "signature": "Shani Nanje (04/22/2026)",
    },
    {
        "name": "Otis Service",
        "milestone_1": "Project Manager, Industry Research, Streamlit app development, and write-up",
        "milestone_2": "Data validation, data explorer",
        "milestone_3": "",
        "signature": "Otis Service (04/09/2026)",
    },
    {
        "name": "Jiwon Chang",
        "milestone_1": "Intelligence buy in research",
        "milestone_2": "Data explorer page development",
        "milestone_3": "Validation and Error Analysis",
        "signature": "Jiwon Chang (04/23/2026)",
    },
    {
        "name": "Supradipta Panta",
        "milestone_1": "Code review",
        "milestone_2": "Data Collection and Summary",
        "milestone_3": "",
        "signature": "Supradipta Panta (04/07/2026)",
    },
]

for member in team_members:
    with st.container(border=True):
        st.subheader(member["name"])
        st.write(f"Milestone 1 Role: {member['milestone_1']}")
        st.write(f"Milestone 2 Role: {member['milestone_2']}")
        st.write(f"Milestone 3 Role: {member['milestone_3']}")
        st.write(f"Signature: {member['signature']}")
