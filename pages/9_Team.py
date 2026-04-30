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
        "milestone_4": "Operational Triage Dashboard, merging of dashboard and data explorer",
        "signature": "Jemima Lumbala (04/29/2026)",
    },
    {
        "name": "Abena Darko",
        "milestone_1": "Threat Intelligence Research & API integration, dashboard development, and write-up",
        "milestone_2": "Ethics and Data Governance, Security-Aware Development Practices, App review",
        "milestone_3": "Phishing URL text mining, ransomware event correlation and analytics panel",
        "milestone_4": "Role-based views, homepage redesign, and app review",
        "signature": "Abena Darko (04/22/2026)",
    },
    {
        "name": "Shani Nanje",
        "milestone_1": "Threat Intelligence Use Case Development",
        "milestone_2": "Data Source Identification and Justification",
        "milestone_3": "Clustering analysis of threatfox data and write-up",
        "milestone_4": "Operational Intelligence and Dissemination",
        "signature": "Shani Nanje (04/22/2026)",
    },
    {
        "name": "Otis Service",
        "milestone_1": "Project Manager, Industry Research, Streamlit app development, and write-up",
        "milestone_2": "Data validation, data explorer",
        "milestone_3": "CTI Visualization development and write-up",
        "milestone_4": "Actionable outputs",
        "signature": "Otis Service (04/23/2026)",
    },
    {
        "name": "Jiwon Chang",
        "milestone_1": "Intelligence buy in research",
        "milestone_2": "Data explorer page development",
        "milestone_3": "Validation and Error Analysis",
        "milestone_4": "Future CTI Platform Directions",
        "signature": "Jiwon Chang (04/28/2026)",
    },
    {
        "name": "Supradipta Panta",
        "milestone_1": "Code review",
        "milestone_2": "Data Collection and Summary",
        "milestone_3": "Key Insights and Intelligence Summary",
        "milestone_4": "Key insights and intelligence summary, merging of threat trends, background, assets and diamond models into overview page",
        "signature": "Supradipta Panta (04/29/2026)",
    },
]

for member in team_members:
    with st.container(border=True):
        st.subheader(member["name"])
        st.write(f"Milestone 1 Role: {member['milestone_1']}")
        st.write(f"Milestone 2 Role: {member['milestone_2']}")
        st.write(f"Milestone 3 Role: {member['milestone_3']}")
        st.write(f"Milestone 4 Role: {member['milestone_4']}")
        st.write(f"Signature: {member['signature']}")
