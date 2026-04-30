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


st.title("📚 PROJECT REFERENCES")

st.header(" (APA-style summary)")
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