import streamlit as st
import pandas as pd
import plotly.express as px
from pyvis.network import Network
import streamlit.components.v1 as components

#st.set_page_config(page_title="Threat Intelligence Dashboard", layout="wide")

# ---------------------------------------------------------
# GLOBAL UI THEME
# ---------------------------------------------------------
st.markdown("""
<style>
html, body, [data-testid="stAppViewContainer"] {
    background-color: #080f1a;
    color: #c9d1d9;
    font-family: 'IBM Plex Sans', sans-serif;
}
.block-container {
    padding-top: 2rem !important;
}
h1, h2, h3 {
    font-weight: 600;
    color: #e6edf3;
}
.hero {
    background: linear-gradient(135deg, #0f2644 0%, #080f1a 60%, #091a10 100%);
    border: 1px solid #1e3a5f;
    border-radius: 12px;
    padding: 2.5rem 3rem;
    margin-bottom: 2rem;
}
.hero-eyebrow {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.72rem;
    letter-spacing: 0.2em;
    color: #38bdf8;
    text-transform: uppercase;
}
.hero-title {
    font-size: 2.2rem;
    font-weight: 700;
    color: #e6edf3;
    line-height: 1.15;
}
.hero-title span {
    color: #38bdf8;
}
.hero-sub {
    font-size: 1rem;
    color: #8ba3c0;
    font-weight: 300;
    max-width: 600px;
    line-height: 1.6;
    margin-top: 0.6rem;
}
.hero-tags {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin-top: 1rem;
}
.tag {
    background: rgba(56,189,248,0.08);
    border: 1px solid rgba(56,189,248,0.25);
    color: #38bdf8;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.7rem;
    padding: 0.25rem 0.65rem;
    border-radius: 4px;
}
.section-box {
    background: #0d1526;
    border: 1px solid #1e3a5f;
    border-radius: 10px;
    padding: 1.2rem 1.4rem;
    margin-bottom: 1.2rem;
}
.badge {
    display: inline-block;
    padding: 0.2rem 0.55rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-family: 'IBM Plex Mono', monospace;
    margin-right: 0.4rem;
}
.badge-critical { background: rgba(239,68,68,0.12); border: 1px solid rgba(239,68,68,0.35); color: #f87171; }
.badge-high { background: rgba(251,146,60,0.12); border: 1px solid rgba(251,146,60,0.35); color: #fb923c; }
.badge-medium { background: rgba(250,204,21,0.12); border: 1px solid rgba(250,204,21,0.35); color: #facc15; }
.badge-trend-up { color: #4ade80; }
.badge-trend-down { color: #f87171; }
.badge-trend-stable { color: #38bdf8; }
#MainMenu, footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# HERO BANNER
# ---------------------------------------------------------
st.markdown("""
<div class="hero">
    <div class="hero-eyebrow">CTI Platform</div>
    <div class="hero-title">Key Insights<br><span>Intelligence Summary</span></div>
    <div class="hero-sub">
        Consolidated intelligence from active datasets, highlighting ransomware, C2 infrastructure, phishing clusters, and botnet activity.
    </div>
    <div class="hero-tags">
        <span class="tag">Akira Ransomware</span>
        <span class="tag">QakBot C2</span>
        <span class="tag">Phishing</span>
        <span class="tag">Ramnit Botnet</span>
        <span class="tag">MITRE ATT&CK</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# INTELLIGENCE SUMMARY WITH SEVERITY + TRENDS
# ---------------------------------------------------------

# 1 — C2 Infrastructure
st.markdown("""
### **1. Adversaries are using consistent C2 infrastructure across global regions**
<div class="section-box">
<span class="badge badge-high">High Severity</span>
<span class="badge badge-trend-up">↑ Increasing Activity</span>
<span class="badge">Confidence: High</span>
<br><br>

<b>Analysis of `filtered_iocs_threatfox` shows:</b><br>
• Repeated use of <b>ports 443, 995, 80, 2078, 2222</b><br>
• <b>IP:Port combinations</b> tied to QakBot, Emotet, Feodo<br>
• C2 servers hosted in AS37705, AS8151, AS11830, AS1241, WIND-AS<br><br>

<b>Implication:</b><br>
Encrypted and legacy ports blend into normal traffic, increasing detection difficulty.
</div>
""", unsafe_allow_html=True)

# 2 — Akira Ransomware
st.markdown("""
### **2. Significant ransomware activity targeting financial sector (Akira group)**
<div class="section-box">
<span class="badge badge-critical">Critical Severity</span>
<span class="badge badge-trend-up">↑ Rapid Growth</span>
<span class="badge">Confidence: High</span>
<br><br>

<b>The `finance_group_iocs` dataset contains:</b><br>
• Dozens of Akira ransomware hashes<br>
• Multiple Bitcoin ransom payment addresses<br>
• MITRE ATT&CK TTPs: T1003.001, T1021.001, T1047, T1112, T1562.001, T1486<br><br>

<b>Implication:</b><br>
Akira is actively deploying new builds. Credential hardening and backup validation are essential.
</div>
""", unsafe_allow_html=True)

# 3 — Phishing Campaigns
st.markdown("""
### **3. Surge in banking-themed phishing campaigns**
<div class="section-box">
<span class="badge badge-high">High Severity</span>
<span class="badge badge-trend-up">↑ Increasing Volume</span>
<span class="badge">Confidence: Medium</span>
<br><br>

<b>The `verified_online_banking_finance` dataset shows:</b><br>
• 30+ active phishing URLs<br>
• Hosted on Vercel, Lovely.app, dweb.link, .co.nl<br>
• Mimic banking login portals<br><br>

<b>Implication:</b><br>
Cloud hosting enables rapid phishing rotation. Stronger brand monitoring and takedowns required.
</div>
""", unsafe_allow_html=True)

# 4 — QakBot
st.markdown("""
### **4. QakBot remains a persistent threat to financial networks**
<div class="section-box">
<span class="badge badge-high">High Severity</span>
<span class="badge badge-trend-stable">→ Stable Activity</span>
<span class="badge">Confidence: High</span>
<br><br>

<b>Cross-referencing datasets reveals:</b><br>
• Multiple QakBot C2 servers active in Feb–Mar 2026<br>
• Examples: 102.158.228.15:443, 197.0.81.220:443, 41.62.43.21:443<br><br>

<b>Implication:</b><br>
QakBot continues as an initial access vector. Outbound 443 monitoring is essential.
</div>
""", unsafe_allow_html=True)

# 5 — Ramnit
st.markdown("""
### **5. Ramnit botnet domains indicate automated credential theft**
<div class="section-box">
<span class="badge badge-medium">Medium Severity</span>
<span class="badge badge-trend-up">↑ Increasing DGA Activity</span>
<span class="badge">Confidence: Medium</span>
<br><br>

<b>The dataset includes 100+ autogenerated Ramnit C2 domains:</b><br>
• wnlgghgffr.com<br>
• wpaxdlstrs.com<br>
• xoodachpaujnikmpp.com<br><br>

<b>Implication:</b><br>
Ramnit remains active using DGAs. DNS monitoring and sinkholing are required.
</div>
""", unsafe_allow_html=True)


# ---------------------------------------------------------
# LOAD DATASETS
# ---------------------------------------------------------
processed_ports = pd.read_csv("data/processed_port_iocs.csv", on_bad_lines="skip")
threat_events = pd.read_csv("data/threat_events.csv", on_bad_lines="skip")

# ---------------------------------------------------------
# VISUALIZATION DROPDOWN
# ---------------------------------------------------------
viz = st.selectbox(
    "Select a visualization:",
    [
        "C2 Port Network Visualization",
        "Akira Ransomware – MITRE Technique Frequency"
    ]
)

# ---------------------------------------------------------
# VISUALIZATION 1 — C2 PORT NETWORK
# ---------------------------------------------------------
if viz == "C2 Port Network Visualization":
    st.markdown('<div class="chart-box">', unsafe_allow_html=True)

    if "port" not in processed_ports.columns:
        st.error("❌ processed_port_iocs.csv must contain a 'port' column.")
    else:
        processed_ports["port"] = pd.to_numeric(processed_ports["port"], errors="coerce")
        port_counts = processed_ports["port"].value_counts().reset_index()
        port_counts.columns = ["Port", "Count"]

        net = Network(height="600px", width="100%", bgcolor="#ffffff", font_color="black")
        net.add_node("C2 Ports", size=50, color="#ff4d4d")

        for _, row in port_counts.iterrows():
            port = str(row["Port"])
            count = int(row["Count"])
            net.add_node(port, size=10 + count, title=f"Port {port} — Count: {count}", color="#1f77b4")
            net.add_edge("C2 Ports", port)

        net.save_graph("port_network.html")
        HtmlFile = open("port_network.html", "r", encoding="utf-8")
        components.html(HtmlFile.read(), height=600)

    st.markdown('</div>', unsafe_allow_html=True)

# ---------------------------------------------------------
# VISUALIZATION 2 — MITRE TECHNIQUE BAR CHART
# ---------------------------------------------------------
elif viz == "Akira Ransomware – MITRE Technique Frequency":
    st.markdown('<div class="chart-box">', unsafe_allow_html=True)

    threat_events = threat_events.rename(columns={
        "technique": "mitre_technique",
        "ttp": "mitre_technique",
        "attack_id": "mitre_technique"
    })

    if "mitre_technique" not in threat_events.columns:
        st.error("❌ threat_events.csv must contain a 'mitre_technique' column.")
    else:
        ttp_counts = threat_events["mitre_technique"].value_counts().reset_index()
        ttp_counts.columns = ["MITRE Technique", "Count"]

        fig = px.bar(
            ttp_counts,
            x="MITRE Technique",
            y="Count",
            title="Akira Ransomware – MITRE Technique Usage",
            color="Count",
            color_continuous_scale="Reds"
        )
        fig.update_layout(xaxis_title="MITRE Technique", yaxis_title="Frequency")
        st.plotly_chart(fig, use_container_width=True)

    st.markdown('</div>', unsafe_allow_html=True)