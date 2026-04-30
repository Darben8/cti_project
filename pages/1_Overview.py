import streamlit as st
import pandas as pd
import plotly.graph_objects as go
# ─────────────────────────────────────────────────────────────
# GLOBAL THEME (Dark Cyber CTI Theme)
# ─────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600;700&display=swap');

    html, body, [data-testid="stAppViewContainer"] {
        background-color: #080f1a;
        color: #c9d1d9;
        font-family: 'IBM Plex Sans', sans-serif;
    }

    /* DO NOT TOUCH LEFT SIDEBAR ARROW */

    /* REMOVE ONLY THE BROKEN RIGHT-SIDE ARROW (keyboard_double_) */
    button[title="View fullscreen"] {
        display: none !important;
    }

    /* CUSTOM RIGHT-SIDE BUTTON (YOUR BLUE » BUTTON) */
    .right-arrow-btn {
        position: fixed;
        top: 14px;
        right: 14px;
        background: #0d1526;
        border: 1px solid #1e3a5f;
        color: #38bdf8;
        padding: 6px 12px;
        border-radius: 6px;
        font-size: 22px;
        cursor: pointer;
        z-index: 9999;
        font-weight: bold;
    }
    .right-arrow-btn:hover {
        border-color: #38bdf8;
        color: #7dd3fc;
    }

    /* Sidebar */
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

    /* Main content container */
    .block-container {
        padding-top: 2rem;
        max-width: 1800px;
    }

    /* Hero banner */
    .hero {
        background: linear-gradient(135deg, #0f2644 0%, #080f1a 60%, #091a10 100%);
        border: 1px solid #1e3a5f;
        border-radius: 12px;
        padding: 3rem 3.5rem 2.5rem;
        margin-bottom: 2.5rem;
        position: relative;
        overflow: hidden;
    }
    .hero::before {
        content: '';
        position: absolute;
        top: -60px; right: -60px;
        width: 260px; height: 260px;
        border-radius: 50%;
        background: radial-gradient(circle, rgba(56,189,248,0.08) 0%, transparent 70%);
    }
    .hero-eyebrow {
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.72rem;
        letter-spacing: 0.2em;
        color: #38bdf8;
        text-transform: uppercase;
        margin-bottom: 0.75rem;
    }
    .hero-title {
        font-size: 2.4rem;
        font-weight: 700;
        color: #e6edf3;
        line-height: 1.15;
        margin: 0 0 0.6rem;
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
        margin-bottom: 1.8rem;
    }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 0.5rem;
        border-bottom: 1px solid #1e3a5f;
        padding-bottom: 0.5rem;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #0d1526;
        color: #8ba3c0;
        border: 1px solid #1e3a5f;
        padding: 0.55rem 1.2rem;
        border-radius: 6px;
        font-size: 0.9rem;
        font-weight: 500;
    }
    .stTabs [aria-selected="true"] {
        background-color: #0f2644 !important;
        color: #38bdf8 !important;
        border: 1px solid #38bdf8 !important;
    }

    /* Cards */
    .info-card {
        background: #0d1526;
        border: 1px solid #1e3a5f;
        border-radius: 10px;
        padding: 1.4rem 1.6rem;
        margin-bottom: 1rem;
        transition: border-color 0.2s;
    }
    .info-card:hover { border-color: #2d5a8e; }

    h3, h4 {
        color: #e6edf3 !important;
        font-weight: 600 !important;
    }

    p, li {
        color: #8ba3c0 !important;
        font-size: 1rem;
        line-height: 1.55;
    }

    #MainMenu, footer, header { visibility: hidden; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ADD CUSTOM RIGHT ARROW BUTTON
#st.markdown('<div class="right-arrow-btn">»</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# HERO SECTION
# ─────────────────────────────────────────────────────────────
st.markdown(
    """
    <div class="hero">
        <div class="hero-eyebrow"></div>
        <div class="hero-title">Overview<br><span>Background,Trends and Assests</span></div>
        <div class="hero-sub">
            A structured breakdown of the Threat Trents, Intelligence Buy-In, Critical Assets and Diamond Models.
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ─────────────────────────────────────────────────────────────
# TABS (YOUR ORIGINAL TWO)
# ─────────────────────────────────────────────────────────────
tab1, tab2, tab3,tab4,tab5 = st.tabs([
    "Industry Background",
    "Threat Trends",
    "Intel Buy-In",
    "Critical Assests",
    "Diamond Models"
])

# ─────────────────────────────────────────────────────────────
# TAB 1 — YOUR CONTENT (UNCHANGED)
# ─────────────────────────────────────────────────────────────
with tab1:

    st.header("Industry Background")

    col1, col2 = st.columns([1.2, 1], gap="large")

    # LEFT COLUMN
    with col1:

        
        st.subheader("Key Services and Products")
        st.write("""
        - Retail & commercial banking  
        - Payments & lending  
        - Wealth & investment services  
        - Digital & mobile banking  
        """)
        

        
        st.subheader("Industry Size and Growth")
        st.write("""
        - Trillions in global assets  
        - Billions of customers  
        - High daily transaction volume  
        - Rapid shift to mobile & cloud banking  
        """)
        

        
        st.subheader("Major Industry Players")
        st.write("""
        - JPMorgan Chase  
        - Citi  
        - HSBC  
        - Goldman Sachs  
        - Bank of America  
        - Wells Fargo  
        - MUFG  
        """)
        

        
        st.subheader("Importance of Information Technology")
        st.write("""
        - Real‑time transaction processing  
        - Fraud detection & monitoring  
        - Online/mobile banking platforms  
        - Data protection & compliance  
        - Cloud & internet‑facing systems  
        """)
        

        
        st.subheader("Risk Concentration in Banking")
        st.write("""
        - High-value financial assets  
        - Sensitive customer data  
        - Constant online exposure  
        - Fast, high-volume transactions  
        """)
        

        
        st.subheader("Stakeholder Overview")
        st.markdown("""
        **SOC Analysts** – Monitor threats & respond quickly.  
        **Fraud Analysts** – Detect compromised accounts & prevent fraud.  
        **TI Analysts** – Track adversaries & emerging threats.  
        **CISOs/Leadership** – Use intelligence for risk decisions & strategy.  
        """)
        

        
        st.subheader("User Stories")
        st.markdown("""
        **Jordan (SOC)** – Monitor threats & prioritize risky assets.  
        **Alicia (CISO)** – Track KPIs & guide security investments.  
        **Rahul (TI Analyst)** – Build adversary profiles & trend dashboards.  
        """)
        

    # RIGHT COLUMN
    with col2:

        
        st.subheader("CTI Use Case – Fraud Prevention")
        st.markdown("""
        - Detects compromised credentials early  
        - Identifies carding & account takeover patterns  
        - Reduces fraud lead time  
        - Supports both tactical and executive decision-making  
        """)
        

        
        st.subheader("Decisions Enabled by CTI")
        st.markdown("""
        - Prioritize high-risk assets  
        - Identify emerging fraud campaigns  
        - Understand attacker capabilities  
        - Guide security investments  
        """)
        

        
        st.subheader("Data & Analytics Used")
        st.markdown("""
        - Dark web & criminal marketplace data  
        - Threat intel feeds (RF, PhishTank, ransomware.live, Shodan, DBIR)  
        - Transaction & behavioral analytics  
        """)
        


    # =============================================
    # RIGHT COLUMN
    # =============================================
    with col2:

        # CTI Use Case
        
        st.subheader("CTI Use Case – Fraud Prevention and Detection")
        st.markdown("""
        Many fraud tools only notify users after fraudulent activity occurs.  
        CTI helps close the gap between credential compromise and actual fraud.

        - Banking faces persistent pressure from credential abuse, phishing, ransomware, and web app attacks.
        - CTI reduces uncertainty by translating external threat data into action.
        - Intelligence-backed prioritization reduces breach likelihood and financial impact.
        - Supports measurable outcomes for both technical teams and executives.
        """)
        

        # Decisions Enabled by CTI
        
        st.subheader("Decisions Enabled by CTI")
        st.markdown("""
        CTI platforms like Recorded Future enable proactive, intelligence-driven decision making.

        They support:
        - Identification of critical assets and associated threats  
        - Prioritization of risks based on attacker behavior  
        - Detection of emerging fraud campaigns (carding, checker services, merchant compromise)  
        - Increased visibility into adversary capabilities  
        - Data‑driven cybersecurity investment decisions  
        """)
        

        # Data & Analytics
        
        st.subheader("Data and Analytics Used")
        st.markdown("""
        1. Dark web and criminal marketplace data  
        2. Threat intelligence feeds (Recorded Future, PhishTank, ransomware.live, Shodan, DBIR)  
        3. Transaction & behavioral analytics (internal fraud monitoring systems)  
        """)
        


with tab2:
    st.title("Threat Trends")
    st.caption("Summary of global and U.S. banking threats, supporting evidence, relevance, and CTI sources.")

    # -------------------------
    # Key Threat Trends (Card)
    # -------------------------
    
    st.subheader("Key Threat Trends")

    st.markdown("""
    **1. Credential Theft & Account Takeover**  
    - **Evidence:** Frequent targeting of customer logins, employee access, and weak/reused credentials.  
    - **Relevance to Banking:** Creates a direct path to fraud, account abuse, and unauthorized fund movement.  
    - **MITRE ATT&CK:** T1110, T1078, T1556  

    **2. Phishing & Social Engineering**  
    - **Evidence:** Customers and staff remain high‑value targets for credential capture and payment‑fraud lures.  
    - **Relevance to Banking:** Enables account compromise, BEC, and downstream intrusion activity.  
    - **MITRE ATT&CK:** T1566, T1056  

    **3. Ransomware & System Intrusion**  
    - **Evidence:** Financial entities face extortion‑driven attacks disrupting operations and exposing sensitive data.  
    - **Relevance to Banking:** Impacts payment processing, business continuity, and public trust.  
    - **MITRE ATT&CK:** T1486, T1021, T1071  

    **4. Web Application & API Attacks**  
    - **Evidence:** Internet‑facing portals and APIs are regularly probed for exploitable weaknesses.  
    - **Relevance to Banking:** Targets digital channels used for customer access and transactions.  
    - **MITRE ATT&CK:** T1190, T1505  
    """)
    

    # -------------------------
    # Global & U.S. Context (Card)
    # -------------------------
    
    st.subheader("Global and U.S. Context")

    st.markdown("""
    - External actors account for a substantial share of intrusions in banking and finance.  
    - Common initial access paths include phishing, credential abuse, and exploitation of exposed services.  
    - U.S. banks remain attractive due to monetizable data, direct payment capabilities, and customer‑facing digital channels.  
    - AI‑enabled phishing and fraud campaigns increase the speed, scale, and personalization of social engineering.  
    """)
    

    # -------------------------
    # Threat Intel Sources (Card)
    # -------------------------
    
    st.subheader("Threat Intel Sources in Scope")

    st.markdown("""
    - **PhishTank:** Phishing indicators and malicious URL reporting for triage and monitoring.  
    - **ransomware.live:** Publicly tracked victim disclosures and extortion activity.  
    - **Shodan:** Exposure intelligence for identifying internet‑facing systems and misconfiguration risks.  

    These sources support early CTI triage by helping analysts monitor active phishing, ransomware reporting,  
    and external exposure trends relevant to the U.S. banking sector.
    """)
    

with tab3:
    st.title("Intelligence Buy-In")
    st.caption("Business value of adopting Cyber Threat Intelligence (CTI) in banking.")

    # =========================
    # CURRENT THREAT LANDSCAPE
    # =========================
    
    st.subheader("Current Threat Landscape")

    st.markdown("""
    Banks are rapidly adopting AI, cloud, and digital services — expanding both capability and risk.
    Cybersecurity remains a top executive concern as attackers use automation and AI to scale operations.

    - AI accelerates phishing, deepfakes, and malware  
    - Shadow AI introduces unmanaged risk  
    - Banks remain prime targets due to sensitive data  

    **Stats:**  
    - 13% faced attacks on AI systems  
    - 97% of AI breaches lacked proper access controls  
    """)
    

    # =========================
    # BREACH FREQUENCY
    # =========================
    
    st.subheader("Frequency of Security Breaches")

    st.markdown("Cyber incidents are now expected events across financial institutions.")
    st.metric("Banks Reporting Incidents (Past Year)", "81%")
    st.markdown("Most banks experience at least one significant security event annually.")
    
    # =========================
    # IMPACT ON STRATEGY
    # =========================
    
    st.subheader("Impact on Organizational Strategy")

    st.markdown("""
    Modern banking requires a shift from reactive security to intelligence‑driven defense.

    - AI and cloud adoption expand attack surfaces  
    - Legacy systems create visibility gaps  
    - CTI helps prioritize and mitigate threats proactively  
    """)
    

    # =========================
    # COST OF DATA BREACHES
    # =========================
    
    st.subheader("Cost of Data Breaches")

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Global Average Cost", "$4.44M")
    with col2:
        st.metric("U.S. Average Cost", "$10.22M")

    st.markdown("""
    **Cost Drivers:**  
    - Shadow AI adds ~$670K per breach  
    - Costs include recovery, fines, downtime, and reputational loss  
    """)
    

    # =========================
    # VALUE OF CTI
    # =========================
    
    st.subheader("Value of Intelligence-Based Security")

    st.markdown("""
    CTI enables proactive defense and measurable business value:

    - Reduces fraud and financial loss  
    - Improves ROI on security investments  
    - Strengthens resilience and compliance  
    - Builds customer trust during digital transformation  

    CTI helps banks stay ahead of threats rather than reacting after damage occurs.
    """)
   

with tab4:
    st.title("Critical Assets")
    st.caption("Priority banking assets, their business value, and operational impact if compromised.")

    
    st.subheader("Critical Asset Table")

    assets = pd.read_csv("data/critical_assets.csv")
    

    # -------------------------
    # Justification (Shortened)
    # -------------------------
   
    st.subheader("Critical Asset Justification")

    st.markdown("""
    - **Core Banking Systems:** Enable daily transactions and account integrity.  
    - **Payment Processing (SWIFT/RTGS):** Essential for settlement and liquidity movement.  
    - **Identity & Access Management:** Controls authentication; compromise enables privilege escalation.  
    - **Online & Mobile Banking:** Main customer-facing channels and high‑risk attack surfaces.  
    - **Customer Data Repositories:** Hold regulated financial/PII data targeted for fraud and extortion.  
    - **Security Operations Tools:** Required for detection, response, and incident containment.  
    - **Tokenized Asset Platforms:** Emerging systems with integrity and custody risks.  
    """)

with tab5:
    st.title("💎 Diamond Models (Banking Threat Scenarios)")
    st.caption("Two complete, realistic Diamond Models aligned to banking threat trends.")

    # -------------------------
    # Diamond Model Plot Function
    # -------------------------
    def plot_diamond(title: str, adversary: str, capability: str, infrastructure: str, victim: str):
        positions = {
            "Adversary": (0, 1),
            "Capability": (1, 0),
            "Infrastructure": (0, -1),
            "Victim": (-1, 0),
        }
        node_text = {
            "Adversary": adversary,
            "Capability": capability,
            "Infrastructure": infrastructure,
            "Victim": victim,
        }

        edges = [
            ("Adversary", "Capability"),
            ("Capability", "Infrastructure"),
            ("Infrastructure", "Victim"),
            ("Victim", "Adversary"),
            ("Adversary", "Infrastructure"),
            ("Capability", "Victim"),
        ]

        fig = go.Figure()

        # Edges
        for a, b in edges:
            x0, y0 = positions[a]
            x1, y1 = positions[b]
            fig.add_trace(
                go.Scatter(
                    x=[x0, x1],
                    y=[y0, y1],
                    mode="lines",
                    line=dict(color="#117ACA", width=2),
                    hoverinfo="skip",
                    showlegend=False,
                )
            )

        # Nodes
        for node, (x, y) in positions.items():
            fig.add_trace(
                go.Scatter(
                    x=[x],
                    y=[y],
                    mode="markers+text",
                    marker=dict(size=48, color="#0B3A69"),
                    text=[node],
                    textposition="middle center",
                    textfont=dict(color="white", size=12),
                    customdata=[node_text[node]],
                    hovertemplate="%{customdata}<extra></extra>",
                    showlegend=False,
                )
            )

        fig.update_layout(
            title=title,
            xaxis=dict(visible=False, range=[-1.6, 1.6]),
            yaxis=dict(visible=False, range=[-1.4, 1.4]),
            plot_bgcolor="#F4F8FC",
            paper_bgcolor="#F4F8FC",
            margin=dict(l=10, r=10, t=50, b=10),
            height=500,
        )
        st.plotly_chart(fig, use_container_width=True)

    # -------------------------
    # Model A
    # -------------------------
    st.markdown('<div class="info-card">', unsafe_allow_html=True)
    st.subheader("Model A: Phishing → Credential Theft → Account Takeover")

    plot_diamond(
        "Diamond Model A",
        adversary="Organized cybercrime operators monetizing stolen banking credentials.",
        capability="Phishing kits, credential harvesting, infostealers, MFA bypass attempts (ATT&CK: T1566, T1110, T1556).",
        infrastructure="Type 1: fake bank domains, credential collection servers, VPN/proxy. Type 2: dark‑web markets, coordination channels.",
        victim="Retail customers, SMB account holders, and bank employees. Assets: credentials, MFA tokens, accounts, credit lines.",
    )

    st.markdown("""
    **Attack flow:**
    1. Victim receives phishing email impersonating a bank.  
    2. Victim submits credentials on spoofed portal.  
    3. Adversary accesses legitimate banking session.  
    4. Fraudulent transfers and account abuse follow.  
    """)
    st.markdown('</div>', unsafe_allow_html=True)

    st.divider()

    # -------------------------
    # Model B
    # -------------------------
    st.markdown('<div class="info-card">', unsafe_allow_html=True)
    st.subheader("Model B: Initial Access Exploit → Lateral Movement → Ransomware Extortion")

    plot_diamond(
        "Diamond Model B",
        adversary="Ransomware-as-a-service affiliate or organized extortion group targeting financial institutions.",
        capability="Exploit kits for edge services, privilege escalation, lateral movement, exfiltration and encryption (ATT&CK: T1190, T1021, T1486).",
        infrastructure="Type 1: exploit delivery, C2 channels, payload staging. Type 2: leak sites and crypto wallets for extortion.",
        victim="Bank IT admins/SOC teams and enterprise users. Assets: core banking, payment systems, customer data, AD/IAM.",
    )

    st.markdown("""
    **Attack flow:**
    1. Adversary exploits vulnerable VPN/web service.  
    2. Establishes foothold and escalates privileges.  
    3. Moves laterally across internal systems.  
    4. Exfiltrates data and deploys ransomware for dual extortion.  
    """)
    st.markdown('</div>', unsafe_allow_html=True)
