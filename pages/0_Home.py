"""Home page – CTI Platform: U.S. Banking."""

import streamlit as st

# ── Global CSS ────────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600;700&display=swap');

    /* ── Root theme ── */
    html, body, [data-testid="stAppViewContainer"] {
        background-color: #080f1a;
        color: #c9d1d9;
        font-family: 'IBM Plex Sans', sans-serif;
    }

    /* ── Sidebar ── */
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

    /* ── Main content area ── */
    .block-container {
        padding-top: 2rem;
        max-width: 1700px;
    }

    /* ── Hero banner ── */
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
    .hero-tags {
        display: flex;
        gap: 0.6rem;
        flex-wrap: wrap;
    }
    .tag {
        background: rgba(56,189,248,0.08);
        border: 1px solid rgba(56,189,248,0.25);
        color: #38bdf8;
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.7rem;
        padding: 0.25rem 0.65rem;
        border-radius: 4px;
        letter-spacing: 0.05em;
    }

    /* ── Section label ── */
    .section-label {
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.68rem;
        letter-spacing: 0.18em;
        text-transform: uppercase;
        color: #38bdf8;
        margin: 2.2rem 0 1rem;
        padding-left: 2px;
    }

    /* ── Milestone cards ── */
    .ms-card {
        background: #0d1526;
        border: 1px solid #1e3a5f;
        border-radius: 10px;
        padding: 1.4rem 1.6rem;
        margin-bottom: 1rem;
        transition: border-color 0.2s;
    }
    .ms-card:hover { border-color: #2d5a8e; }
    .ms-card-header {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        margin-bottom: 0.9rem;
    }
    .ms-badge {
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.65rem;
        font-weight: 600;
        letter-spacing: 0.12em;
        padding: 0.2rem 0.55rem;
        border-radius: 3px;
        text-transform: uppercase;
    }
    .ms-badge-done {
        background: rgba(34,197,94,0.12);
        border: 1px solid rgba(34,197,94,0.3);
        color: #4ade80;
    }
    .ms-badge-new {
        background: rgba(56,189,248,0.12);
        border: 1px solid rgba(56,189,248,0.35);
        color: #38bdf8;
    }
    .ms-title {
        font-size: 1rem;
        font-weight: 600;
        color: #e6edf3;
    }
    .ms-item {
        display: flex;
        align-items: flex-start;
        gap: 0.6rem;
        padding: 0.3rem 0;
        font-size: 0.875rem;
        color: #8ba3c0;
        line-height: 1.5;
    }
    .ms-item-check { color: #4ade80; font-size: 0.85rem; flex-shrink: 0; margin-top: 2px; }
    .ms-item-dot   { color: #2d5a8e; font-size: 0.85rem; flex-shrink: 0; margin-top: 2px; }

    /* ── Nav hint ── */
    .nav-hint {
        background: rgba(56,189,248,0.05);
        border: 1px solid rgba(56,189,248,0.15);
        border-radius: 8px;
        padding: 0.9rem 1.2rem;
        font-size: 0.82rem;
        color: #8ba3c0;
        margin-top: 2rem;
    }
    .nav-hint strong { color: #38bdf8; }

    /* ── Hide Streamlit chrome ── */
    #MainMenu, footer { visibility: hidden; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── Hero ──────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <div class="hero">
        <div class="hero-eyebrow">Hackstreet Girls · Cyber Threat Intelligence · Finance</div>
        <div class="hero-title">CTI Platform:<br><span>U.S. Banking Sector</span></div>
        <div class="hero-sub">
            A tactical and operational threat intelligence platform tracking phishing campaigns,
            ransomware activity, IOC clusters, and exposure data targeting U.S. financial institutions.
        </div>
        <div class="hero-tags">
            <span class="tag">PhishTank</span>
            <span class="tag">ThreatFox</span>
            <span class="tag">ransomware.live</span>
            <span class="tag">Shodan</span>
            <span class="tag">K-means Clustering</span>
            <span class="tag">Text mining</span>
            <span class="tag">Event Correlation</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Milestone Timeline ────────────────────────────────────────────────────────
st.markdown('<div class="section-label">// Project Timeline</div>', unsafe_allow_html=True)

# ── Milestone 1 ──
with st.expander("📌 Milestone 1 — Industry Baseline & Threat Framing"):
    st.markdown(
        """
        <div class="ms-card-header">
            <span class="ms-badge ms-badge-done">Complete</span>
            <span class="ms-title">Industry scoping, threat prioritization, Diamond Model foundation</span>
        </div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Tightened industry focus to the U.S. banking sector within finance</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Focused geography on North America (United States)</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Removed AZSecure as a relevant data source</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Prioritized top banking threats: credential theft → phishing → ransomware → web application attacks</div>
        """,
        unsafe_allow_html=True,
    )

# ── Milestone 2 ──
with st.expander("📌 Milestone 2 — Data Integration & Dashboard"):
    st.markdown(
        """
        <div class="ms-card-header">
            <span class="ms-badge ms-badge-done">Complete</span>
            <span class="ms-title">Live API sources, dynamic data explorer, expanded dashboard</span>
        </div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Created the dynamic Data Explorer page</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Integrated ThreatFox via live API — replaced synthetic data</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Updated Dashboard with source filters, metrics, and asset-aligned threat charts</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Added collection strategy, data source identification/justification, and references pages</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Downloaded and integrated PhishTank and ransomware.live datasets into data folder</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Updated team roles in pages subfolder</div>
        """,
        unsafe_allow_html=True,
    )

# ── Milestone 3 ──
with st.expander("📌 Milestone 3 — Analytical Methods & Validation"):
    st.markdown(
        """
        <div class="ms-card-header">
            <span class="ms-badge ms-badge-done">Complete</span>
            <span class="ms-title">Text mining, ransomware correlation, K-means clustering, operational metrics</span>
        </div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Phishing URL Text Mining: TF-IDF, n-gram analysis, keyword summaries</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Ransomware Event Correlation: cross-source group risk, IOC overlap, network graph</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>K-means clustering over ThreatFox-derived inputs</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Interactive Analytics Panel with multi-source filtering and unique-key state management</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Operational metrics: MTTD reduction estimates and indicator precision tracking</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Validation: error analysis, data limitation documentation, approach justification</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Enhanced UI: wide-mode layout, automated EST refresh timestamps</div>
        """,
        unsafe_allow_html=True,
    )

# ── Milestone 4 ──
with st.expander("📌 Milestone 4 — Operational Intelligence & Final Platform", expanded=True):
    st.markdown(
        """
        <div class="ms-card-header">
            <span class="ms-badge ms-badge-new">Current</span>
            <span class="ms-title">Role-based views, triage dashboard, dissemination framework, future directions</span>
        </div>
        <div class="ms-item"><span class="ms-item-check">✓</span>K-means: updated algorithm and integrated clustering outputs into Analytics Panel</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Role-Based Views: Executive Summary and Analyst Drill-Down tabs in Analytical Approaches</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Key Insights: three intelligence findings with implications and recommended actions</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Operational Triage Dashboard: severity/category filtering, COA column, CSV/JSON export</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Operational Intelligence page: who/when/what/how dissemination framework</div>
        <div class="ms-item"><span class="ms-item-dot">○</span>STIX-like JSON export and IOC-to-control course-of-action mapping</div>
        <div class="ms-item"><span class="ms-item-dot">✓</span>Future CTI Platform Directions: three justified development paths</div>
        <div class="ms-item"><span class="ms-item-dot">✓</span>Polished UI, consistent dark theme, updated README with user guide</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Condensed the Dashboard page and added new tabs</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Redesigned homepage with new hero banner, project framing, and timeline summary</div>
        <div class="ms-item"><span class="ms-item-check">✓</span>Introduced overview page that provides a concise project summary</div>
        """,
        unsafe_allow_html=True,
    )

# ── Nav hint ──────────────────────────────────────────────────────────────────
st.markdown(
    """
    <div class="nav-hint">
        <strong>Navigate</strong> using the sidebar. Start with
        <strong>Dashboard</strong> for the operational view,
        <strong>Analytical Approaches</strong> for role-based intelligence briefings,
        or <strong>Future Directions</strong> for platform roadmap.
    </div>
    """,
    unsafe_allow_html=True,
)