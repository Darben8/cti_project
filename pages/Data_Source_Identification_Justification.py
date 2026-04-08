import streamlit as st

st.title("CTI Data Sources: PhishTank & ThreatFox")

tab1, tab2 = st.tabs(["PhishTank", "ThreatFox"])

# ── PhishTank Tab ──────────────────────────────────────────────────────────────
with tab1:
    st.header("PhishTank")

    col1, col2 = st.columns([1, 1], gap="large")

    with col1:
        st.subheader("Background")
        st.markdown(
            """
            PhishTank is a free community-driven platform operated by **Cisco Talos Intelligence Group**
            that acts as a clearing house for data and information about phishing on the internet.
            It collects, verifies, and distributes known phishing URLs (malicious domains, URLs)
            submitted by users and security researchers. The dataset is used in threat intelligence
            pipelines, email security tools, and anti-phishing research.
            """
        )

        st.subheader("Value for Banking")
        st.markdown(
            """
            Phishing is the **#1 attack vector against banks**. Financial institutions face:
            - Credential harvesting pages mimicking online banking portals
            - Fake customer service login pages
            - Phishing emails targeting employees
            - Fraudulent payment authorization pages

            PhishTank helps banks:
            - Identify active phishing campaigns impersonating their brand
            - Block malicious URLs at the email gateway or firewall
            - Identify attacker infrastructure (domains, hosting providers, IPs)
            - Detect trends in phishing kits targeting financial services
            """
        )

        st.subheader("Who Generates the Data?")
        st.markdown(
            """
            - Security researchers
            - Open-source intelligence contributors
            - Automated submissions
            - Anti-phishing vendors
            """
        )

    with col2:
        st.subheader("How Much Data Is Available?")
        st.markdown(
            """
            - Tens of thousands of active phishing URLs
            - Historical archive spanning years of phishing campaigns
            - Daily updates with new submissions
            """
        )

        st.subheader("Why This Data Source? (Diamond Model)")
        st.markdown(
            """
            PhishTank gives visibility into attacker infrastructure and victim targeting,
            ideal for financial CTI. It maps to all four diamond model vertices:

            - **Adversary:** Identifies phishing groups and recurring threat actors through repeated infrastructure patterns
            - **Infrastructure:** URLs, domains, hosting providers, IPs
            - **Capability:** Shows attacker use of phishing kits, cloned banking portals, and credential harvesters
            - **Victim:** Banking customers and employees are top targets
            """
        )

        st.subheader("Industry Usage")
        st.markdown(
            """
            Financial institutions and cybersecurity vendors integrate PhishTank feeds into
            SIEM and fraud detection systems to block malicious domains and detect phishing
            campaigns in real time. Common users include:
            - Fraud prevention teams
            - SOC analysts
            - Email security vendors serving banks
            """
        )

# ── ThreatFox Tab ─────────────────────────────────────────────────────────────
with tab2:
    st.header("ThreatFox")

    col1, col2 = st.columns([1, 1], gap="large")

    with col1:
        st.subheader("Background")
        st.markdown(
            """
            ThreatFox, run by **abuse.ch** and **Spamhaus**, is an OSINT platform that allows
            anyone to share indicators of compromise (IOCs) associated with malware. Contributors
            can share domains, IP addresses, and email addresses associated with malware and
            botnet command and control (C2). Every indicator in the database is tied to a
            specific, named malware family such as QakBot, Dridex, TrickBot, and IcedID.
            """
        )

        st.subheader("Value for Banking")
        st.markdown(
            """
            Financial institutions are prime targets for threat actors using malware, banking
            trojans, and credential harvesters. ThreatFox's entire dataset maps to the malware
            families that most aggressively target financial institutions.

            **Banking Trojan C2 Blocking:** Banking trojans (QakBot, Dridex, TrickBot, IcedID)
            depend on C2 servers to send instructions, steal credentials, and inject fake banking
            forms. Blocking known malicious IPs and domains cuts off trojans from their C2 servers.

            **Confidence Scoring for IOCs:** ThreatFox assigns a confidence score (0–100) to each
            IOC, helping banks prioritize risk — high-confidence IOCs carry more weight in fraud
            detection systems.

            **Real-Time Threat Feeds:** Indicators are kept current; submissions older than 10 days
            are discouraged and those older than 6 months are removed, reducing false positives and
            ensuring legitimate customers are not wrongly flagged.
            """
        )

    with col2:
        st.subheader("Who Generates the Data?")
        st.markdown(
            """
            - **Community:** Security researchers and analysts submit IOCs associated with
              malware botnets
            - **Spamhaus:** abuse.ch integrated with Spamhaus and has become one of the largest
              independently crowdsourced intelligence sources for tracked malware and botnets
            """
        )

        st.subheader("How Much Data Is Available?")
        st.markdown(
            """
            - Over **1.7 million IOCs** shared on ThreatFox
            - ~**95 million API requests** answered in a single 30-day period (October 2024)
            - Enables real-time insights for threat hunting and mitigation
            """
        )

        st.subheader("Why This Data Source? (Diamond Model)")
        st.markdown(
            """
            ThreatFox aligns with the two most useful areas of the diamond model for banking
            fraud prevention: **Capability** and **Infrastructure**.

            - **Capability:** Links each IOC to a specific malware family (e.g., QakBot), giving
              analysts immediate insight into the threat's behavior — such as credential theft or
              session hijacking. A ThreatFox IOC tagged `win.qakbot` tells a fraud analyst
              immediately that the affected user is likely subject to credential theft.
            - **Infrastructure:** Tracks active C2 servers, enabling banks to block malicious
              communication channels before attacks escalate.
            """
        )

        st.subheader("Industry Usage")
        st.markdown(
            """
            **FS-ISAC Member Institutions:** ThreatFox is a default feed in MISP (Malware
            Information Sharing Platform). Any FS-ISAC member institution running MISP —
            which includes most major global banks — automatically has access to ThreatFox
            data as part of their MISP feed.
            """
        )
