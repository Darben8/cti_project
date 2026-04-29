
import pandas as pd
import streamlit as st

st.title("Operational Intelligence and Dissemination")
st.caption("Operational intelligence strategies based on active threat analysis.")

with st.expander("Threat Summary", expanded=True):
    st.markdown("**Active threats identified across four datasets:**")
    summary_df = pd.DataFrame(
        [
            {
                "Threat Actor / Campaign": "Akira Ransomware Group",
                "Severity": "Critical",
                "Status": "Active",
                "MITRE ATT&CK TTPs": "T1003.001, T1021.001, T1047, T1112, T1562.001, T1486",
            },
            {
                "Threat Actor / Campaign": "QakBot C2 Infrastructure",
                "Severity": "High",
                "Status": "Active (Feb–Mar 2026)",
                "MITRE ATT&CK TTPs": "T1071, T1055, T1547",
            },
            {
                "Threat Actor / Campaign": "Banking Phishing Cluster",
                "Severity": "High",
                "Status": "Active (30+ URLs)",
                "MITRE ATT&CK TTPs": "T1566, T1056",
            },
            {
                "Threat Actor / Campaign": "Ramnit Botnet (DGA)",
                "Severity": "Medium",
                "Status": "Active",
                "MITRE ATT&CK TTPs": "T1568, T1056",
            },
        ]
    )
    st.dataframe(summary_df, use_container_width=True, hide_index=True)

with st.expander("1. Who to Notify"):
    st.markdown("**Stakeholder Notification:**")
    stakeholder_df = pd.DataFrame(
        [
            {
                "Stakeholder": "CISO / Executive Leadership",
                "What They Receive": "Strategic risk posture, regulatory exposure, and ransomware targeting summary.",
                "When": "Within 2 hours of critical finding",
            },
            {
                "Stakeholder": "IR Team",
                "What They Receive": "Full IOC package: IPs, hashes, C2 domains, TTPs.",
                "When": "Immediate — parallel to CISO",
            },
            {
                "Stakeholder": "SOC / Detection Engineering",
                "What They Receive": "firewall block lists, and outbound monitoring thresholds for QakBot C2.",
                "When": "Within 4 hours",
            },
            {
                "Stakeholder": "IT / Network Operations",
                "What They Receive": "IP block lists for Akira/QakBot, port policy updates.",
                "When": "Same business day",
            },
            {
                "Stakeholder": "Staff (Security Awareness)",
                "What They Receive": "Phishing campaign warning with examples of active spoofed login portals.",
                "When": "Within 24 hours",
            },
            {
                "Stakeholder": "Clients (if brand impersonation confirmed)",
                "What They Receive": "Notification of active phishing sites impersonating the institution, with a report-a-phish link.",
                "When": "Within 48 hours",
            },
        ]
    )
    st.dataframe(stakeholder_df, use_container_width=True, hide_index=True)


with st.expander("When and What to Communicate"):
    st.markdown("**Communication timeline by urgency:**")
    comms_df = pd.DataFrame(
        [
            {
                "Timeframe": "Immediate",
                "Audience": "CISO + IR Lead",
                "Message": "Confirmed Akira campaign. Credential harvesting and lateral movement indicate active pre-ransomware stage. Provide financial addresses and file hashes.",
                "Type": "Critical escalation",
            },
            {
                "Timeframe": "4 hours",
                "Audience": "SOC",
                "Message": "Active QakBot C2 IPs: 102.158.228.15:443, 197.0.81.220:443, 41.62.43.21:443. Block outbound traffic.",
                "Type": "Operational intel",
            },
            {
                "Timeframe": "24 hours",
                "Audience": "Staff",
                "Message": "Active phishing campaign are being hosted. Domains mimic login portals (e.g., secure-bank-login-verify.com). Do not enter credentials on unexpected prompts.",
                "Type": "Awareness bulletin",
            },
            {
                "Timeframe": "48 hours",
                "Audience": "IT / SOC",
                "Message": "100+ Ramnit domains identified (e.g., wnlgghgffr.com). DGA-based credential theft modules targeting financial login portals. DNS blacklisting and proxy policy updates required.",
                "Type": "Monitoring advisory",
            },
        ]
    )
    st.dataframe(comms_df, use_container_width=True, hide_index=True)

with st.expander("How to Deliver Intelligence"):
    st.markdown("**Delivery method by audience and use case:**")
    delivery_df = pd.DataFrame(
        [
            {
                "Method": "TAXII",
                "Audience": "IR Team, SOC",
                "Purpose": "Packages threat information in a format that security systems can read and act on automatically, while also sharing that intelligence with other financial institutions via FS-ISAC.",
            },
            {
                "Method": "Threat Intelligence Dashboard",
                "Audience": "CISO, SOC",
                "Purpose": "Live campaign status, IOC hit counts, MITRE TTP heatmap, phishing takedown queue. Recieves updates during active campaigns.",
            },
            {
                "Method": "Finished Intelligence Reports (PDF/Slides)",
                "Audience": "CISO, Executives",
                "Purpose": "Narrative context, threat actor profiling, risk scoring, and strategic recommendations.",
            },
            {
                "Method": "Automated Alerts",
                "Audience": "Firewalls, EDR, Email Gateway",
                "Purpose": "Push IOC block lists directly to security controls.",
            },
            {
                "Method": "Encrypted Bulletins",
                "Audience": "Staff, Clients",
                "Purpose": "Plain-language advisories with specific action steps. Raw IOCs are not sent to general staff.",
            },
        ]
    )
    st.dataframe(delivery_df, use_container_width=True, hide_index=True)


with st.expander("Courses of Action and Implementation"):
    coa_data = {
        "1 — Block Akira and QakBot C2 Infrastructure (Immediate)": (
            "Block all identified C2 IPs across perimeter firewall and endpoint policy. "
            "Alert on any historical connection attempts — hits indicate existing compromise.\n\n"
            "**Why:** QakBot is the documented initial access vector for Akira. Severing C2 disrupts lateral movement commands before ransomware deployment."
        ),
        "2 — Credential Hardening and Lateral Movement Prevention (24–72 hrs)": (
            "Enforce MFA on all remote access. Rotate service account credentials. "
            "Disable remote execution except where required. Deploy honeytokens on file shares as early-warning tripwires.\n\n"
            "**Why:** Akira uses lateral movement, and remote execution as its pre-ransomware chain. Breaking any link limits impact."
        ),
        "3 — Phishing URL Takedown and URL Filtering (48 hrs)": (
            "Submit active phishing URLs through abuse@ channels and eCrime feeds. "
            "Push domains to secure web gateway block lists. Enable monitoring to detect new impersonation domains automatically.\n\n"
            "**Why:** Cloud hosting enables fast domain rotation — proactive takedown plus monitoring is the only sustainable countermeasure."
        ),
        "4 — Ramnit Domain DNS Blacklisting (48–72 hrs)": (
            "Ingest Ramnit domains into DNS sinkholes and proxy block lists. "
            "Deploy behavioral detection in SIEM: flag outbound DNS queries. "
            "Use passive DNS monitoring to detect new DGA cycles.\n\n"
            "**Why:** Static blocklists are insufficient against C2. Sinkholes redirect infected hosts to analyst-controlled IPs for identification."
        ),
        "5 — Ransomware Tabletop and Backup Validation (1–2 weeks)": (
            "Schedule an Akira-scenario tabletop exercise (T1486). Test restoration from immutable or air-gapped backup. "
            "Validate backup integrity — Akira exfiltrates data before encryption to increase extortion leverage. "
            "Confirm current RTO/RPO and review cyber insurance policy for double-extortion coverage.\n\n"
            "**Why:** Backup integrity is the final line of defense. Without it, payment becomes the only recovery path."
        ),
    }
    for coa_title, coa_detail in coa_data.items():
        st.markdown(f"**{coa_title}**")
        st.markdown(coa_detail)
        st.divider()


with st.expander("How This Informs the Next CTI Iteration"):
    iter_df = pd.DataFrame(
        [
            {
                "Area": "New Collection Requirement",
                "Action": "Task collection on Akira infrastructure: new C2 IPs and monitor underground forums for new affiliate recruitment.",
            },
            {
                "Area": "Gap Analysis",
                "Action": "Next cycle should enrich with incident timeline data to understand the access-to-ransomware window.",
            },
            {
                "Area": "Metric Tracking",
                "Action": "Track IOC block hit rate, phishing takedowns, and lateral movement detections.",
            },
            {
                "Area": "Feedback Loop",
                "Action": "Ingest alert outcomes back into the threat intel platform. Mark IOCs as confirmed-hit, false-positive, or expired. Update confidence scoring for QakBot and Ramnit indicators.",
            },
            {
                "Area": "Sharing Posture",
                "Action": "Submit Akira IOC package to FS-ISAC. Share anonymized TTPs via TAXII to receive enriched sector-wide intelligence in return.",
            },
        ]
    )
    st.dataframe(iter_df, use_container_width=True, hide_index=True)


with st.expander("Critical Asset Prioritization and Diamond Model Updates"):
    st.markdown("**Asset prioritization by threat exposure:**")
    asset_df = pd.DataFrame(
        [
            {
                "Priority": "Critical",
                "Asset": "Active Directory / IAM Infrastructure",
                "Recommended Action": "Immediate MFA enforcement and develope a tiered AD model.",
            },
            {
                "Priority": "Critical",
                "Asset": "Core Banking / Payment Systems",
                "Recommended Action": "Network segmentation and data classification review.",
            },
            {
                "Priority": "Critical",
                "Asset": "Customer-Facing Login Portals",
                "Recommended Action": "Anti-phishing campaigns, monitoring, anomalous login alerting.",
            },
            {
                "Priority": "High",
                "Asset": "Backup Infrastructure",
                "Recommended Action": "Immediate cloud backup, offline validation, encryption-at-rest audit.",
            },
        ]
    )
    st.dataframe(asset_df, use_container_width=True, hide_index=True)

    st.markdown("**Diamond model summaries by threat actor:**")
    diamond_data = {
        "Akira Ransomware Group": {
            "Adversary": "Sophisticated ransomware-as-a-service affiliate. Financial sector targeting confirmed.",
            "Capability": "ateral movement, exfiltration and encryption. New builds actively deployed.",
            "Infrastructure": "Bitcoin ransom wallets documented. C2 channels likely QakBot-delivered.",
            "Victim": "Financial organizations, weak credentials, and inadequate backup posture.",
        },
        "Banking Phishing Cluster": {
            "Adversary": "Multiple actors using common hosting TTPs. Possibly linked to QakBot delivery chain via malicious URLs.",
            "Capability": "Credential harvesting, brand impersonation, fake domain rotations on cloud platforms.",
            "Infrastructure": "30+ active URLs identified.",
            "Victim": "Retail banking customers and employees of impersonated institutions.",
        },
    }

    selected_actor = st.selectbox("Select threat actor to view diamond model:", list(diamond_data.keys()))
    model = diamond_data[selected_actor]
    diamond_df = pd.DataFrame(
        [{"Dimension": k, "Detail": v} for k, v in model.items()]
    )
    st.dataframe(diamond_df, use_container_width=True, hide_index=True)
