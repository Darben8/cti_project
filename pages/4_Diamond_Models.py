"""Diamond model visualizations for two banking threat scenarios."""

import plotly.graph_objects as go
import streamlit as st


st.title("💎 Diamond Models (Banking Threat Scenarios)")
st.caption("Two complete, realistic Diamond Models aligned to banking threat trends.")


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


st.subheader("Model A: Phishing → Credential Theft → Account Takeover")
plot_diamond(
    "Diamond Model A",
    adversary="Organized cybercrime operators monetizing stolen banking credentials.",
    capability="Phishing kits, credential harvesting, infostealers, MFA bypass attempts (ATT&CK: T1566, T1110, T1556).",
    infrastructure="Type 1: fake bank domains, credential collection servers, VPN/proxy. Type 2: dark-web markets, coordination channels.",
    victim="Retail customers, SMB account holders, and bank employees. Assets: credentials, MFA tokens, accounts, credit lines.",
)

st.markdown(
    """
**Attack flow:**
1. Victim receives phishing email impersonating a bank.
2. Victim submits credentials on spoofed portal.
3. Adversary accesses legitimate banking session.
4. Fraudulent transfers/account abuse follows.
    """
)

st.divider()

st.subheader("Model B: Initial Access Exploit → Lateral Movement → Ransomware Extortion")
plot_diamond(
    "Diamond Model B",
    adversary="Ransomware-as-a-service affiliate or organized extortion group targeting financial institutions.",
    capability="Exploit kits for edge services, privilege escalation, lateral movement, exfiltration and encryption (ATT&CK: T1190, T1021, T1486).",
    infrastructure="Type 1: exploit delivery, C2 channels, payload staging. Type 2: leak sites and crypto wallets for extortion.",
    victim="Bank IT admins/SOC teams and enterprise users. Assets: core banking, payment systems, customer data, AD/IAM.",
)

st.markdown(
    """
**Attack flow:**
1. Adversary exploits vulnerable VPN/web service.
2. Establishes foothold and escalates privileges.
3. Moves laterally across internal systems.
4. Exfiltrates data and deploys ransomware for dual extortion.
    """
)
