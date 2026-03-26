import streamlit as st

st.info("The banking sector is one of the most targeted industries due to its high financial value and sensitive data.")
st.title("Threat Trends & Critical Assets")

st.header("Threat Trends in Banking")

st.subheader("Key Exploits Targeting the Industry")
st.markdown("""
- AI‑enabled fraud and financial crime increasing in sophistication
- Exploitation of fragmented or brittle data infrastructure.
- Attacks targeting digital banking channels, including mobile and online portals. services  
""")

st.subheader("Technologies Being Targeted")
st.markdown("""
- Tokenized asset infrastructure and on‑chain banking environments
- AI‑powered automation systems used in authentication and fraud detection
- Expansion of BaaS and embedded finance ecosystems introduces 3rd‑party risk  
""")

st.subheader("Specific Areas Being Targeted")
st.markdown("""
- Payment Systems (e.g., wire transfers, ACH)  
- Customer Databases (PII and financial records)  
- Authentication Systems (login portals, MFA systems)  
- Mobile banking apps and authentication layers   
""")

st.subheader("Threat Actors Targeting Banking")
st.markdown("""
- **FIN7**: Cybercriminal group known for targeting financial institutions  
- **Lazarus Group**: State-sponsored group linked to financial cyberattacks  
- **Cybercriminal Syndicates**: Organized groups conducting fraud and ransomware  
""")

st.header("Critical Assets in Banking")

assets = [
    ("Core Banking System", "Processes all financial transactions", "System failure and financial disruption", "Bank employees"),
    ("Customer Data", "Stores personal and financial information", "Identity theft and fraud", "Customers"),
    ("Payment Systems", "Handles money transfers", "Financial loss and fraud", "Banks and customers"),
    ("ATM Network", "Provides access to cash", "Service outages and fraud", "Public users"),
    ("Online Banking Platform", "Allows customers to access accounts", "Account takeover and data breaches", "Customers")
]

for name, value, impact, users in assets:
    st.subheader(name)
    st.write(f"Value: {value}")
    st.write(f"Impact if breached: {impact}")
    st.write(f"Users: {users}")

