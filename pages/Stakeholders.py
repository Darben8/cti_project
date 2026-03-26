import streamlit as st
st.title("Stakeholders, User Stories, and CTI Use Case")

col1, col2 = st.columns([1.2, 1], gap="large")

with col1:
    st.subheader("Stakeholders")
    st.markdown(
        """
- **Industry focus:** U.S. banking sector within the broader finance and insurance ecosystem.
- **Core services/products:** retail banking, commercial banking, digital payments, lending, wealth management, and treasury services.
- **Major industry players:** JPMorgan Chase, Bank of America, Citigroup, Wells Fargo, HSBC, MUFG, and Standard Chartered.
- **Why IT is mission-critical:** always-on online banking, real-time transaction processing, fraud detection pipelines, API-driven integrations, and regulatory reporting depend on secure digital infrastructure.
- **Risk concentration:** banking remains highly targeted due to access to capital, high-value identity data, internet-facing services, and transaction velocity.
        """
    )

    st.subheader("User Stories")
    st.markdown(
        """
**1) SOC Analyst - Jordan**
- View near-real-time threat trends targeting banking infrastructure.
- Filter and prioritize high-risk assets for monitoring.

**2) CISO - Alicia**
- Track executive KPIs (threat volume and exposure levels).
- Review adversary capabilities and attack paths for budget planning.

**3) Threat Intelligence Analyst - Rahul**
- Use adversary profiles and diamond models for leadership briefings.
- Detect patterns using category-filtered threat dashboards.
        """
    )

with col2:
    st.subheader("CTI Use Case")
    st.markdown(
        """
- Banking faces persistent pressure from credential abuse, phishing, ransomware, and web app attacks.
- A CTI-led approach reduces uncertainty by translating external threat data into action for controls, detection engineering, and prioritization.
- Intelligence-backed prioritization helps reduce breach likelihood and expected financial impact by focusing resources on the highest-probability, highest-impact scenarios.
- This supports measurable outcomes for both technical teams and executive stakeholders.
        """
    )
