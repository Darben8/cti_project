import streamlit as st

st.title("Intelligence Buy-In")

st.info("This section demonstrates the business value of adopting a Cyber Threat Intelligence (CTI) platform in the banking sector.")

# =========================
# CURRENT THREAT LANDSCAPE
# =========================

st.header("Current Threat Landscape")

st.write("""
The banking sector is undergoing rapid digital transformation, driven by AI adoption,
hybrid cloud environments, and data modernization. While these innovations improve efficiency,
they also introduce significant cybersecurity risks.

Cybersecurity has remained the top concern for executives for three consecutive years,
as financial institutions face increasing threats from sophisticated cyber adversaries.
""")

st.markdown("""
- Cybercriminals are leveraging **AI to automate phishing, deepfakes, and attack development**, reducing attack launch time from hours to minutes  
- Organizations are rapidly adopting AI without proper governance, creating vulnerabilities such as **“shadow AI”**  
- Financial institutions remain **high-value targets** due to sensitive financial and personal data  
""")

st.markdown("""
**Key Statistics:**
- 13% of organizations have experienced attacks targeting AI systems  
- 97% of AI-related breaches occurred in environments without proper access controls  
""")

st.divider()

# =========================
# BREACH FREQUENCY
# =========================

st.header("Frequency of Security Breaches")

st.write("""
Cyber incidents are no longer rare events but expected occurrences within the banking industry.
""")

st.metric("Banks Experiencing Incidents (Past Year)", "81%")

st.write("""
A majority of financial institutions report at least one cybersecurity incident annually,
highlighting the persistent and evolving threat landscape.
""")

st.divider()

# =========================
# IMPACT ON STRATEGY
# =========================

st.header("Impact on Organizational Strategy")

st.write("""
Modern banking technologies require a shift from reactive security to intelligence-driven security.
""")

st.markdown("""
- Adoption of **AI, hybrid cloud, and data modernization** increases attack surfaces  
- **Fragmented datasets and legacy systems** create visibility gaps  
- Organizations must adopt **CTI-driven strategies** to proactively identify and mitigate threats  
""")

st.divider()

# =========================
# COST OF DATA BREACHES
# =========================

st.header("Cost of Data Breaches")

col1, col2 = st.columns(2)

with col1:
    st.metric("Global Average Cost", "$4.44M")

with col2:
    st.metric("U.S. Average Cost", "$10.22M")

st.markdown("""
**Additional Cost Drivers:**
- Shadow AI contributes approximately **$670,000** per breach  

**Total costs include:**
- Incident response and recovery  
- Legal and regulatory fines  
- Operational downtime  
- Reputational damage  
""")

st.divider()

# =========================
# VALUE OF CTI
# =========================

st.header("Value of Intelligence-Based Security")

st.write("""
Cyber Threat Intelligence (CTI) enables organizations to shift from reactive to proactive security,
providing measurable business value.
""")

st.markdown("""
- **Reduces fraud** by identifying adversary tools and techniques early  
- **Improves ROI** of cybersecurity investments  
- **Enhances resilience** against evolving cyber threats  
- **Reduces regulatory exposure** and compliance risks  
- **Builds customer trust** during digital transformation initiatives  
""")

st.success("Implementing a CTI platform allows financial institutions to proactively defend against threats, reduce financial losses, and support strategic decision-making.")