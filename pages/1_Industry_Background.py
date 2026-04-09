import streamlit as st


st.title("Banking Industry Overview & Stakeholder Analysis")


tab1, tab2 = st.tabs(["Key Industry Characteristics", "Stakeholder Analysis"])

with tab1:
        st.header("Key Services and Products")
        st.write("""
        The banking industry provides essential financial services including:
        - Retail banking (checking and savings accounts)
        - Commercial banking (business loans and credit)
        - Investment services (wealth management, trading)
        - Digital banking (mobile and online platforms)
        """)

        st.header("Industry Size and Growth")
        st.write("""
        The global banking industry manages trillions of dollars in assets and serves billions of customers worldwide.
        - Millions of transactions occur daily
        - Rapid growth in mobile and online banking
        - Increasing reliance on cloud infrastructure
        """)

        st.header("Major Industry Players")
        st.write("""
        Some of the largest banking institutions in the U.S. include:
        - JPMorgan Chase
        - Citi Group 
        - HSBC
        - Goldman Sachs 
        - Bank of America
        - Wells Fargo
        - MUFG
        """)

        st.header("Importance of Information Technology")
        st.write("""
        Information technology is critical to banking operations:
        - Enables real-time transaction processing
        - Supports fraud detection systems
        - Powers mobile and online banking platforms
        - Secures sensitive financial data
        - Facilitates regulatory compliance and reporting
        - Supports internet-facing infrastructure
        """)

        st.header("Risk Concentration in Banking")
        st.write("""
        The banking sector is a prime target for cyber threats due to:
                - Access to capital
                - High-value identity data
                - Internet-facing services
                - Transaction velocity
        """)


with tab2:
        st.header("Stakeholder Overview")
        col1, col2 = st.columns([1.2, 1], gap="large")

        with col1:
                st.subheader("Stakeholder Overview")
                st.markdown(
                        """
                The banking-sector CTI platform serves multiple stakeholders across technical, operational, and executive levels, each with distinct objectives but a shared goal of reducing cyber risk and financial loss.

                Security Operations Center (SOC) Analysts are responsible for monitoring and responding to security threats in real time. They rely on the platform to identify malicious indicators, detect active threats, and accelerate incident response.

                Fraud Analysts focus on preventing financial fraud such as account takeover and card misuse. They use threat intelligence to detect compromised credentials, monitor suspicious activity, and proactively mitigate fraud before transactions occur.

                Threat Intelligence Analysts analyze adversary behavior, emerging threats, and attack patterns. The platform supports their work by providing structured intelligence, such as diamond models and trend analysis, to better understand attacker tactics and improve detection strategies.

                Chief Information Security Officers (CISOs) and Security Leadership use the platform for strategic decision-making. They require high-level insights, risk metrics, and threat trends to prioritize investments, align security initiatives with business risk, and strengthen overall cybersecurity posture.

                Together, these stakeholders ensure that threat intelligence is translated into actionable, organization-wide security improvements, bridging the gap between technical detection and strategic risk management
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
                st.subheader("CTI Use Case - Fraud Prevention and Detection")
                st.markdown(
                        """
                Many fraud tools only let users know that their card has been used for fraudulent activity. They do not take the steps beforehand to prevent the fraud. 
                There is also a gap in time from when card information is compromised to when the actual fraud occurs. Threat actors can steal card information, 
                store it, put it on the dark web and use it even months later making prevention harder.
                At the same time, banks face increasingly sophisticated threats, including AI-enabled fraud and attacks targeting digital banking channels, which continue
                to rank among top executive concerns.

                - Banking faces persistent pressure from credential abuse, phishing, ransomware, and web app attacks.
                - A CTI-led approach reduces uncertainty by translating external threat data into action for controls, detection engineering, and prioritization.
                - Intelligence-backed prioritization helps reduce breach likelihood and expected financial impact by focusing resources on the highest-probability, highest-impact scenarios.
                - This supports measurable outcomes for both technical teams and executive stakeholders.
                        """
                )
                st.subheader("Decisions Enabled by CTI")
                st.markdown(
                        """
                CTI platforms like Recorded future enable proactive, intelligence-driven decision making rather than recative fraud response.
                They also support:
                -Identification of critical assets and associated threats 
                -Prioritization of risks based on attacker behavior 
                -Detection of emerging fraud campaigns (e.g., carding, checker services, merchant compromise)
                -Increased visibility into adversary capabilities (via diamond models) 
                -Data‑driven cybersecurity investment decisions 

                        """
                )
                st.subheader("Data and Analytics Used")
                st.markdown(
                        """
                1. Dark web and criminal marketplace data
                2. Threat Intelligence feeds (Recorded Future, PhishTank, ransomware.live, Shodan, DBIR)
                3. Transaction & behavioral analytics (internal fraud monitoring systems)
                
                        """
                )