import streamlit as st

st.title("🔭 Future CTI Platform Directions")
st.markdown("Three realistic next steps to make this platform more powerful and actionable.")

st.divider()

with st.container():
    st.markdown("### Automatic Indicator Enrichment")
    st.markdown(
        """
        Automatically look up flagged URLs and IPs across multiple threat databases
        (like VirusTotal and Shodan) so analysts get richer context without having
        to search manually.
        """
    )
    st.info("**Builds on:** Existing PhishTank & ThreatFox API integrations")

st.divider()

with st.container():
    st.markdown("### Transaction Data Integration")
    st.markdown(
        """
        Connect the platform to bank transaction feeds so threat indicators can be
        matched against real account activity, helping catch fraud faster and earlier.
        """
    )
    st.info("**Builds on:** Current fraud prevention use case and IOC monitoring")

st.divider()

with st.container():
    st.markdown("### Personalized Alerts by Role")
    st.markdown(
        """
        Automatically send the right information to the right person (detailed threat
        data for analysts, high-level summaries for executives, etc) so everyone gets what
        they need without digging through the full dashboard.
        """
    )
    st.info("**Builds on:** Existing stakeholder views")

st.divider()

st.caption("These directions are grounded in the platform's current capabilities and are scoped for realistic future development.")