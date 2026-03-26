"""Critical assets page."""

import pandas as pd
import streamlit as st

st.title("Critical Assets")
st.caption("Priority banking assets, their business value, and the operational impact if they are compromised.")

st.info(
    "The banking sector depends on a small set of high-value systems and data stores that support transactions, access control, customer trust, and regulatory obligations."
)

st.subheader("Critical Asset Table")
assets = pd.read_csv("data/critical_assets.csv")
st.dataframe(assets, use_container_width=True, hide_index=True)

with st.expander("Critical Asset Justification"):
    st.markdown(
        """
- **Core banking systems:** Backbone for account operations, transaction integrity, and daily service delivery.
- **Payment processing systems and SWIFT/RTGS connectivity:** Directly tied to settlement, liquidity movement, and customer trust.
- **Identity and access management:** High-value control point that can enable privilege escalation and broad compromise if abused.
- **Online and mobile banking platforms:** Primary internet-facing attack surface for credential theft, fraud, and service disruption.
- **Customer data repositories:** Store regulated financial and personal data that can drive extortion, fraud, and compliance penalties.
- **Security operations tooling:** Essential for detection, containment, investigation, and evidence preservation during incidents.
- **Tokenized asset platforms:** Emerging banking infrastructure that can introduce custody, integrity, and transaction manipulation risk.
        """
    )
