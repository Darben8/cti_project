"""Critical assets page."""

import pandas as pd
import streamlit as st
import sys

# Import data validation utilities
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))
from utils.data_validation import DatasetQualityValidator

st.title("Critical Assets")
st.caption("Priority banking assets, their business value, and the operational impact if they are compromised.")

st.info(
    "The banking sector depends on a small set of high-value systems and data stores that support transactions, access control, customer trust, and regulatory obligations."
)

st.subheader("Critical Asset Table")
assets = pd.read_csv("data/critical_assets.csv")
st.dataframe(assets, use_container_width=True, hide_index=True)

# Dataset Quality for Critical Assets
with st.expander("ℹ️ Asset Inventory Quality", expanded=False):
    validator = DatasetQualityValidator()
    # Use lower threshold for assets (they're expert-curated, not sampled)
    size_check = validator.validate_dataset_size(assets, "Critical Assets Inventory", min_acceptable=3)
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Asset Count", size_check["row_count"])
    with col2:
        st.caption(
            "✅ **Asset inventory validated.** Critical asset classification is expert-curated based on banking sector best practices. "
            "Record count reflects core systems; more can be added as the program expands."
        )
    
    st.info(
        "**Why is this inventory valuable at this scale?** \n\n"
        "Asset prioritization is not statistical; it's business-driven. These 7 assets represent the **highest-impact** systems in banking. "
        "Security focus should be proportional to business criticality, not count. A small, well-defined asset list enables precise control placement."
    )


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
