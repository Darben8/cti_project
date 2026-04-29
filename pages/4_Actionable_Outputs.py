"""
Milestone 4: Actionable Outputs Dashboard

Provides interactive export of threat intelligence data with course-of-action recommendations
in multiple formats (CSV, JSON, STIX).
"""

import streamlit as st
import pandas as pd
import json
from pathlib import Path
from datetime import datetime

# Import the actionable outputs module
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "utilities"))
from actionable_outputs import (
    ActionableOutputExporter,
    CourseOfActionMapper,
    COURSE_OF_ACTIONS,
)

st.set_page_config(
    page_title="Actionable Outputs & COA Mapping",
    page_icon="📤",
    layout="wide",
)

st.title("📤 Milestone 4: Actionable Outputs & Course-of-Action Mapping")
st.markdown("""
**Objective**: Transform threat intelligence data into actionable outputs with structured 
recommendations through multiple export formats (CSV, JSON, STIX).
""")

# Load data
@st.cache_data
def load_ioc_data():
    """Load IOC data from CSV files."""
    data_dir = Path(__file__).parent.parent / "data"
    dfs = {}
    
    if (data_dir / "combined_iocs.csv").exists():
        dfs["Combined IOCs"] = pd.read_csv(data_dir / "combined_iocs.csv")
    
    if (data_dir / "finance_group_iocs.csv").exists():
        dfs["Finance Group IOCs"] = pd.read_csv(data_dir / "finance_group_iocs.csv")
    
    if (data_dir / "filtered_iocs_threatfox.csv").exists():
        dfs["ThreatFox IOCs"] = pd.read_csv(data_dir / "filtered_iocs_threatfox.csv")
    
    return dfs

try:
    ioc_datasets = load_ioc_data()
    if not ioc_datasets:
        st.error("❌ No IOC data files found. Please ensure CSV files are in the data/ folder.")
        st.stop()
except Exception as e:
    st.error(f"❌ Error loading data: {e}")
    st.stop()

# Sidebar: Data Selection
st.sidebar.header("📊 Data Selection")
selected_dataset = st.sidebar.selectbox(
    "Select IOC Dataset",
    options=list(ioc_datasets.keys()),
    help="Choose which dataset to export and generate COAs for"
)

df = ioc_datasets[selected_dataset]
st.sidebar.metric("Total Indicators", len(df))

# Main tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "📋 Overview & COA Mapping",
    "📤 Export Formats",
    "📊 Intelligence Report",
    "ℹ️ About COAs"
])

# ============================================================================
# TAB 1: Overview & COA Mapping
# ============================================================================
with tab1:
    st.subheader("Threat Summary & Course-of-Action Mapping")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric("Dataset", selected_dataset)
        st.metric("Total Indicators", len(df))
    
    with col2:
        if "type" in df.columns:
            st.metric("Indicator Types", df["type"].nunique())
        if "tags" in df.columns:
            st.metric("Threat Categories", df["tags"].nunique())
    
    st.markdown("---")
    
    # Categorize threats
    coa_mapper = CourseOfActionMapper()
    threat_categories = []
    severities = []
    
    for _, row in df.iterrows():
        threat_type = row.get("type", "")
        category = row.get("ioc type", "")
        tags = row.get("tags", "")
        
        coa = coa_mapper.get_coa(threat_type, category, tags)
        threat_categories.append(coa["category"])
        severities.append(coa["severity"])
    
    df_with_coa = df.copy()
    df_with_coa["threat_category"] = threat_categories
    df_with_coa["severity"] = severities
    
    # Display threat summary
    threat_counts = df_with_coa["threat_category"].value_counts()
    severity_counts = df_with_coa["severity"].value_counts()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Threat Categories")
        for category, count in threat_counts.items():
            st.info(f"**{category.upper()}**: {count} indicators")
    
    with col2:
        st.markdown("### Severity Distribution")
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for severity in sorted(severity_counts.index, key=lambda x: severity_order.get(x, 999)):
            count = severity_counts[severity]
            color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
            st.info(f"{color} **{severity}**: {count} indicators")
    
    st.markdown("---")
    
    # Show sample COAs for each category
    st.markdown("### Sample Course-of-Action Recommendations")
    
    unique_categories = df_with_coa["threat_category"].unique()
    
    for category in sorted(unique_categories):
        with st.expander(f"📋 {category.upper()} - Recommended Actions"):
            sample_rows = df_with_coa[df_with_coa["threat_category"] == category].head(1)
            
            if not sample_rows.empty:
                sample = sample_rows.iloc[0]
                coa = coa_mapper.get_coa(
                    sample.get("type", ""),
                    sample.get("ioc type", ""),
                    sample.get("tags", "")
                )
                
                st.markdown(f"**Severity**: {coa['severity']}")
                st.markdown(f"**TTL (Days)**: {coa['ttl_days']}")
                st.markdown("**Recommended Actions**:")
                for i, action in enumerate(coa["recommended_actions"], 1):
                    st.markdown(f"{i}. {action}")
    
    st.markdown("---")
    
    # Show sample indicators with COA
    st.markdown("### Sample Indicators with COA Recommendations")
    
    display_cols = ["indicator", "type", "threat_category", "severity", "source", "tags"]
    available_cols = [col for col in display_cols if col in df_with_coa.columns]
    
    st.dataframe(
        df_with_coa[available_cols].head(10),
        use_container_width=True,
        height=400
    )

# ============================================================================
# TAB 2: Export Formats
# ============================================================================
with tab2:
    st.subheader("Export Threat Intelligence Data")
    
    st.markdown("""
    Choose your preferred export format for threat intelligence integration:
    - **CSV**: For import into security tools, spreadsheets, and EDR/SIEM systems
    - **JSON**: For API integration and automated workflows
    - **STIX 2.1**: Standardized format for threat intelligence sharing
    """)
    
    st.markdown("---")
    
    # Export options
    include_coa = st.checkbox(
        "✅ Include Course-of-Action Recommendations",
        value=True,
        help="Add severity, TTL, and recommended actions to exports"
    )
    
    st.markdown("---")
    
    col1, col2, col3 = st.columns(3)
    
    # CSV Export
    with col1:
        st.markdown("### 📄 CSV Format")
        st.markdown("""
        **Best for:**
        - Spreadsheet analysis
        - SIEM ingestion
        - Email distribution
        - Archival
        
        **Includes:**
        - All indicator fields
        - Threat categorization
        - COA recommendations (optional)
        """)
        
        if st.button("🔽 Export to CSV", key="csv_export", use_container_width=True):
            with st.spinner("Generating CSV..."):
                try:
                    export_df, csv_path = ActionableOutputExporter.export_to_csv(
                        df_with_coa,
                        include_coa=include_coa
                    )
                    
                    csv_data = export_df.to_csv(index=False)
                    st.download_button(
                        label="⬇️ Download CSV",
                        data=csv_data,
                        file_name=f"cti_indicators_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
                    st.success(f"✅ CSV ready! ({len(export_df)} rows)")
                except Exception as e:
                    st.error(f"❌ Error: {e}")
    
    # JSON Export
    with col2:
        st.markdown("### 📋 JSON Format")
        st.markdown("""
        **Best for:**
        - API integration
        - Automated processing
        - Integration with SOAR/playbooks
        - Data transformation pipelines
        
        **Includes:**
        - Structured metadata
        - COA recommendations (optional)
        - Standards-compliant format
        """)
        
        if st.button("🔽 Export to JSON", key="json_export", use_container_width=True):
            with st.spinner("Generating JSON..."):
                try:
                    json_data, json_path = ActionableOutputExporter.export_to_json(
                        df_with_coa,
                        include_coa=include_coa,
                        include_stix=False
                    )
                    
                    json_str = json.dumps(json_data, indent=2, default=str)
                    st.download_button(
                        label="⬇️ Download JSON",
                        data=json_str,
                        file_name=f"cti_indicators_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                        use_container_width=True
                    )
                    st.success(f"✅ JSON ready! ({json_data['metadata']['indicator_count']} indicators)")
                except Exception as e:
                    st.error(f"❌ Error: {e}")
    
    # STIX Export
    with col3:
        st.markdown("### 🔐 STIX 2.1 Format")
        st.markdown("""
        **Best for:**
        - Standards-based sharing
        - TIP (Threat Intelligence Platform) import
        - Information exchange
        - Interoperability
        
        **Includes:**
        - STIX 2.1 compliant objects
        - Campaign/malware relationships
        - Standardized indicators
        """)
        
        if st.button("🔽 Export to STIX", key="stix_export", use_container_width=True):
            with st.spinner("Generating STIX Bundle..."):
                try:
                    stix_bundle, stix_path = ActionableOutputExporter.export_to_stix(df_with_coa)
                    
                    stix_str = json.dumps(stix_bundle, indent=2, default=str)
                    st.download_button(
                        label="⬇️ Download STIX",
                        data=stix_str,
                        file_name=f"stix_bundle_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                        use_container_width=True
                    )
                    st.success(f"✅ STIX bundle ready! ({len(stix_bundle['objects'])} objects)")
                except Exception as e:
                    st.error(f"❌ Error: {e}")
    
    st.markdown("---")
    
    # Export with STIX Bundle
    st.markdown("### 🚀 Advanced: JSON with Embedded STIX")
    
    if st.button("🔽 Export JSON with STIX Bundle", use_container_width=True):
        with st.spinner("Generating JSON with STIX..."):
            try:
                json_data, json_path = ActionableOutputExporter.export_to_json(
                    df_with_coa,
                    include_coa=include_coa,
                    include_stix=True
                )
                
                json_str = json.dumps(json_data, indent=2, default=str)
                st.download_button(
                    label="⬇️ Download JSON + STIX",
                    data=json_str,
                    file_name=f"cti_complete_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    use_container_width=True
                )
                st.success("✅ Complete export ready!")
            except Exception as e:
                st.error(f"❌ Error: {e}")

# ============================================================================
# TAB 3: Intelligence Report
# ============================================================================
with tab3:
    st.subheader("📊 Comprehensive Intelligence Report")
    
    if st.button("📋 Generate Report", use_container_width=True):
        with st.spinner("Generating intelligence report..."):
            try:
                report, report_path = ActionableOutputExporter.generate_intelligence_report(df_with_coa)
                
                # Display report summary
                st.markdown("### 📈 Report Summary")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Indicators", report["report_metadata"]["total_indicators"])
                with col2:
                    st.metric("Report Generated", report["report_metadata"]["generated_at"][:10])
                with col3:
                    st.metric("Organization", report["report_metadata"]["organization"])
                
                st.markdown("---")
                
                # Severity Distribution
                st.markdown("### Severity Distribution")
                severity_data = report["severity_distribution"]
                severity_cols = st.columns(4)
                severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                
                for idx, (severity, count) in enumerate(sorted(severity_data.items(), key=lambda x: severity_order.get(x[0], 999))):
                    with severity_cols[idx]:
                        color_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
                        st.metric(f"{color_emoji} {severity}", count)
                
                st.markdown("---")
                
                # Threat Summary
                st.markdown("### Threat Categories & Indicators")
                threat_summary = report["threat_summary"]
                
                for threat_cat, details in threat_summary.items():
                    with st.expander(f"🎯 {threat_cat.upper()} ({details['count']} indicators)"):
                        st.markdown(f"**Severity**: {details['severity']}")
                        st.markdown(f"**Count**: {details['count']}")
                        
                        # Show sample indicators
                        if details["indicators"]:
                            indicator_df = pd.DataFrame(details["indicators"][:10])
                            st.dataframe(indicator_df, use_container_width=True)
                
                st.markdown("---")
                
                # COA Recommendations
                st.markdown("### Recommended Course-of-Action by Category")
                
                coa_recs = report["course_of_action_recommendations"]
                
                for category, coa_details in coa_recs.items():
                    with st.expander(f"📋 {category.upper()} - {coa_details['severity']} Severity"):
                        st.markdown(f"**Time-to-Live**: {coa_details['ttl_days']} days")
                        st.markdown(f"**Number of Actions**: {len(coa_details['actions'])}")
                        st.markdown("**Recommended Actions**:")
                        for i, action in enumerate(coa_details["actions"], 1):
                            st.markdown(f"{i}. {action}")
                
                st.markdown("---")
                
                # Download report
                report_json = json.dumps(report, indent=2, default=str)
                st.download_button(
                    label="📥 Download Full Report",
                    data=report_json,
                    file_name=f"intelligence_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    use_container_width=True
                )
                
                st.success("✅ Report generated successfully!")
                
            except Exception as e:
                st.error(f"❌ Error generating report: {e}")

# ============================================================================
# TAB 4: About COAs
# ============================================================================
with tab4:
    st.subheader("ℹ️ About Course-of-Action Mapping")
    
    st.markdown("""
    ## What is Course-of-Action (COA) Mapping?
    
    Course-of-Action mapping links threat intelligence indicators to specific, actionable 
    recommendations that security teams can implement immediately.
    
    ### Key Features:
    
    **1. Threat Categorization**
    - Automatically categorizes indicators based on type and tags
    - Maps to specific threat categories (phishing, malware, ransomware, etc.)
    
    **2. Severity Assessment**
    - CRITICAL: Immediate action required (ransomware, credential theft)
    - HIGH: Urgent investigation needed (malware, phishing)
    - MEDIUM: Monitor and investigate (suspicious infrastructure)
    
    **3. Time-to-Live (TTL)**
    - Recommended duration indicator remains actionable
    - Ranges from 30 days (phishing) to 90 days (ransomware)
    
    **4. Specific Recommendations**
    Each threat category includes tailored actions:
    """)
    
    # Display COA database
    st.markdown("### COA Database")
    
    for threat_type, coa_info in COURSE_OF_ACTIONS.items():
        with st.expander(f"🎯 {threat_type.upper()} - {coa_info['severity']} Severity"):
            st.markdown(f"**TTL**: {coa_info['ttl_days']} days")
            st.markdown("**Recommended Actions**:")
            for i, action in enumerate(coa_info["actions"], 1):
                st.markdown(f"{i}. {action}")
    
    st.markdown("---")
    
    st.markdown("""
    ### Implementation Guide
    
    **Step 1: Export Data**
    - Choose your preferred format (CSV, JSON, STIX)
    - Include COA recommendations
    
    **Step 2: Distribute**
    - Share with relevant security teams
    - Integrate with SOAR/automation platforms
    - Import into SIEM/TIP systems
    
    **Step 3: Execute**
    - Implement recommended actions
    - Document execution and outcomes
    - Adjust based on results
    
    **Step 4: Track & Improve**
    - Monitor effectiveness
    - Update TTL as needed
    - Refine COA database
    
    ### Integration Examples
    
    **SIEM/EDR**: Import CSV for automated alerting and blocking
    **SOAR**: Use JSON with COAs to trigger automated playbooks
    **TIP**: Import STIX bundle for centralized threat intelligence
    **Email**: Distribute reports to stakeholders via JSON/CSV
    """)
    
    st.info("""
    💡 **Pro Tip**: Combine multiple export formats for different audiences:
    - Technical teams → JSON (for integration)
    - Security analysts → CSV (for analysis)
    - Enterprise TIP systems → STIX (for sharing)
    """)
