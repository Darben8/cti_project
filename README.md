# CTI Project: U.S. Banking Threat Intelligence Platform

This repository contains the final Milestone 4 version of a multipage Streamlit cyber threat intelligence platform focused on the U.S. banking sector. The app combines phishing, malware, ransomware, infrastructure, and asset-prioritization data into one workflow that supports both analyst investigation and leadership-facing communication.

## Final App Scope

The platform is designed primarily for tactical and operational CTI use in a banking context. It focuses on turning open-source threat data into usable security outputs for triage, dissemination, prioritization, and future platform planning.

The current app supports:
- Banking-focused phishing intelligence from PhishTank-derived datasets
- Malware and IOC enrichment from ThreatFox
- Ransomware victim and group IOC context from ransomware.live-derived datasets
- Shodan exposure summaries for internet-facing banking infrastructure
- Critical asset alignment for banking-relevant systems
- Interactive triage and export workflows
- Role-based views for executive and analyst audiences
- Actionable outputs in CSV, JSON, and STIX-like formats
- Analytics workflows for phishing URL text mining, ransomware event correlation, and K-means clustering

## Milestone Coverage

### Milestone 1
- Banking-sector scoping and U.S. geographic focus
- Threat trends and adversary framing
- Critical asset identification
- Diamond Model content and sector context

### Milestone 2
- Streamlit dashboard expansion
- Data source identification and collection framing
- PhishTank and ThreatFox integration
- Local data explorer and supporting CTI context

### Milestone 3
- Analytical methods page
- Phishing URL text mining outputs
- Ransomware event correlation outputs
- K-means clustering support
- Validation and limitations content
- Expanded dashboard metrics and filtering

### Milestone 4
- Visible milestone-change checklist on the Home page
- Key intelligence findings with implications
- Operational intelligence and dissemination guidance
- Role-based views for executive and analyst audiences
- Operational triage queue with filtering and export
- Actionable outputs with course-of-action mapping
- Future CTI platform direction content

## App Structure

The app is launched from `app.py`, which defines the navigation and global Streamlit page configuration.

### Main entry point
- `app.py`
  - Configures the app in wide layout and routes users to each page

### Pages currently used by the app
- `pages/0_Home.py`
  - Landing page with project overview and milestone-by-milestone checklist

- `pages/1_Overview.py`
  - Banking-industry background, threat trends, intelligence buy-in, critical assets, and Diamond Model content

- `pages/2_Dashboard.py`
  - Main operational dashboard with source filtering, analyst metrics, asset alignment, Shodan summary, ethics/security notes, and a triage queue export workflow

- `pages/3_Data_Sources.py`
  - Source identification, source value, and collection summary content for PhishTank and ThreatFox

- `pages/4_Key_insights.py`
  - Intelligence summary page highlighting key findings such as ransomware activity, phishing clustering, botnet behavior, and command-and-control infrastructure patterns

- `pages/5_Operational_Intelligence_and_Dissemination.py`
  - Stakeholder-focused dissemination strategy, notification timing, reporting approach, asset prioritization, and diamond-model updates

- `pages/6_Analytics.py`
  - Main analytical approaches page with executive summary, analyst drill-down, approach justification, and future CTI directions

- `pages/8_Actionable_Outputs.py`
  - Export-focused page for course-of-action mapping and delivery of indicators in CSV, JSON, and STIX-like formats

- `pages/9_Team.py`
  - Team contributions and milestone-role summary

- `pages/10_References.py`
  - Project references and supporting sources

## Data Files

### Core local datasets used by the app
- `data/phishtank.csv`
  - Local phishing IOC dataset used in the dashboard and supporting workflows

- `data/verified_online_banking_finance.csv`
  - Banking/finance subset extracted from `verified_online.csv`

- `data/filtered_iocs_threatfox.csv`
  - ThreatFox-derived IOC dataset used across dashboard, analytics, and key insight workflows

- `data/finance_group_iocs.csv`
  - Ransomware-group IOC dataset used for operational and analytical CTI content

- `data/finance_victims.csv`
  - Ransomware victim dataset used for victim and industry targeting context

- `data/critical_assets.csv`
  - Banking-relevant critical asset alignment table

- `data/all_iocs.csv`
  - Combined strict IOC feed generated from multiple local sources

### Supporting local data files
- `data/combined_iocs.csv`
  - Legacy or smaller merged IOC sample retained for comparison/export workflows

- `data/processed_port_iocs.csv`
  - Processed IOC subset used for the port/network visualization on the Key Insights page

- `data/threat_events.csv`
  - Threat-event summary data used for the MITRE technique frequency visualization

- `data/verified_online.csv`
  - Larger phishing source file used to derive the banking/finance subset

- `data/verified_online.gz`
  - Compressed copy of the verified online source data

- `data/finance_failed_ioc_groups.csv`
  - Support file from ransomware retrieval/group processing

### Generated analytics output folders
- `data/phishing_url_text_mining/`
  - URL features, keyword summaries, TF-IDF outputs, n-grams, TLD summaries, and evaluation metrics

- `data/ransomware_event_correlation/`
  - Group-risk summaries, overlap summaries, family matches, network nodes/edges, and related metrics

- `data/kmeans_validation/`
  - Cluster metrics, clustered IOC output, and K-means validation plots

## Utilities and Supporting Scripts

### Analytics and data-processing utilities
- `utilities/phishing_url_text_mining.py`
  - Builds phishing URL text-mining outputs from banking phishing data

- `utilities/ransomware_event_correlation.py`
  - Produces cross-source ransomware correlation outputs and network-analysis files

- `utilities/kmeans2.py`
  - Current K-means workflow used to generate saved validation outputs in `data/kmeans_validation/`

- `utilities/kmeans.py`
  - Earlier K-means workflow retained in the repository

- `utilities/retrieve_ransomware_data.py`
  - Support script for collecting and preparing ransomware-focused data

- `utilities/extract_banking_verified_online.py`
  - Extracts the banking/finance phishing subset from `verified_online.csv`

- `utilities/actionable_outputs.py`
  - Shared helper module for course-of-action mapping, structured exports, STIX-like output, and intelligence report generation

### Data-preparation helpers
- `data/combine.py`
  - Combines multiple source exports into `data/all_iocs.csv`

- `data/data_collection.py`
  - Collection helper for selected source exports and API-backed summaries

## Data Sources

The project uses or references the following external sources:
- PhishTank
- ThreatFox
- ransomware.live
- Shodan
- MITRE ATT&CK
- Industry background and banking-sector reference material listed on the References page

## Environment Variables

Some app features rely on optional API-backed data retrieval. If you want those features available, create a `.env` file in the project root with:

```env
SHODAN_API_KEY=your_key_here
THREATFOX_API_KEY=your_key_here
```

Notes:
- The app can still run using the included local CSV files if you do not provide API keys.
- API-backed collection scripts use `python-dotenv` to load the `.env` file.

## How to Run

### Requirements
- Python 3.11 or newer recommended
- `pip`
- Internet access if you plan to use API-backed or external-source refresh features

### Windows PowerShell

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

### Conda environment

```bash
conda create -n cti-platform python=3.11 -y
conda activate cti-platform
pip install -r requirements.txt
streamlit run app.py
```

### Docker

```bash
docker build -t banking-cti-app .
docker run --rm -p 8501:8501 --env-file .env banking-cti-app
```

After launch, Streamlit will typically expose the app at:

- `http://localhost:8501`

## Recommended Run Order

For most users, the easiest path is:
1. Install dependencies
2. Add optional API keys to `.env` if needed
3. Run `streamlit run app.py`
4. Open the Home page first for milestone coverage and project orientation
5. Review Dashboard, Analytics, Operational Intelligence, and Actionable Outputs for the core Milestone 4 experience

## User Guide

### Best pages to start with
- `Home`
  - Quick overview of what changed by milestone

- `Dashboard`
  - Operational overview, source filters, triage queue, and exportable alert view

- `Key Insights & Intelligence Summary`
  - Fast summary of major findings from the data

- `Operational Intelligence & Dissemination`
  - Stakeholder communication, reporting, and course-of-action framing

- `Analytical Approaches`
  - Executive and analyst role-based exploration of the analytics

- `Actionable Outputs`
  - Export indicators and course-of-action recommendations in multiple formats

### Key Milestone 4 features
- Triage queue filtering by severity, asset, category, and status
- CSV/JSON export support for operational views
- Course-of-action mapping for indicators
- STIX-like export generation
- Executive-summary and analyst-drill-down communication paths

## Notes

- The repository now reflects the final Milestone 4 app state rather than the earlier milestone-only layout.
- Most core demonstrations can be run from included local data files.
- Some supporting scripts are intended for preprocessing or regeneration of saved outputs rather than daily app use.
- The app is designed to stand alone as a final course deliverable with operational CTI framing, not just exploratory visuals.
