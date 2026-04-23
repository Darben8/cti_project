# CTI Project: U.S. Banking Threat Intelligence Platform

This repository contains a multipage Streamlit application for cyber threat intelligence focused on the U.S. banking sector. The current project state reflects Milestone 3, which extends earlier dashboard and data-explorer work with analytical methods, validation content, and operational CTI framing.

## Current Scope

The app is designed primarily for tactical CTI and secondarily for operational CTI.

It combines:
- Banking-focused phishing intelligence from PhishTank-derived datasets
- ThreatFox local and live IOC records
- ransomware.live victim data
- Shodan exposure summaries
- Critical asset alignment for banking-relevant systems
- Analytical workflows for phishing URL text mining, ransomware event correlation, and K-means clustering

## Milestone Coverage

### Milestone 1
- Industry background and banking-sector scope
- Threat trends and critical assets
- Diamond Model content
- Initial dashboard framing

### Milestone 2
- Dynamic data explorer
- Data source identification and justification
- Collection strategy and source summary
- Expanded dashboard views
- API-backed and local CTI source integration

### Milestone 3
- Interactive analytical approaches page
- Phishing URL text mining outputs
- Ransomware event correlation outputs
- K-means clustering support
- Preliminary visualizations and operational metrics
- Validation, limitations, and CTI justification content
- Tabbed layouts for:
  - `Data Explorer` + `Ethics & Security`
  - `Interactive Analytics` + `Approach Justification` + `Key Insights & Intelligence Summary`

## Main App Structure

- `app.py`
  - Landing page with the three milestone sections only

- `pages/1_Industry_Background.py`
  - Sector background and framing for the U.S. banking focus

- `pages/2_Threat_Trends.py`
  - Threat trend analysis and supporting CTI context

- `pages/3_Critical_Assets.py`
  - Banking critical assets and prioritization context

- `pages/4_Diamond_Models.py`
  - Diamond Model analysis and visuals

- `pages/5_Intel_Buyin.py`
  - Intelligence buy-in and stakeholder-facing value framing

- `pages/6_Dashboard.py`
  - Main CTI dashboard with source filtering, summary metrics, threat charts, asset alignment, heatmap, and Shodan summary

- `pages/7_Data_Explorer.py`
  - Tabbed page for:
    - `Dynamic Data Explorer`
    - `Ethics & Security`

- `pages/8_Analytical_approaches.py`
  - Tabbed page for:
    - `Interactive Analytics Panel`
    - `Approach Justification`
    - `Key Insights & Intelligence Summary`

- `pages/8_Data_Source_Identification_Justification.py`
  - Source identification, justification, and collection summary

- `pages/9_References.py`
  - References and citations

- `pages/10_Team.py`
  - Team roles and milestone contributions

## Data Inputs

Core local datasets include:
- `data/phishtank.csv`
- `data/verified_online_banking_finance.csv`
- `data/filtered_iocs_threatfox.csv`
- `data/finance_victims.csv`
- `data/finance_group_iocs.csv`
- `data/critical_assets.csv`
- `data/combined_iocs.csv`

Generated analytical outputs include:
- `data/phishing_url_text_mining/`
  - phishing URL features
  - keyword summaries
  - TF-IDF outputs
  - n-gram outputs
  - evaluation metrics

- `data/ransomware_event_correlation/`
  - group risk summaries
  - overlap summaries
  - network nodes and edges
  - group IOC-type counts
  - network metrics

## Analytics Utilities

- `utilities/phishing_url_text_mining.py`
  - Extracts phishing URL features and produces text-mining outputs

- `utilities/ransomware_event_correlation.py`
  - Builds cross-source ransomware correlation outputs and network files

- `utilities/kmeans.py`
  - K-means clustering workflow over ThreatFox-derived inputs

- `utilities/retrieve_ransomware_data.py`
  - Retrieval/support script for ransomware-related data handling

- `utilities/extract_banking_verified_online.py`
  - Banking-focused extraction support for verified online phishing data

## Other Supporting Files

- `data/data_collection.py`
  - Local collection script for selected source exports

- `Dockerfile`
  - Container setup for running the Streamlit app

- `requirements.txt`
  - Python dependencies

- `images/Diamond_model.png`
- `images/Diamond_model2.png`
  - Diamond Model visuals used in the app

- `changes/`
  - Development-time working copies and alternate versions retained during iteration

## Data Sources

- PhishTank
- ThreatFox
- ransomware.live
- Shodan

Note:
- `ThreatFox` and `Shodan` may require API keys through `.env`
- Some app pages use local cached/exported data alongside live API requests

## Local Run

### Windows PowerShell
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

### macOS / Linux
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

If needed, create a `.env` file for API-backed pages:
- `SHODAN_API_KEY`
- `THREATFOX_API_KEY`

## Docker Run

```bash
docker build -t banking-cti-app .
docker run --rm -p 8501:8501 --env-file .env banking-cti-app
```

## Notes

- The repository currently reflects Milestone 3 functionality and layout.
- Several pages combine local datasets with live-source summaries.
- The analytical justification content is presented in a higher-level CTI briefing style rather than a strict rubric table.
- The project emphasizes defender-facing outputs such as prioritization, triage support, alert precision, and mean-time-to-detect improvement.
