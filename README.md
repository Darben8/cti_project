# CTI - U.S. Banking Streamlit App

This repository now includes a multipage Streamlit application focused on cyber threat intelligence in the U.S. banking sector.

## Included Milestone 1 Sections
- Introduction and industry background
- Stakeholders and user stories
- CTI use case / threat-model-backed design
- Threat trends and critical assets
- Two complete Diamond Models (A and B) with visual diagrams
- Dynamic dashboard starter (filter + dynamic chart + dynamic table + KPIs)
- Intelligence buy-in section
- "What's New" milestone checklist in the app

## Included Milestone 2 Sections
- Expanded dashboard with multiple CTI visualizations and critical asset alignment
- Data explorer for filtered inspection of combined threat intelligence records
- Data source identification and justification for PhishTank and ThreatFox
- Collection strategy and data summary for how source data was gathered and normalized
- Team roles and milestone contribution updates
- Support for live and local CTI data sources including PhishTank, ThreatFox, ransomware.live, and Shodan
- Local collection script for exporting Shodan exposure metadata and live ThreatFox records

## Data Sources
- PhishTank (open source)
- ransomware.live (open source)
- Shodan (API key via `.env`)
- Threatfox (API key via '.env')


## Local Run
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env and add SHODAN_API_KEY
streamlit run app.py
```

## Docker Run
```bash
docker build -t banking-cti-m1 .
docker run --rm -p 8501:8501 --env-file .env banking-cti-m1
```

## Project Structure
- `app.py` - Streamlit app entry point
- `README.md` - project overview and setup instructions
- `requirements.txt` - Python dependencies
- `Dockerfile` - container setup for the app
- `images/Diamond_model.png` - Diamond Model image for PhishTank/source justification content
- `images/Diamond_model2.png` - Diamond Model image for ThreatFox/source justification content
- `pages/1_Industry_Background.py` - industry background page
- `pages/2_Threat_Trends.py` - threat trends and threat intelligence overview
- `pages/3_Critical_Assets.py` - critical assets page
- `pages/4_Diamond_Models.py` - Diamond Model analysis page
- `pages/5_Intel_Buyin.py` - intelligence buy-in page
- `pages/6_Dashboard.py` - main dashboard page combining charts, source views, and asset alignment
- `pages/7_Data_Explorer.py` - data exploration page for filtered source inspection
- `pages/8_Data_Source_Identification_Justification.py` - data source background, justification, and collection summary page
- `pages/9_References.py` - references and citations page
- `pages/10_Team.py` - team roles and contributions page
- `pages/Stakeholders.py` - stakeholders page
- `data/data_collection.py` - local collection script for Shodan and ThreatFox exports
- `data/critical_assets.csv` - critical assets dataset
- `data/combined_iocs.csv` - combined IOC dataset used by dashboard and data explorer pages
- `data/phishtank.csv` - local PhishTank IOC dataset
- `data/threat_events.csv` - threat events dataset
<<<<<<< HEAD

## Notes
- Citations are displayed in APA-style summary format in the app.
- MITRE ATT&CK technique IDs are included where relevant.
=======
- `changes/` - working copies and alternate versions retained during development

## Notes
- Citations are displayed in APA-style summary format in pages/References.
- MITRE ATT&CK technique IDs are included where relevant.
>>>>>>> 304529f37bbd894f0d73f60577375ad8cc6aa119
