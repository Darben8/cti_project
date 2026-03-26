# CTI Milestone 1 - U.S. Banking Streamlit App

This repository now includes a multipage Streamlit application for Milestone 1 focused on cyber threat intelligence in the U.S. banking sector.

## Included Milestone 1 Sections
- Introduction and industry background
- Stakeholders and user stories
- CTI use case / threat-model-backed design
- Threat trends and critical assets
- Two complete Diamond Models (A and B) with visual diagrams
- Dynamic dashboard starter (filter + dynamic chart + dynamic table + KPIs)
- Intelligence buy-in section
- "What's New" milestone checklist in the app

## Data Sources
- PhishTank (open source)
- ransomware.live (open source)
- Shodan (API key via `.env`)
- Approved class input figures (Verizon / IBM / Deloitte)

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
- `pages/1_Industry_Background.py` - industry background page
- `pages/2_Threat_Trends.py` - threat trends and threat intelligence overview
- `pages/3_Critical_Assets.py` - critical assets page
- `pages/4_Diamond_Models.py` - Diamond Model analysis page
- `pages/5_Dashboard_Starter.py` - dynamic dashboard page
- `pages/6_Intel_Buyin.py` - intelligence buy-in page
- `pages/7_Team.py` - team page
- `pages/Stakeholders.py` - stakeholders page
- `data/critical_assets.csv` - critical assets dataset
- `data/threat_events.csv` - threat events dataset

## Notes
- Citations are displayed in APA-style summary format in the app.
- MITRE ATT&CK technique IDs are included where relevant.
