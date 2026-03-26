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
- `app.py` - landing page + milestone checklist + background/use case/buy-in
- `pages/1_Threat_Trends_and_Critical_Assets.py`
- `pages/2_Diamond_Models.py`
- `pages/3_Dashboard_Starter.py`
- `data/critical_assets.csv`
- `data/threat_events.csv`

## Notes
- Citations are displayed in APA-style summary format in the app.
- MITRE ATT&CK technique IDs are included where relevant.
