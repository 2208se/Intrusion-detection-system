# SoukDZ-IDS — Intelligent Multi-Modal Intrusion Detection System

> **Final Year Engineering Project (PFE) · ESTIN / LITAN Laboratory · 2025–2026**
 
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://python.org)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.8.0-orange?logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![SHAP](https://img.shields.io/badge/SHAP-0.42-purple)](https://shap.readthedocs.io)
[![Flask](https://img.shields.io/badge/Flask-mock--backend-black?logo=flask)](https://flask.palletsprojects.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-dashboard-red?logo=streamlit)](https://streamlit.io)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

A production-ready, fully decoupled **two-layer intrusion detection system** for the [SoukDZ](https://github.com/kiouaz/soukdz-frontend) C2C fashion marketplace — combining **network  traffic analysis** (Layer 1) and **application behavioral analysis** (Layer 2) through a weighted cross-layer correlation engine, with full **SHAP per-alert explainability** in a real-time Streamlit dashboard.

---

## Results at a Glance

| Metric | Layer 1 (Network) | Layer 2 (Behavioral) | Kali Campaign |
|---|---|---|---|
| **F1-Score** | **1.0000** | **1.0000** | — |
| **AUC-ROC** | **1.0000** | **1.0000** | — |
| **False Positive Rate** | **0.000** | **0.000** | **0 / 4,861 legit entries** |
| **Detection Rate** | 100% | 100% | **5 / 5 scenarios** |
| **Detection Delay** | — | — | **10 seconds** |
| Test set size | 70,133 samples | 71 windows | 24 May 2026 |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SoukDZ Marketplace                        │
│         (Flask mock → Spring Boot production backend)        │
│                    Apache access.log ↓                       │
└──────────────────────────┬──────────────────────────────────┘
                           │ (log file — no runtime coupling)
          ┌────────────────┴────────────────┐
          │                                 │
    ┌─────▼──────────────────┐   ┌──────────▼──────────────────┐
    │     LAYER 1 — NETWORK   │   │   LAYER 2 — BEHAVIORAL       │
    │                         │   │                              │
    │  Scapy packet capture   │   │  Apache log parser (regex)   │
    │  60-second windows      │   │  5-minute behavioral windows │
    │  7 engineered features  │   │  8 marketplace features      │
    │  RF on CICIDS2017       │   │  RF + SMOTE on SoukDZ logs   │
    │  (957,452 samples)      │   │  (354 windows)               │
    │                         │   │                              │
    │  → S_L1 ∈ [0, 1]        │   │  → S_L2 ∈ [0, 1]            │
    └─────────────┬───────────┘   └──────────────┬──────────────┘
                  │                              │
                  └──────────────┬───────────────┘
                                 │
                    ┌────────────▼────────────────┐
                    │   CROSS-LAYER CORRELATOR     │
                    │                              │
                    │  S_final = 0.6·S_L2          │
                    │           + 0.4·S_L1         │
                    │                              │
                    │  FAIBLE   < 0.30  → log      │
                    │  MOYEN    0.30–0.60 → watch  │
                    │  ÉLEVÉ    0.60–0.85 → limit  │
                    │  CRITIQUE > 0.85  → block    │
                    └────────────┬────────────────┘
                                 │
                    ┌────────────▼────────────────┐
                    │   SHAP EXPLAINABILITY DASH   │
                    │   Streamlit · TreeSHAP       │
                    │   Per-alert top-3 features   │
                    │   4 tabs: L1 / L2 / Corr /  │
                    │           Alert History      │
                    └─────────────────────────────┘
```

---

## Features

- **Decoupled architecture** — the IDS shares no runtime dependency with the marketplace application; it reads exclusively from Apache log files
- **Cross-layer correlation** — first published system combining network and application behavioral signals for a marketplace threat model
- **Domain-specific feature engineering** — 8 behavioral features calibrated to the SoukDZ attack surface (brute force, credential stuffing, reconnaissance, scraping, fake accounts)
- **SMOTE class balancing** — handles the severe class imbalance inherent in security data without random duplication
- **Full SHAP explainability** — TreeSHAP per-alert top-3 feature attribution, computed in polynomial time for every raised alert
- **4-tier alert levels** — FAIBLE / MOYEN / ÉLEVÉ / CRITIQUE with automated responses at each level
- **Hot-swappable models** — `.joblib` serialisation allows model updates without downtime
- **Zero false positives** — validated against 4,861 concurrent legitimate entries during the Kali Linux campaign

---

## Layer 1 — Network Features

Extracted per source IP over 60-second sliding windows via Scapy:

| Feature | Formula | Attack Targeted |
|---|---|---|
| `bytes_per_second` | Σbytes / window_duration | DDoS · Scraping |
| `packet_rate` | Σpackets / 60s | Brute Force · DDoS |
| `unique_dst_ports` | \|{dst_port}\| | Reconnaissance · PortScan |
| `psh_flag_rate` | Σ(PSH=1) / Σpackets | Brute Force |
| `avg_packet_len` | Σbytes / Σpackets | Scraping · Web Attacks |
| `src_ip_entropy` | −Σ pᵢ log pᵢ | Credential Stuffing |
| `syn_to_ack_ratio` | Σ(SYN) / Σ(ACK) | SYN Flood · DoS |

**Training dataset:** CICIDS2017 (Canadian Institute for Cybersecurity) — 957,452 samples, 80 raw features reduced to 7 by Gini importance ranking.

---

## Layer 2 — Behavioral Features

Extracted per source IP over 5-minute windows by parsing Apache Combined Log Format:

| Feature | Computation | Attack Targeted |
|---|---|---|
| `failed_logins` | COUNT(status=401 AND /login) | S1 Brute Force |
| `login_success_ratio` | COUNT(200, /login) / total logins | S1 · S2 |
| `scan_score` | COUNT(status=404) / total requests | S3 Reconnaissance |
| `new_accounts` | COUNT(201, POST /register) | S5 Fake Accounts |
| `listing_reqs` | COUNT(GET /listings*) | S4 Scraping |
| `msg_rate` | COUNT(POST /messages) | Spam · Fraud |
| `offer_rate` | COUNT(POST /offers) | Offer abuse |
| `ip_diversity` | \|unique_src_IPs\| / total_requests | S2 Credential Stuffing |

**Training dataset:** SoukDZ synthetic logs — 354 five-minute behavioral windows generated by running real Kali Linux attack tools against the Flask mock backend.

---

## Threat Model — 5 Attack Scenarios

| # | Scenario | Tool | OWASP | MITRE ATT&CK |
|---|---|---|---|---|
| S1 | Brute Force | Hydra v9.5 | A07:2021 | T1110.001 |
| S2 | Credential Stuffing | Python script | A07:2021 | T1110.004 |
| S3 | Reconnaissance | Nikto v2.5.0 | A05:2021 | T1595.002 |
| S4 | Catalog Scraping | Python/requests | A05:2021 | T1020 |
| S5 | Fake Account Creation | Python loop | A07:2021 | T1136 |

> **Key finding:** S2 and S5 produce weak network signals (S_L1 ≈ 0.55–0.61) and would be missed or under-scored by a network-only IDS. The application behavioral layer is decisive for these two scenarios.

---

## Project Structure

```
soukdz-ids/
│
├── backend/                        # Flask mock marketplace backend
│   ├── app.py                      # 7 REST endpoints, Apache logging middleware
│   ├── vinted.db                   # SQLite — 2 users, 8 listings
│   └── requirements.txt
│
├── ids/
│   ├── layer1_network.py           # Scapy capture → 7 features → RF inference
│   ├── layer2_logs.py              # Apache log parser → 8 behavioral features
│   ├── correlator.py               # load_models(), correlate_and_score(), run_continuous()
│   ├── traffic_simulator.py        # Legitimate traffic generator (concurrent with attacks)
│   └── models/
│       ├── rf_layer1.joblib        # Trained RF — Layer 1
│       ├── rf_layer2.joblib        # Trained RF — Layer 2
│       ├── shap_l1.joblib          # TreeSHAP explainer — Layer 1
│       └── shap_l2.joblib          # TreeSHAP explainer — Layer 2
│
├── training/
│   ├── train_layer1.py             # CICIDS2017 → feature selection → SMOTE → RF
│   ├── train_layer2.py             # SoukDZ logs → 8 features → SMOTE → RF
│   └── data/
│       ├── cicids2017/             # Place CICIDS2017 CSV files here
│       └── soukdz_logs/            # Generated behavioral windows (JSON)
│
├── dashboard/
│   └── app.py                      # Streamlit — 4 tabs: L1 / L2 / Correlation / History
│
├── notebooks/
│   ├── layer1_analysis.ipynb       # Layer 1 EDA, feature importance, ROC curves
│   └── layer2_analysis.ipynb       # Layer 2 EDA, SMOTE visualisation, SHAP plots
│
├── docs/
│   ├── thesis_engineer.pdf         # ESTIN engineering thesis (XeLaTeX)
│   └── architecture.png            # System architecture diagram
│
├── docker-compose.yml              # Backend + IDS + Dashboard
├── requirements.txt
├── .env.example
└── README.md
```

---

## Installation

### Prerequisites

- Python 3.11 or 3.13
- Linux (Ubuntu 22.04+ recommended) or WSL2
- For Layer 1 packet capture: `sudo` privileges (Scapy requires raw socket access)

### 1. Clone the repository

```bash
git clone https://github.com/kiouaz/soukdz-ids.git
cd soukdz-ids
```

### 2. Create a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

<details>
<summary>Core dependencies</summary>

```
scapy>=2.5.0
scikit-learn==1.8.0
imbalanced-learn>=0.12.0
shap==0.42.1
flask>=3.0.0
streamlit>=1.35.0
pandas>=2.2.0
numpy>=1.26.0
joblib>=1.4.0
```

</details>

### 4. Download CICIDS2017

The CICIDS2017 dataset must be downloaded separately from the [University of New Brunswick](https://www.unb.ca/cic/datasets/ids-2017.html). Place the CSV files in `training/data/cicids2017/`.

### 5. Train the models

```bash
# Train Layer 1 (network classifier — requires CICIDS2017 CSVs)
python training/train_layer1.py

# Train Layer 2 (behavioral classifier — uses SoukDZ synthetic logs)
python training/train_layer2.py
```

Both scripts serialise their models to `ids/models/`.

---

## Usage

### Start the Flask mock backend

```bash
cd backend
python app.py
# → Running on http://127.0.0.1:5000
```

### Run the IDS (Layer 2 only — no root required)

```bash
cd ids
python correlator.py --mode log-only
```

### Run the IDS (full dual-layer — requires root for Scapy)

```bash
cd ids
sudo python correlator.py --mode full
```

### Launch the Streamlit dashboard

```bash
cd dashboard
streamlit run app.py
# → http://localhost:8501
```

### Run the legitimate traffic simulator (separate terminal)

```bash
cd ids
python traffic_simulator.py --target http://127.0.0.1:5000
```

### Docker (all services)

```bash
docker-compose up --build
# Backend  → :5000
# Dashboard → :8501
```

---

## Training Details

### Layer 1 — CICIDS2017

```
Total samples:   957,452
Train split:     765,961  (80%)
Test split:      191,491  (20%, stratified)
SMOTE applied:   Minority attack categories (Infiltration, Web Attacks)
Classifier:      RandomForestClassifier(n_estimators=100, criterion='gini',
                                        max_features='sqrt', random_state=42)
```

### Layer 2 — SoukDZ Behavioral Logs

```
Total windows:   354  (5-minute behavioral windows)
Train split:     283  (80%)
Test split:      71   (20%, stratified)
SMOTE applied:   Attack windows (10 original → balanced)
Classifier:      RandomForestClassifier(n_estimators=100, criterion='gini',
                                        max_features='sqrt', random_state=42)
```

---

## Kali Linux Validation Campaign

Campaign date: **24 May 2026**  
Environment: VMware Workstation · Kali Linux VM (4GB RAM) · Flask backend on host

| Scenario | Tool | S_L1 | S_L2 | S_final | Alert | Delay |
|---|---|---|---|---|---|---|
| S1 Brute Force | Hydra v9.5 `-t 16` | 0.94 | 0.97 | **0.958** | CRITIQUE | 10s |
| S2 Cred. Stuffing | Python (100 IPs) | 0.61 | 0.92 | **0.917** | CRITIQUE | 10s |
| S3 Reconnaissance | Nikto v2.5.0 | 0.88 | 0.95 | **0.922** | CRITIQUE | 10s |
| S4 Catalog Scraping | Python/requests | 0.90 | 0.88 | **0.888** | CRITIQUE | 10s |
| S5 Fake Accounts | Python loop | 0.55 | 0.96 | **0.958** | CRITIQUE | 10s |
| **Legitimate (4,861 entries)** | traffic_simulator.py | <0.15 | <0.12 | **<0.12** | FAIBLE | — |

> The 10-second detection delay is a file-polling artifact, not an algorithm limitation. The detection logic runs in milliseconds. Replacing the file poll with `watchdog`/inotify streaming would reduce this to sub-second latency.

---

## SHAP Explainability

Every ÉLEVÉ and CRITIQUE alert includes a per-alert SHAP attribution report. Example output for a Brute Force event:

```
CRITIQUE alert — S_final: 0.958
Timestamp: 2026-05-24 14:23:07
Source IP: 192.168.1.105

Top contributing features (SHAP values):
  failed_logins     : +0.38  ██████████████████████████████████████
  login_succ_ratio  : +0.21  █████████████████████
  scan_score        : +0.09  █████████
  [base rate]       :  0.12
```

SHAP values computed via `TreeExplainer` (exact Shapley values — no approximation).

---

## API Reference — Flask Mock Backend

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Authenticate user |
| `POST` | `/api/register` | Create new account |
| `GET` | `/api/listings` | Browse all listings |
| `GET` | `/api/listings/:id` | Get listing detail |
| `POST` | `/api/listings` | Create listing |
| `POST` | `/api/messages` | Send message |
| `POST` | `/api/offers` | Submit offer |

All requests are logged in Apache Combined Log Format to `backend/logs/access.log`.

---

## Limitations

1. **Synthetic Layer 2 training data** — 354 scripted behavioral windows do not fully represent production traffic diversity. The system should be retrained on real SoukDZ logs within 60 days of platform launch.

2. **Simultaneous dual-layer operation** — during the Kali validation campaign, Layer 1 (Scapy) and Layer 2 (logs) were not running concurrently. The cross-layer formula is architecturally validated but not empirically tested with both layers active at the same time.

3. **File-polling detection delay** — the 10-second delay is caused by the log polling interval. Sub-second detection is achievable with streaming log-tailing (Python `watchdog`, inotify, or a message queue).

---

## Roadmap

- [ ] Retrain Layer 2 on real SoukDZ production logs (60 days post-launch)
- [ ] Replace file polling with real-time log streaming (watchdog / Kafka)
- [ ] Spring Boot interceptor integration (replace Flask mock)
- [ ] Simultaneous dual-layer empirical validation campaign
- [ ] Federated learning across multiple Algerian e-commerce platforms
- [ ] Graph Neural Networks for coordinated fraud-ring detection
- [ ] Adversarial robustness evaluation (threshold-aware evasion attacks)

---

## Research Context

This system is the subject of a **Final Year Engineering Project (PFE)** at [ESTIN](https://www.estin.dz/) (École Supérieure en Sciences et Technologies de l'Informatique et du Numérique), Béjaïa, Algeria, developed within the **LITAN Laboratory**.

The IDS is designed for the **SoukDZ** platform — an Algerian C2C fashion marketplace incubated at LITAN under startup decree 1275/008.

**Key finding from a systematic review of 24 IDS methods across 4 generations (1994–2026):** no published system simultaneously addresses cross-layer network + application behavioral correlation, domain-specific marketplace feature engineering, and full SHAP per-alert explainability. This system addresses all three gaps.

### Key References

- Denning, D.E. (1987). An intrusion-detection model. *IEEE Transactions on Software Engineering*, SE-13(2).
- Sharafaldin, I., et al. (2018). Toward generating a new intrusion detection dataset. *ICISSP*.
- Chawla, N.V., et al. (2002). SMOTE: Synthetic minority over-sampling technique. *JAIR*, 16.
- Lundberg, S.M. & Lee, S.-I. (2017). A unified approach to interpreting model predictions. *NeurIPS*.
- Khraisat, A., et al. (2019). Survey of intrusion detection systems. *Cybersecurity*, 2(1).
- Rahman, A., et al. (2024). ML strategies in IDS: a comprehensive survey. *Frontiers in Computer Science*.

---

## Academic Information

| | |
|---|---|
| **Student** | Kiouaz Selssabila |
| **Degree** | Engineer's Degree in Computer Science — Specialty: Cybersecurity |
| **Institution** | ESTIN, RN 75, Amizour 06300, Béjaïa, Algeria |
| **Laboratory** | LITAN — Laboratoire d'Informatique et Technologies Avancées du Numérique |
| **Supervisor** | Mme Amara Karima (LITAN / ESTIN) |
| **Co-supervisor** | Pr. Naït Abdesselam Farid (Université Paris Cité) |
| **Academic year** | 2025 / 2026 |

---

## License

This project is released under the [MIT License](LICENSE).

The CICIDS2017 dataset is subject to its own terms of use — see the [UNB CIC website](https://www.unb.ca/cic/datasets/ids-2017.html).

---

## Contributing

This is an academic project. Issues and pull requests are welcome for bug fixes, documentation improvements, or implementation enhancements.

```bash
git checkout -b feature/your-feature
git commit -m "feat: description"
git push origin feature/your-feature
```

Please open an issue before submitting large changes.
