# Authentication Security Dashboard

## Overview
This repository implements a Django‑based authentication system with a **premium security analysis dashboard**. The dashboard provides five deterministic, rule‑based security tools that can be invoked via a REST API or directly from the web UI:

1. **Risk Classifier** – evaluates a login attempt and returns a risk level (Low/Medium/High), a concise reason, and a recommendation (Allow/Block/Challenge).
2. **Suspicious Activity Detector** – scans a series of login logs for brute‑force, impossible‑travel, or device‑switch anomalies.
3. **Session Conflict Resolver** – detects concurrent sessions from disparate locations and suggests safe actions (terminate, suspend, flag).
4. **Log Summarizer** – produces a human‑readable summary of authentication logs, highlighting patterns and actionable insights.
5. **Brute‑Force Detector** – identifies credential‑stuffing attacks and recommends IP blocking or rate‑limiting.

All logic lives in `auth/login/security_engine.py` and is **deterministic** – no external AI services are required. The implementation is fully unit‑tested with a tiny script in `scratch/test_security.py`.

## Project Structure
```
/authentification/
│   README.md
│   requirements.txt
│   .gitignore
│
├── auth/
│   └── login/
│       ├── security_engine.py   # core security logic
│       ├── views.py              # API endpoint `SecurityAnalysisView`
│       ├── urls.py               # registers `/security/`
│       └── ...
│
├── security.html                # premium dark‑theme dashboard (HTML/CSS)
├── login.html
├── register.html
└── venv/                        # Python virtual environment
```

## Setup
1. **Clone the repository**
   ```bash
   git clone <repo‑url>
   cd authentification
   ```
2. **Create a virtual environment** (the repository already contains one, but you can recreate it):
   ```bash
   python -m venv venv
   venv\Scripts\activate   # on Windows
   ```
3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```
   The required packages are:
   - Django
   - djangorestframework
   - django-cors-headers
4. **Run database migrations**
   ```bash
   python manage.py migrate
   ```
5. **Start the development server**
   ```bash
   python manage.py runserver
   ```
   The API endpoint will be available at `http://127.0.0.1:8000/security/` and the dashboard at `http://127.0.0.1:8000/security.html`.

## Usage
- **API**: POST JSON payloads to `/security/` with a `type` field (`risk`, `suspicious`, `conflict`, `summary`, `bruteforce`) and the corresponding data shape. The view returns a JSON response containing the analysis result.
- **Dashboard**: Open `security.html` in a browser. Use the built‑in simulation buttons to send example payloads to the API and view formatted results.

## Testing
A quick sanity check is provided in `scratch/test_security.py`. Run it with:
```bash
python scratch/test_security.py
```
The script prints the output of each of the five security functions for a set of mock inputs.

## Contributing
Feel free to fork the repository and submit pull requests. When adding new security heuristics, keep the implementation **deterministic** and add unit tests.

## License
This project is released under the MIT License.
