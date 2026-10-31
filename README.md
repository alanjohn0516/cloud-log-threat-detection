# Cloud Log Threat Detection: Brute Force Detection in AWS CloudTrail Logs

Literature review plus a working prototype that detects brute force attacks
(password guessing, spraying, credential stuffing, role enumeration) in
synthetic AWS CloudTrail logs, comparing industry rules with ML models.

## Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Generate data
```bash
python cloud/generate_logs.py
```

## Run tests
```bash
python -m pytest tests -v
```
