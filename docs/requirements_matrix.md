# Requirements traceability matrix

Status: DONE, PARTIAL, NOT DONE, PENDING (student work)

## Document 1: literature review plan

| # | Requirement | Status | Where |
|---|---|---|---|
| 1 | Brute force (T1110) in AWS CloudTrail ConsoleLogin and AssumeRole | DONE | cloud/generate_logs.py, security/rules.py |
| 2 | Other log sources (VPC Flow Logs, CloudWatch, GuardDuty, EC2 auth logs) | NOT DONE | scope limit, listed as future work |
| 3 | Variants: guessing, spraying, credential stuffing, role enumeration | DONE | generator attacks, pipeline classification |
| 4 | Industry rules: Elastic, Sigma/Splunk, Splunk Security Content | DONE | security/rules.py (R1, R2, R3) |
| 5 | RQ1: log sources and most useful fields | PARTIAL | ml/features.py, reports/ml_feature_importance.csv; literature part pending |
| 6 | RQ2: detection approaches compared | DONE | reports/ml_results.csv, cross_seed_summary.csv (graph and LLM only in the review) |
| 7 | RQ3: variants addressed | DONE | reports/ml_attack_level.csv |
| 8 | RQ4: datasets and metrics | DONE | synthetic generator, precision, recall, F1, FPR |
| 9 | RQ5: gaps (false positives, low-and-slow, no public AWS dataset) | DONE | rules miss spraying and low-and-slow, SSO false alarm |
| 10 | SLR: search, screening, PRISMA, extraction, quality scoring | PENDING | tools in docs/slr/, searching is student work |
| 11 | Verify details of the five seed papers | PENDING | check on publisher pages |

## Document 2: system roles

| # | Requirement | Status | Where |
|---|---|---|---|
| 12 | Create a cloud server on AWS/Azure/GCP and deploy the application | NOT DONE | everything runs locally (WSL) |
| 13 | Collect logs | DONE | generator, POST /logs |
| 14 | Store logs in a database | DONE (local SQLite) | cloud/database.py |
| 15 | API to send logs to the AI model | DONE | POST /detect, GET /alerts |
| 16 | Host the security dashboard | PARTIAL | dashboard/app.py runs locally |
| 17 | Manage storage and access | PARTIAL | no authentication yet |
| 18 | Dataset, cleaning, feature selection | DONE | generator, ml/features.py |
| 19 | Train and compare Random Forest, Decision Tree, Logistic Regression, Isolation Forest, XGBoost | DONE | ml/train.py |
| 20 | Accuracy, precision, recall, F1 | DONE | security/metrics.py, reports/ |
| 21 | Integrate the model with the cloud application | DONE | security/pipeline.py, cloud/api.py |
| 22 | Define threats, indicators, security rules | DONE | security/rules.py |
| 23 | Threat classification and severity levels | DONE | security/pipeline.py |
| 24 | Authentication and access control | NOT DONE | planned |
| 25 | Alert and incident-response procedures | DONE | recommended actions, alert status workflow |
| 26 | Security dashboard | DONE (local) | dashboard/app.py |

## Known limitations

- All data is synthetic; train and test come from the same generator (different seeds).
- History features assume attackers use IP addresses never seen before.
- Incident grouping can merge simultaneous attacks that share a target (ALERT-0007).
