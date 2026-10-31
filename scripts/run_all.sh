#!/usr/bin/env bash
# scripts/run_all.sh: rebuilds everything from scratch and tests it.
# Run from the project root with the virtual environment active:
#   bash scripts/run_all.sh
set -e
echo "== 1/7 Generate synthetic CloudTrail logs"
python cloud/generate_logs.py > reports/generator_output.txt
grep "Total events" reports/generator_output.txt

echo "== 2/7 Load logs into the cloud database"
python -m cloud.load_logs --reset | grep -E "Result|Total events"

echo "== 3/7 Rule engine baseline"
python -m security.evaluate_rules > reports/rules_output.txt
grep "Overall" reports/rules_output.txt

echo "== 4/7 Train and compare ML models"
python -m ml.train > reports/ml_output.txt
grep -A8 "FULL feature set" reports/ml_output.txt

echo "== 5/7 Integrated pipeline"
python -m security.run_pipeline > reports/pipeline_output.txt
grep -A4 "POLICY COMPARISON" reports/pipeline_output.txt

echo "== 6/7 API smoke test"
python scripts/smoke_test.py

echo "== 7/7 Automated tests"
python -m pytest tests -q

echo "ALL STEPS FINISHED"
