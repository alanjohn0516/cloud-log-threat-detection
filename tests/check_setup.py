# tests/check_setup.py
# Checks that all required libraries are installed correctly.
import pandas, numpy, sklearn, xgboost, matplotlib, seaborn
import fastapi, uvicorn, streamlit, requests, joblib, pytest

libs = {
    "pandas": pandas, "numpy": numpy, "scikit-learn": sklearn,
    "xgboost": xgboost, "matplotlib": matplotlib, "seaborn": seaborn,
    "fastapi": fastapi, "uvicorn": uvicorn, "streamlit": streamlit,
    "requests": requests, "joblib": joblib, "pytest": pytest,
}
for name, lib in libs.items():
    print(f"OK  {name:14} {lib.__version__}")
print("\nSetup complete. You are ready for Step 2.")
