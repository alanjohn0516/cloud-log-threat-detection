# docs/slr/quality_summary.py
# Adds up the quality scores and counts papers per detection approach.
import pandas as pd

df = pd.read_csv("docs/slr/papers_extraction.csv")

qcols = ["q1_objectives", "q2_reproducible", "q3_dataset",
         "q4_metrics", "q5_limitations"]
for col in qcols:
    df[col] = pd.to_numeric(df[col], errors="coerce")  # blank -> NaN

df["quality_total"] = df[qcols].sum(axis=1, min_count=1)
df["title_short"] = df["title"].str[:45] + "..."

print(df[["id", "title_short", "approach", "log_source", "quality_total"]]
      .to_string(index=False))
print("\nPapers per detection approach:")
print(df["approach"].value_counts().to_string())
