# docs/slr/make_prisma.py
# Draws a PRISMA-style flow diagram from docs/slr/prisma_counts.json
import json
import matplotlib
matplotlib.use("Agg")  # draw to a file, no display needed
import matplotlib.pyplot as plt

with open("docs/slr/prisma_counts.json") as f:
    c = json.load(f)

# Derived numbers
screened = c["identified"] - c["duplicates_removed"]
full_text = screened - c["excluded_title_abstract"]
from_search = full_text - c["excluded_full_text"]
final = from_search + c["added_snowballing"]

if min(screened, full_text, from_search, final) < 0:
    print("WARNING: a count is negative. Check prisma_counts.json.")

fig, ax = plt.subplots(figsize=(9, 10))
ax.axis("off")

main_x, side_x = 0.33, 0.80
box = dict(boxstyle="round,pad=0.5", fc="#eef3fb", ec="#1f3a6e")
side = dict(boxstyle="round,pad=0.5", fc="#fdf1e3", ec="#a35a00")

mains = [
    (0.92, f"Records identified from databases\n(n = {c['identified']})"),
    (0.74, f"Records after duplicates removed\n(n = {screened})"),
    (0.56, f"Full-text papers assessed\n(n = {full_text})"),
    (0.38, f"Studies from database search\n(n = {from_search})"),
    (0.18, f"Studies included in the review\n(n = {final})"),
]
sides = [
    (0.83, f"Duplicates removed\n(n = {c['duplicates_removed']})"),
    (0.65, f"Excluded at title/abstract\n(n = {c['excluded_title_abstract']})"),
    (0.47, f"Excluded at full text\n(n = {c['excluded_full_text']})"),
    (0.28, f"Added by snowballing\n(n = {c['added_snowballing']})"),
]

for y, text in mains:
    ax.text(main_x, y, text, ha="center", va="center", fontsize=11, bbox=box)
for y, text in sides:
    ax.text(side_x, y, text, ha="center", va="center", fontsize=10, bbox=side)

arrow = dict(arrowstyle="->", color="#333333")
for (y1, _), (y2, _) in zip(mains[:-1], mains[1:]):
    ax.annotate("", xy=(main_x, y2 + 0.05), xytext=(main_x, y1 - 0.05), arrowprops=arrow)
for y, _ in sides:
    ax.annotate("", xy=(side_x - 0.13, y), xytext=(main_x + 0.02, y), arrowprops=arrow)

ax.set_xlim(0, 1)
ax.set_ylim(0.05, 1)
ax.set_title("PRISMA-style flow diagram", fontsize=14)
fig.savefig("reports/prisma_flow.png", dpi=200, bbox_inches="tight")
print("Saved reports/prisma_flow.png")
print(f"Identified={c['identified']} -> Screened={screened} -> "
      f"Full text={full_text} -> From search={from_search} -> Final={final}")
