import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

d = pd.read_csv("timeline/case03_timeline.csv", parse_dates=["datetime_utc"])
d["t"] = (d["datetime_utc"] - d["datetime_utc"].min()).dt.total_seconds()

print("First label counts:")
print(d["query"].str.split(".").str[0].value_counts().head())
print("\nQueries longer than the 41-char polling baseline:")
print(d[d["query_len"] > 41][["datetime_utc", "query_len", "qtype_name"]].to_string())

fig, ax = plt.subplots(2, 1, figsize=(12, 7), sharex=True,
                       gridspec_kw={"height_ratios": [3, 1.3]})
colors = {"TXT": "tab:red", "MX": "tab:blue", "CNAME": "tab:green"}
for q, g in d.groupby("qtype_name"):
    ax[0].scatter(g["t"], g["query_len"], s=14, label=q, color=colors[q], alpha=0.8)
ax[0].axhline(41, ls="--", color="gray", lw=0.8)
ax[0].text(2, 46, "41-char polling baseline", color="gray", fontsize=8)
ax[0].set_ylabel("Query name length (chars)")
ax[0].set_title("Case03 - DNS tunneling (dnscat2) - 445 queries, 127.0.0.1 -> 127.0.0.1:53")
ax[0].legend(title="qtype")

bins = range(0, int(d["t"].max()) + 6, 5)
ax[1].hist(d["t"], bins=bins, color="tab:purple")
ax[1].set_ylabel("Queries / 5 s")
ax[1].set_xlabel("Seconds since first query (start 18:25:25 UTC)")

for x, label, y, ha in [(0, "Session 1\nhandshake", 225, "left"),
                        (118.8, "Session 2\nhandshake", 225, "right"),
                        (126.5, "240-char\nburst", 190, "left"),
                        (256, "Session 2 stops\n(inferred)", 225, "right")]:
    for a in ax:
        a.axvline(x, color="black", ls=":", lw=0.8)
    off = 1 if ha == "left" else -1
    ax[0].text(x + off, y, label, fontsize=7, va="top", ha=ha)
plt.tight_layout()
plt.savefig("viz/case03_timeline.png", dpi=150)
print("\nSaved viz/case03_timeline.png")
