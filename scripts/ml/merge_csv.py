#!/usr/bin/env python3

import pandas as pd

# 1) Read each feature CSV
ben = pd.read_csv("benign_features.csv")
mal = pd.read_csv("malicious_features.csv")

# 2) Assign labels
ben["label"] = 0
mal["label"] = 1

# 3) Concatenate
df = pd.concat([ben, mal], ignore_index=True)

# 4) Shuffle (optional but recommended)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# 5) Write out
df.to_csv("flows_labeled.csv", index=False)
print(f"Wrote flows_labeled.csv with {len(df)} rows")
