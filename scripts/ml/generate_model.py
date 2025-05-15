#!/usr/bin/env python3
"""
generate_model.py

Reads a labeled flows CSV, trains a logistic regression,
and writes model parameters (weights, intercept, means, stds)
to the ml/parameters directory.
"""

import argparse
import logging
import os
import sys

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression

def parse_args():
    p = argparse.ArgumentParser(
        description="Train logistic-regression model on flow features and output parameters."
    )
    p.add_argument(
        "--input-csv", "-i", required=True,
        help="Path to labeled CSV (must include a 'label' column)."
    )
    p.add_argument(
        "--output-dir", "-o", default="ml/parameters",
        help="Directory to write weights.txt, intercept.txt, mean.txt, std.txt"
    )
    p.add_argument(
        "--random-state", type=int, default=42,
        help="Random seed for reproducibility."
    )
    return p.parse_args()

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

def main():
    args = parse_args()
    setup_logging()

    # 1) Load data
    if not os.path.isfile(args.input_csv):
        logging.error("Input CSV not found: %s", args.input_csv)
        sys.exit(1)
    df = pd.read_csv(args.input_csv)
    if 'label' not in df.columns:
        logging.error("CSV must contain a 'label' column.")
        sys.exit(1)

    y = df['label'].values
    X = df.drop(columns=['label']).values
    feature_names = df.drop(columns=['label']).columns.tolist()
    logging.info("Loaded %d samples with %d features", X.shape[0], X.shape[1])

    # 2) Compute training-set means & stds
    means = X.mean(axis=0)
    stds = X.std(axis=0, ddof=0)
    X_scaled = (X - means) / stds
    logging.info("Standardized features (zero mean, unit variance)")

    # 3) Train logistic regression
    clf = LogisticRegression(
        random_state=args.random_state,
        solver='lbfgs',
        max_iter=1000,
        class_weight='balanced',
    )
    clf.fit(X_scaled, y)
    weights = clf.coef_[0]
    intercept = clf.intercept_[0]
    logging.info("Trained logistic regression (intercept=%.4f)", intercept)

    os.makedirs(args.output_dir, exist_ok=True)

    def write_array(arr, path):
        """
        Saves arr (a NumPy array or a Python list) to `path` with one float per line,
        and logs the number of entries written.
        """
        np.savetxt(path, arr, fmt="%.6f")
        try:
            count = arr.shape[0]
        except AttributeError:
            count = len(arr)
        logging.info("Wrote %s (%d entries)", path, count)

    write_array(weights,     os.path.join(args.output_dir, "weights.txt"))
    write_array([intercept], os.path.join(args.output_dir, "intercept.txt"))
    write_array(means,       os.path.join(args.output_dir, "mean.txt"))
    write_array(stds,        os.path.join(args.output_dir, "std.txt"))


    with open(os.path.join(args.output_dir, "features.txt"), "w") as f:
        for name in feature_names:
            f.write(f"{name}\n")
    logging.info("Wrote feature list to features.txt")

    logging.info("Model parameter generation complete.")

if __name__ == "__main__":
    main()
