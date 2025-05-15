#!/usr/bin/env python3
from sklearn.metrics import classification_report, roc_auc_score
import pandas as pd
import numpy as np

df = pd.read_csv("data/processed/flows_test.csv")
y_true = df["label"].values
X = df.drop(columns=["label"]).values
means = np.loadtxt("ml/parameters/mean.txt")
stds  = np.loadtxt("ml/parameters/std.txt")
weights = np.loadtxt("ml/parameters/weights.txt")
intercept = float(np.loadtxt("ml/parameters/intercept.txt"))

def sigmoid(z): return 1/(1+np.exp(-z))
X_scaled = (X - means)/stds
z = intercept + X_scaled.dot(weights)
y_prob = sigmoid(z)
y_pred = (y_prob > 0.5).astype(int)

print(classification_report(y_true, y_pred))
print("ROC AUC:", roc_auc_score(y_true, y_prob))
