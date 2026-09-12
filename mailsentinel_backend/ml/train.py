"""
MailSentinel ML — Model Training Script

Trains a TF-IDF + Random Forest classifier on synthetic phishing data.
Run once: python ml/train.py

Outputs: ml/phishing_model.pkl
"""

import os
import sys


sys.path.insert(0, os.path.dirname(__file__))

from data_generator import generate_dataset

from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, classification_report, confusion_matrix
)
import joblib
import numpy as np

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')


def train():
    print("=" * 60)
    print("  MailSentinel — ML Phishing Classifier Training")
    print("=" * 60)


    print("\n[1/5] Generating training data...")
    samples = generate_dataset(n_phishing=1200, n_legit=1200)
    texts  = [s['text']  for s in samples]
    labels = [s['label'] for s in samples]

    print(f"      Total samples : {len(samples)}")
    print(f"      Phishing (1)  : {sum(labels)}")
    print(f"      Legitimate (0): {len(labels) - sum(labels)}")


    print("\n[2/5] Splitting into train/test (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )
    print(f"      Train: {len(X_train)}  |  Test: {len(X_test)}")


    print("\n[3/5] Building TF-IDF + Random Forest pipeline...")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            max_features=8000,
            ngram_range=(1, 3),
            sublinear_tf=True,
            min_df=2,
            stop_words='english',
            strip_accents='unicode',
            analyzer='word',
        )),
        ('clf', RandomForestClassifier(
            n_estimators=200,
            max_depth=None,
            min_samples_split=2,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1,
        )),
    ])


    print("\n[4/5] Training model...")
    # Train the TF-IDF and Random Forest pipeline.
    pipeline.fit(X_train, y_train)


    print("\n[5/5] Evaluating model...")
    # Evaluate the model on the test set.
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec  = recall_score(y_test, y_pred)
    f1   = f1_score(y_test, y_pred)

    print(f"\n  Accuracy  : {acc:.4f}  ({acc*100:.1f}%)")
    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  F1 Score  : {f1:.4f}")

    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred,
                                target_names=['Legitimate', 'Phishing']))

    cm = confusion_matrix(y_test, y_pred)
    print("  Confusion Matrix:")
    print(f"    TN={cm[0,0]}  FP={cm[0,1]}")
    print(f"    FN={cm[1,0]}  TP={cm[1,1]}")


    print("\n  Running 5-fold cross-validation...")
    cv_scores = cross_val_score(pipeline, texts, labels, cv=5, scoring='f1')
    print(f"  CV F1 Scores: {cv_scores}")
    print(f"  CV Mean F1:   {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # Save the trained model for runtime prediction.
    joblib.dump(pipeline, MODEL_PATH)
    size_kb = os.path.getsize(MODEL_PATH) / 1024
    print(f"\nModel saved to: {MODEL_PATH}  ({size_kb:.0f} KB)")
    print("=" * 60)

    return pipeline


if __name__ == '__main__':
    train()
