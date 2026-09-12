"""
MailSentinel ML — Phishing Predictor

Loads the trained model and exposes predict() for use in security.py.
Model is loaded once and cached in memory.
"""

import os
import joblib

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')

_model = None


def load_model():
    global _model
    # Load the saved model only once.
    if _model is None:
        if os.path.exists(MODEL_PATH):
            _model = joblib.load(MODEL_PATH)
    return _model


def predict(subject: str, body_text: str) -> dict:
    """
    Returns:
        {
            'probability': float  0.0 (safe) .. 1.0 (phishing),
            'label':       'phishing' | 'legitimate' | 'unavailable',
            'confidence':  float  0.0 .. 1.0,
            'loaded':      bool,
        }
    """
    model = load_model()
    # Return unavailable if the model file cannot be loaded.
    if model is None:
        return {
            'probability': 0.5,
            'label':       'unavailable',
            'confidence':  0.0,
            'loaded':      False,
        }

    text  = f"{subject or ''} {body_text or ''}".strip()
    prob  = model.predict_proba([text])[0][1]
    label = 'phishing' if prob >= 0.5 else 'legitimate'
    conf  = prob if prob >= 0.5 else (1.0 - prob)

    return {
        'probability': round(float(prob), 4),
        'label':       label,
        'confidence':  round(float(conf), 4),
        'loaded':      True,
    }


def is_model_ready() -> bool:
    return os.path.exists(MODEL_PATH)
