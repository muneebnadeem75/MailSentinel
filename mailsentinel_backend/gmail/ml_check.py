"""
MailSentinel ML Check — Check 7: ML Classifier
Module-level import so the model loads ONCE at startup, not per-request.
"""
import os
import sys



_BACKEND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_ROOT not in sys.path:
    sys.path.insert(0, _BACKEND_ROOT)


try:
    from ml.predictor import predict as _ml_predict, is_model_ready as _ml_ready
    _ML_AVAILABLE = True
except Exception as _import_err:
    _ML_AVAILABLE = False
    _ML_IMPORT_ERR = str(_import_err)


def _ml_result(name, status, detail):
    """Standardised check result dict."""
    return {'name': name, 'status': status, 'detail': detail}


def _check_ml_classifier(subject, body_text):
    """
    Check 7 — Random Forest classifier trained locally on phishing/legit data.
    Weight: 15 pts.
    """
    name = "ML Classifier"

    if not _ML_AVAILABLE:
        return _ml_result(name, "warn",
                          "ML module not available: " + _ML_IMPORT_ERR[:60])

    if not _ml_ready():
        return _ml_result(name, "warn",
                          "ML model not trained yet -- run: python ml/train.py")

    try:
        prediction = _ml_predict(subject, body_text)

        if not prediction["loaded"]:
            return _ml_result(name, "warn", "ML model could not be loaded")

        prob     = prediction["probability"]
        conf     = prediction["confidence"]
        pct      = round(prob * 100, 1)
        conf_pct = round(conf * 100)

        if prob >= 0.70:
            return _ml_result(name, "fail",
                              "ML model: " + str(pct) + "% phishing probability (confidence " + str(conf_pct) + "%)")
        elif prob >= 0.45:
            return _ml_result(name, "warn",
                              "ML model: " + str(pct) + "% phishing probability -- borderline")
        else:
            safe_pct = round((1.0 - prob) * 100, 1)
            return _ml_result(name, "pass",
                              "ML model: " + str(safe_pct) + "% legitimate (confidence " + str(conf_pct) + "%)")

    except Exception as exc:
        msg = str(exc)
        if len(msg) > 80:
            msg = msg[:80]
        return _ml_result(name, "warn", "ML prediction failed: " + msg)
