"""
Risk scoring utilities for phishing detection model.
Converts model probability outputs into interpretable risk scores and levels.
"""


def compute_risk_score(probability: float) -> float:
    """
    Convert model probability (0–1) into a percentage risk score (0–100).
    
    Args:
        probability (float): Model output probability between 0 and 1

    Returns:
        float: Risk score between 0 and 100, rounded to 2 decimal places
    """
    if probability < 0:
        probability = 0
    elif probability > 1:
        probability = 1

    return round(probability * 100, 2)


def get_risk_level(score: float) -> str:
    """
    Convert numeric risk score into categorical risk level.

    Args:
        score (float): Risk score between 0 and 100

    Returns:
        str: LOW, MEDIUM, or HIGH
    """
    if score < 40:
        return "LOW"
    elif score < 70:
        return "MEDIUM"
    return "HIGH"


def get_risk_assessment(probability: float) -> dict:
    """
    Full risk breakdown for UI/dashboard usage.

    Args:
        probability (float): Model probability (0–1)

    Returns:
        dict: {
            "risk_score": float,
            "risk_level": str
        }
    """
    score = compute_risk_score(probability)

    return {
        "risk_score": score,
        "risk_level": get_risk_level(score)
    }