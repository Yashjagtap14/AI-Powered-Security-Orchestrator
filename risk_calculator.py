def calculate_risk(severity):

    severity = severity.lower()

    score_map = {
        "low": 2,
        "medium": 5,
        "high": 8,
        "critical": 10,
        "warning": 4,
        "error": 8
    }

    return score_map.get(
        severity,
        1
    )