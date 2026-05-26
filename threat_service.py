def get_threat_data(severity):

    severity = severity.lower()

    mapping = {
        "low": "Minimal Threat",
        "medium": "Moderate Threat",
        "high": "Serious Threat",
        "critical": "Critical Threat"
    }

    return {
        "threat_level":
        mapping.get(severity, "Unknown")
    }