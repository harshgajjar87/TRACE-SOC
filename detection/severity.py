SEVERITY_LEVELS = {

    "INFO": 1,

    "LOW": 2,

    "MEDIUM": 3,

    "HIGH": 4,

    "CRITICAL": 5

}


def get_severity_score(severity):

    return SEVERITY_LEVELS.get(
        severity.upper(),
        1
    )


def classify_severity(score):

    if score >= 90:
        return "CRITICAL"

    elif score >= 70:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    elif score >= 20:
        return "LOW"

    return "INFO"