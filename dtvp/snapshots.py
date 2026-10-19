"""Historical source-rating validation for explicit snapshot migration."""

from cvss import CVSS3, CVSS4


def base_rating(rating):
    vector = rating.get("vector", "")
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/", "CVSS:4.0/")):
        return None
    try:
        parsed = CVSS4(vector) if vector.startswith("CVSS:4") else CVSS3(vector)
        allowed = (
            {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}
            if vector.startswith("CVSS:4")
            else {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
        )
        supplied = {field.split(":", 1)[0] for field in vector.split("/")[1:]}
        score = parsed.scores()[0]
        if not supplied.issubset(allowed) or float(rating.get("score", score)) != score:
            return None
        return {"vector": vector, "score": score}
    except ValueError, TypeError:
        return None
