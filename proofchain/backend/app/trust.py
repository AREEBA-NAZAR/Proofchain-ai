"""Transparent trust score: every point is attributable to a named component.

The score summarizes *provenance signals*. It is not a judgement that the
content is true.
"""

DISCLAIMERS = [
    "A blockchain record proves this fingerprint was registered by this wallet at this time and has "
    "not been altered since. It does not prove the content is truthful or that the registrant is the "
    "original author.",
    "AI analysis is probabilistic. It can miss manipulated content and can flag genuine content.",
]


def compute_trust(record: dict | None, identity: dict | None, analysis: dict | None, flags: list[dict]) -> dict:
    components = []

    # 1. Provenance (30)
    if record is None:
        pts, detail = 0, "No on-chain record exists for this fingerprint."
    elif record["revoked"]:
        pts, detail = 0, "The creator revoked this record."
    else:
        pts, detail = 30, "Fingerprint is registered on-chain and the record is intact."
    components.append({"id": "provenance", "label": "Blockchain provenance", "points": pts, "max": 30, "detail": detail})

    # 2. Identity (20)
    if record is None:
        pts, detail = 0, "No registrant."
    elif identity and identity["verified"]:
        pts, detail = 20, f"Registered by “{identity['name']}”, an identity attested by the registry admin."
    elif identity:
        pts, detail = 8, f"Registrant self-declares as “{identity['name']}” (unverified; anyone can claim a name)."
    else:
        pts, detail = 3, "Registered by an anonymous wallet with no identity profile."
    components.append({"id": "identity", "label": "Creator identity", "points": pts, "max": 20, "detail": detail})

    # 3. AI signals (30)
    risk = (analysis or {}).get("risk")
    if risk is None:
        pts = 15
        detail = "This file type could not be scored for AI generation or safety, so this component is neutral."
    else:
        pts = round(30 * (1 - risk))
        detail = (
            f"Estimated content risk {risk:.0%} (AI generation, manipulation or unsafe content; "
            f"{(analysis or {}).get('engine') or 'file safety checks'})."
        )
    components.append({"id": "ai", "label": "Content analysis", "points": pts, "max": 30, "detail": detail})

    # 4. Registration pattern (20)
    penalty = {"high": 20, "medium": 10, "info": 0}
    serious = [f for f in flags if penalty.get(f["severity"], 0) > 0]
    if record is None:
        pts, detail = 0, "Not applicable without a record."
    elif serious:
        pts = max(0, 20 - sum(penalty[f["severity"]] for f in serious))
        detail = "Suspicious registration pattern(s): " + ", ".join(sorted({f["kind"] for f in serious})) + "."
    else:
        pts, detail = 20, "No suspicious registration patterns detected."
    components.append({"id": "pattern", "label": "Registration pattern", "points": pts, "max": 20, "detail": detail})

    score = sum(c["points"] for c in components)
    if record is not None and record["revoked"]:
        score = min(score, 35)
    if record is None:
        band = "unregistered"
    elif score >= 75:
        band = "high"
    elif score >= 50:
        band = "moderate"
    else:
        band = "low"

    return {"score": score, "max": 100, "band": band, "components": components}
