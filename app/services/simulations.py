SCENARIOS = {
    "sql-injection": {
        "name": "SQL injection",
        "description": "A mock applicant lookup receives a crafted search string.",
        "vulnerable": "String-concatenated query can alter the mock lookup predicate.",
        "defended": "A parameterized lookup treats the entire search string as data.",
    },
    "brute-force": {
        "name": "Brute-force login",
        "description": "Three predefined guesses are replayed against a simulated account.",
        "vulnerable": "The mock account accepts repeated guesses without throttling.",
        "defended": "A simulated rate limit locks the mock account after repeated failures.",
    },
    "broken-access-control": {
        "name": "Broken access control",
        "description": "A fictional applicant requests another applicant's record.",
        "vulnerable": "A lookup by record ID alone exposes the mock record.",
        "defended": "The request is denied because the record owner does not match.",
    },
    "unsafe-upload": {
        "name": "Unsafe file upload",
        "description": "A harmless filename is checked against the resume upload policy.",
        "vulnerable": "The mock vulnerable path accepts a disallowed extension.",
        "defended": "The upload allow-list rejects the disallowed file type.",
    },
}


def run_simulation(scenario, defended):
    if scenario not in SCENARIOS or not isinstance(defended, bool):
        raise ValueError("Choose a supported scenario and a defense state.")
    if scenario == "sql-injection":
        outcome = {
            "blocked": defended,
            "result": "Mock lookup returned zero rows; input remained data." if defended
            else "Mock lookup predicate was altered; two fictional applicant rows would be exposed.",
            "evidence": "Bound parameters used." if defended else "Unsafe string concatenation simulated; no SQL was executed.",
        }
    elif scenario == "brute-force":
        outcome = {
            "blocked": defended,
            "result": "Account locked after the third failed attempt." if defended
            else "Three failed guesses were accepted without a simulated delay.",
            "evidence": "Mock throttle: 3 attempts per window." if defended else "No throttle in vulnerable mock.",
        }
    elif scenario == "broken-access-control":
        outcome = {
            "blocked": defended,
            "result": "Access denied; applicant ownership did not match." if defended
            else "Another fictional applicant's record was exposed by ID-only lookup.",
            "evidence": "Owner check applied." if defended else "ID-only lookup simulated; no real records accessed.",
        }
    else:
        outcome = {
            "blocked": defended,
            "result": "Upload rejected by the resume extension allow-list." if defended
            else "The mock vulnerable implementation accepted a .html filename.",
            "evidence": "Allowed types: PDF, DOC, DOCX." if defended else "Filename only; no file stored or executed.",
        }
    return {"scenario": scenario, "defended": defended, **outcome}
