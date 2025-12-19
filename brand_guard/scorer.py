def score(flags: list[str]) -> tuple[str, int]:
    points = 0

    for f in flags:
        # Very strong indicators
        if f in ("ip_as_domain", "punycode", "brand_in_domain_not_official"):
            points += 4

        # Strong indicator
        elif f.startswith("suspicious_tld:"):
            points += 3

        # Medium indicators
        elif f in ("no_https", "many_subdomains"):
            points += 2

        # Weak indicators (add up over many flags)
        elif f.startswith("keyword:"):
            points += 1

        # Invalid / empty
        elif f == "empty_domain":
            points += 5

    if points >= 7:
        return "high", points
    if points >= 4:
        return "medium", points
    return "low", points