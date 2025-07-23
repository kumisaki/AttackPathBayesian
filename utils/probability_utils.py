def calc_probability(cvss, epss):
    """
    Calculate the probability of exploitation based on CVSS and EPSS.
    """
    try:
        p = 1 - (1 - (float(cvss) / 10)) * (1 - float(epss))
    except Exception:
        p = 0.0
    return round(p, 3)

# You can add wrappers for estimate_parent_influence or compute_structural_probability here if needed. 