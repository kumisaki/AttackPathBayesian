"""
Helper functions for CPD probability estimation.
File path: utils/estimate_probabilities.py
"""

from __future__ import annotations
from typing import Dict, List, Mapping, Sequence, Set, Tuple

MIN_PROB, MAX_PROB = 0.0, 1.0
TACTIC_REPEAT_FACTOR = 0.7      # all tactics identical → down-weight
TACTIC_DIVERSE_FACTOR = 1.2     # tactics diverse      → up-weight
DEFAULT_PROB = 0.3


def _clamp(x: float, low: float = MIN_PROB, high: float = MAX_PROB) -> float:
    return max(low, min(high, x))


def estimate_parent_influence(
    parent_info: Sequence[Tuple[str, str]],
    *,
    device_vulns: Mapping[str, Sequence[dict]],
    technique_score_map: Mapping[str, float],
    technique_to_tactic_map: Mapping[str, str],
) -> float:
    """Return P(child=1 | given active parents)."""
    scores: List[float] = []
    tactic_sets: List[Set[str]] = []

    for pid, ptype in parent_info:
        if ptype == "device":
            vulns = device_vulns.get(pid, ())
            if not vulns:
                continue
            s = max(
                _clamp((float(v.get("cvss", 5.0)) / 10) * (0.5 + float(v.get("epss", 0))))
                * (0.5 if float(v.get("epss", 0)) < 0.1 else 1.0)
                for v in vulns
            )
            scores.append(s)
            tactic_sets.append(
                {
                    technique_to_tactic_map[tid]
                    for v in vulns
                    for tid in v.get("attack_techniques", [])
                    if tid in technique_to_tactic_map
                }
            )
        else:  # technique
            s = _clamp(technique_score_map.get(pid, DEFAULT_PROB))
            if s < 0.1:
                s *= 0.5
            scores.append(s)
            tactic_sets.append({technique_to_tactic_map.get(pid)})

    if not scores:
        return DEFAULT_PROB

    if not tactic_sets:
        diversity = 1.0
    elif all(ts == tactic_sets[0] for ts in tactic_sets):
        diversity = TACTIC_REPEAT_FACTOR
    elif len(set().union(*tactic_sets)) > 1:
        diversity = TACTIC_DIVERSE_FACTOR
    else:
        diversity = 1.0

    return _clamp(sum(scores) / len(scores) * diversity)


def compute_structural_probability(
    parents: Sequence[str],
    node: str,
    *,
    technique_score_map: Mapping[str, float],
    technique_to_tactic_map: Mapping[str, str],
    vulnerabilities: Sequence[dict],
) -> float:
    device_idx: Dict[str, List[dict]] = {}
    for v in vulnerabilities:
        dev = v.get("parent_device_id")
        if dev:
            device_idx.setdefault(dev, []).append(v)

    info = [
        (p.split(":", 1)[1], "device" if p.startswith("compromised:") else "technique")
        for p in parents
    ]
    return estimate_parent_influence(
        parent_info=info,
        device_vulns=device_idx,
        technique_score_map=technique_score_map,
        technique_to_tactic_map=technique_to_tactic_map,
    )
